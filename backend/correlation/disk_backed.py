from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Callable

from backend.correlation.correlator import (
    GENERIC_IPS,
    IncidentState,
    StreamingCorrelator,
)
from backend.models import Detection, Incident, NormalizedEvent


class DiskBackedStreamingCorrelator(StreamingCorrelator):
    """Streaming correlator that keeps only the active time window in RAM.

    Historical detections and graph edges are stored in a temporary SQLite database.
    The database is local and is removed after final incident reconstruction.
    """

    def __init__(
        self,
        window_minutes: int,
        member_sink: Callable[[str, str], None] | None = None,
        temp_dir: Path | None = None,
    ):
        super().__init__(window_minutes=window_minutes, member_sink=member_sink)
        handle = tempfile.NamedTemporaryFile(
            prefix="chainsight-correlation-",
            suffix=".sqlite3",
            dir=str(temp_dir) if temp_dir else None,
            delete=False,
        )
        self._db_path = handle.name
        handle.close()
        self._db = sqlite3.connect(self._db_path)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA temp_store=FILE")
        self._db.executescript(
            """
            CREATE TABLE detections (
                detection_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                detection_json TEXT NOT NULL,
                event_json TEXT NOT NULL
            );
            CREATE INDEX idx_corr_detections_time ON detections(timestamp, detection_id);
            CREATE TABLE edges (
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                confidence REAL NOT NULL,
                relationship_type TEXT NOT NULL,
                PRIMARY KEY(source_id, target_id, relationship_type)
            );
            CREATE INDEX idx_corr_edges_target ON edges(target_id);
            CREATE TABLE visited (detection_id TEXT PRIMARY KEY);
            CREATE TABLE seen_event_ids (event_id TEXT PRIMARY KEY);
            CREATE TABLE frontier (detection_id TEXT PRIMARY KEY);
            CREATE TABLE component_members (detection_id TEXT PRIMARY KEY);
            """
        )
        self._pending_writes = 0
        self._db.commit()
        # The base class fields are retained for active-window indexes only.
        self.graph.clear()
        self.all_detections.clear()

    def add(self, detection: Detection, event: NormalizedEvent) -> str:
        self._expire(event.timestamp)

        candidate_ids: set[str] = set()
        if event.host:
            candidate_ids.update(self.by_host.get(event.host.lower(), ()))
        if event.source_ip and event.source_ip not in GENERIC_IPS:
            candidate_ids.update(self.by_ip.get(event.source_ip, ()))
        if event.destination_ip and event.destination_ip not in GENERIC_IPS:
            candidate_ids.update(self.by_ip.get(event.destination_ip, ()))
        if event.domain:
            candidate_ids.update(self.by_domain.get(event.domain.lower(), ()))
        if event.registry_path:
            candidate_ids.update(self.by_reg.get(event.registry_path.lower(), ()))

        for other_id in candidate_ids:
            other_pair = self.active_detections.get(other_id)
            if not other_pair:
                continue
            other_detection, other_event = other_pair
            edge = self._evaluate_link(other_detection, other_event, detection, event)
            if edge:
                self._db.execute(
                    "INSERT OR IGNORE INTO edges VALUES (?, ?, ?, ?, ?)",
                    (edge.source_det_id, edge.target_det_id, edge.reason, edge.confidence, edge.relationship_type),
                )

        self._db.execute(
            "INSERT OR REPLACE INTO detections VALUES (?, ?, ?, ?, ?)",
            (
                detection.detection_id,
                event.event_id,
                event.timestamp.isoformat(),
                detection.model_dump_json(),
                event.model_dump_json(),
            ),
        )
        self._pending_writes += 1
        if self._pending_writes >= 1_000:
            self._db.commit()
            self._pending_writes = 0

        self.active_detections[detection.detection_id] = (detection, event)
        if event.host:
            self.by_host[event.host.lower()].add(detection.detection_id)
        if event.source_ip and event.source_ip not in GENERIC_IPS:
            self.by_ip[event.source_ip].add(detection.detection_id)
        if event.destination_ip and event.destination_ip not in GENERIC_IPS:
            self.by_ip[event.destination_ip].add(detection.detection_id)
        if event.domain:
            self.by_domain[event.domain.lower()].add(detection.detection_id)
        if event.registry_path:
            self.by_reg[event.registry_path.lower()].add(detection.detection_id)
        self.arrival_queue.append((event.timestamp, detection.detection_id))

        # This is a progress hint only. Final IDs are recomputed from persisted components.
        incident_id = f"INC-{detection.detection_id[:8].upper()}"
        if self.member_sink:
            self.member_sink(incident_id, event.event_id)
        return incident_id

    def has_event_id(self, event_id: str) -> bool:
        return self._db.execute("SELECT 1 FROM seen_event_ids WHERE event_id = ?", (event_id,)).fetchone() is not None

    def remember_event_id(self, event_id: str) -> None:
        self._db.execute("INSERT OR IGNORE INTO seen_event_ids VALUES (?)", (event_id,))
        self._pending_writes += 1
        if self._pending_writes >= 1_000:
            self._db.commit()
            self._pending_writes = 0

    def _load_pair(self, detection_id: str) -> tuple[Detection, NormalizedEvent]:
        row = self._db.execute(
            "SELECT detection_json, event_json FROM detections WHERE detection_id = ?",
            (detection_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Missing persisted detection: {detection_id}")
        return Detection.model_validate_json(row[0]), NormalizedEvent.model_validate_json(row[1])

    def incidents(self) -> list[Incident]:
        """Reconstruct connected components using disk-backed frontier/visited tables."""
        self._db.commit()
        self._pending_writes = 0
        incidents: list[Incident] = []
        seeds = self._db.execute(
            "SELECT detection_id FROM detections ORDER BY timestamp, detection_id"
        )
        for (seed_id,) in seeds:
            exists = self._db.execute(
                "SELECT 1 FROM visited WHERE detection_id = ?", (seed_id,)
            ).fetchone()
            if exists:
                continue

            self._db.execute("DELETE FROM frontier")
            self._db.execute("DELETE FROM component_members")
            self._db.execute("INSERT OR IGNORE INTO frontier VALUES (?)", (seed_id,))

            # Disk-backed breadth-first traversal. The Python process holds one ID at a time.
            while True:
                row = self._db.execute(
                    "SELECT detection_id FROM frontier LIMIT 1"
                ).fetchone()
                if row is None:
                    break
                current_id = row[0]
                self._db.execute("DELETE FROM frontier WHERE detection_id = ?", (current_id,))
                already_seen = self._db.execute(
                    "SELECT 1 FROM visited WHERE detection_id = ?", (current_id,)
                ).fetchone()
                if already_seen:
                    continue
                self._db.execute("INSERT OR IGNORE INTO visited VALUES (?)", (current_id,))
                self._db.execute("INSERT OR IGNORE INTO component_members VALUES (?)", (current_id,))

                neighbors = self._db.execute(
                    "SELECT target_id FROM edges WHERE source_id = ? "
                    "UNION SELECT source_id FROM edges WHERE target_id = ?",
                    (current_id, current_id),
                )
                for (neighbor_id,) in neighbors:
                    self._db.execute(
                        "INSERT OR IGNORE INTO frontier "
                        "SELECT ? WHERE NOT EXISTS "
                        "(SELECT 1 FROM visited WHERE detection_id = ?)",
                        (neighbor_id, neighbor_id),
                    )

            reason_rows = self._db.execute(
                "SELECT DISTINCT reason FROM edges WHERE "
                "source_id IN (SELECT detection_id FROM component_members) "
                "OR target_id IN (SELECT detection_id FROM component_members)"
            ).fetchall()
            component_reasons = [row[0] for row in reason_rows]

            state: IncidentState | None = None
            member_rows = self._db.execute(
                "SELECT detection_id FROM component_members ORDER BY detection_id"
            )
            for (member_id,) in member_rows:
                detection, event = self._load_pair(member_id)
                if state is None:
                    state = IncidentState(
                        incident_id="",
                        first_observed=event.timestamp,
                        last_observed=event.timestamp,
                    )
                state.add(detection, event, component_reasons)

            if state is not None:
                sorted_event_ids = sorted(state.event_ids)
                id_hash = hashlib.sha256(
                    "|".join(sorted_event_ids).encode()
                ).hexdigest()[:8].upper()
                state.incident_id = f"INC-{id_hash}"
                incidents.append(state.model())

            self._db.commit()

        incidents.sort(key=lambda inc: (inc.risk_score, inc.last_observed), reverse=True)
        return incidents

    def close(self) -> None:
        db = getattr(self, "_db", None)
        if db is not None:
            try:
                db.close()
            finally:
                self._db = None
        path = getattr(self, "_db_path", None)
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass

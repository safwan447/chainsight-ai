from __future__ import annotations

import json
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_DNS, uuid5

from backend.config import RULES_PATH
from backend.mitre import mapping
from backend.models import Detection, NormalizedEvent


class CompiledRule:
    """Precomputed and optimized detection rule for high-throughput evaluation."""

    def __init__(self, raw_rule: dict[str, Any]):
        self.raw = raw_rule
        self.id: str = raw_rule["id"]
        self.name: str = raw_rule["name"]
        self.severity: str = raw_rule.get("severity", "medium").lower()
        self.technique_id: str = raw_rule.get("technique_id", "")
        self.confidence: float = float(raw_rule.get("confidence", 0.7))

        self.name_mapped, self.tactic_mapped = mapping(self.technique_id)
        self.technique_name: str = self.name_mapped or raw_rule.get("technique_name", "Unknown")
        self.tactic: str = self.tactic_mapped or raw_rule.get("tactic", "Unknown")

        # Event criteria
        self.event_criteria: dict[str, list[str]] = {}
        for k, v in raw_rule.get("event", {}).items():
            if isinstance(v, list):
                self.event_criteria[k] = [str(item).lower() for item in v]
            else:
                self.event_criteria[k] = [str(v).lower()]

        # Target category for fast index filtering
        self.target_categories: set[str] = set()
        if "category" in self.event_criteria:
            self.target_categories = set(self.event_criteria["category"])

        # Needles for substring checks (pre-lowercased)
        self.contains: list[str] = [n.lower() for n in raw_rule.get("contains", [])]
        self.parent_in: list[str] = [n.lower() for n in raw_rule.get("parent_in", [])]
        self.domain_contains: list[str] = [n.lower() for n in raw_rule.get("domain_contains", [])]
        self.registry_contains: list[str] = [n.lower() for n in raw_rule.get("registry_contains", [])]
        self.file_contains: list[str] = [n.lower() for n in raw_rule.get("file_contains", [])]

        # Raw event checks
        self.raw_contains: dict[str, list[str]] = {}
        for field, needles in raw_rule.get("raw_contains", {}).items():
            if isinstance(needles, list):
                self.raw_contains[field] = [n.lower() for n in needles]
            else:
                self.raw_contains[field] = [str(needles).lower()]


class DetectionEngine:
    """High-performance offline detection engine with categorized rule indexing and auth state tracking."""

    def __init__(self, rule_path: Path = RULES_PATH):
        self.rule_path = rule_path
        self.rules: list[CompiledRule] = []
        self.category_rules: dict[str, list[CompiledRule]] = defaultdict(list)
        self.any_category_rules: list[CompiledRule] = []

        # Sliding window state for failed auth tracking: (host, user) -> deque of (timestamp, event_id)
        self.failed_auth: dict[tuple[str | None, str | None], deque[tuple[Any, str]]] = defaultdict(deque)
        # Track when an auth alert was emitted for a window to avoid redundant alert spam
        self.last_auth_alert_time: dict[tuple[str | None, str | None], Any] = {}

        self._load_rules()

    def _load_rules(self) -> None:
        if not self.rule_path.exists():
            return
        rules_data = json.loads(self.rule_path.read_text(encoding="utf-8"))
        for raw_rule in rules_data:
            compiled = CompiledRule(raw_rule)
            self.rules.append(compiled)
            if compiled.target_categories:
                for cat in compiled.target_categories:
                    self.category_rules[cat].append(compiled)
            else:
                self.any_category_rules.append(compiled)

    @staticmethod
    def _text_contains_any(text: str | None, needles: list[str]) -> tuple[bool, str | None]:
        if not text or not needles:
            return False, None
        lowered = text.lower()
        for needle in needles:
            if needle in lowered:
                return True, needle
        return False, None

    @staticmethod
    def _clean_proc_name(name: str | None) -> str:
        if not name:
            return ""
        base = name.split("\\")[-1].split("/")[-1].lower()
        if base.endswith(".exe"):
            base = base[:-4]
        return base

    def reset_state(self) -> None:
        """Reset state between distinct investigation runs."""
        self.failed_auth.clear()
        self.last_auth_alert_time.clear()

    def detect(self, events: list[NormalizedEvent]) -> list[Detection]:
        self.reset_state()
        return self.detect_batch(events)

    def detect_batch(self, events: list[NormalizedEvent]) -> list[Detection]:
        """Evaluate one bounded batch of normalized events against indexed rules."""
        found: list[Detection] = []

        for event in events:
            # 1. State-aware failed authentication detection
            raw = event.raw_event
            raw_event_dict = raw.get("event") if isinstance(raw.get("event"), dict) else {}
            outcome = raw_event_dict.get("outcome") if isinstance(raw_event_dict, dict) else None
            status = raw.get("status")
            action = str(event.action).lower()

            is_failed_auth = (
                (event.category == "authentication" or "logon" in action or "login" in action)
                and (
                    outcome in ("failure", "failed")
                    or status in ("failed", "failure")
                    or "failed" in action
                    or raw.get("logdesc") == "Admin login failed"
                )
            )

            if is_failed_auth:
                key = (event.host, event.user)
                failures = self.failed_auth[key]
                failures.append((event.timestamp, event.event_id))

                # Expire failures older than 15 minutes
                cutoff = event.timestamp - timedelta(minutes=15)
                while failures and failures[0][0] < cutoff:
                    failures.popleft()

                if len(failures) >= 5:
                    last_alert = self.last_auth_alert_time.get(key)
                    # Trigger if no alert yet or if at least 15 minutes passed since last alert for this user/host
                    if not last_alert or (event.timestamp - last_alert) >= timedelta(minutes=15) or len(failures) == 5:
                        self.last_auth_alert_time[key] = event.timestamp
                        conf = min(0.95, 0.60 + len(failures) * 0.04)
                        evidence = {
                            "trigger_reason": f"Observed {len(failures)} failed authentication attempts within 15 minutes",
                            "failed_attempts": len(failures),
                            "window_minutes": 15,
                            "host": event.host,
                            "user": event.user,
                            "source_ip": event.source_ip,
                            "event_ids": [f[1] for f in list(failures)[-5:]],
                        }
                        auth_rule = CompiledRule({
                            "id": "CS-AUTH-001",
                            "name": "Repeated failed authentication",
                            "severity": "medium",
                            "technique_id": "T1110",
                            "confidence": conf,
                        })
                        found.append(self._create_detection(event, auth_rule, conf, evidence))

            # 2. Rule evaluation with category pre-filtering
            candidate_rules = self.category_rules.get(event.category.lower(), []) + self.any_category_rules

            event_proc_clean = self._clean_proc_name(event.process_name)
            event_parent_clean = self._clean_proc_name(event.parent_process)

            for rule in candidate_rules:
                matches = True
                matched_details: dict[str, Any] = {}

                # Check event attribute criteria
                for key, expected_values in rule.event_criteria.items():
                    actual = getattr(event, key, None)
                    if not actual:
                        matches = False
                        break

                    actual_str = str(actual).lower()
                    if key in ("process_name", "parent_process"):
                        actual_clean = event_proc_clean if key == "process_name" else event_parent_clean
                        if not any(v in actual_str or v == actual_clean for v in expected_values):
                            matches = False
                            break
                    else:
                        if not any(v in actual_str for v in expected_values):
                            matches = False
                            break

                if not matches:
                    continue

                # Check command line contains
                if rule.contains:
                    has_match, needle = self._text_contains_any(event.command_line, rule.contains)
                    if not has_match:
                        matches = False
                    else:
                        matched_details["matched_command_indicator"] = needle

                if not matches:
                    continue

                # Check parent process in
                if rule.parent_in:
                    has_match, needle = self._text_contains_any(event.parent_process, rule.parent_in)
                    if not has_match:
                        # Check cleaned parent
                        if not any(p == event_parent_clean for p in rule.parent_in):
                            matches = False
                        else:
                            matched_details["matched_parent_process"] = event_parent_clean
                    else:
                        matched_details["matched_parent_process"] = needle

                if not matches:
                    continue

                # Check domain contains
                if rule.domain_contains:
                    has_match, needle = self._text_contains_any(event.domain, rule.domain_contains)
                    if not has_match:
                        matches = False
                    else:
                        matched_details["matched_domain"] = needle

                if not matches:
                    continue

                # Check registry contains
                if rule.registry_contains:
                    has_match, needle = self._text_contains_any(event.registry_path, rule.registry_contains)
                    if not has_match:
                        matches = False
                    else:
                        matched_details["matched_registry"] = needle

                if not matches:
                    continue

                # Check file contains
                if rule.file_contains:
                    has_match, needle = self._text_contains_any(event.file_path, rule.file_contains)
                    if not has_match:
                        matches = False
                    else:
                        matched_details["matched_file"] = needle

                if not matches:
                    continue

                # Check raw field contains
                for field, needles in rule.raw_contains.items():
                    raw_val = str(event.raw_event.get(field, ""))
                    has_match, needle = self._text_contains_any(raw_val, needles)
                    if not has_match:
                        matches = False
                        break
                    matched_details[f"matched_raw_{field}"] = needle

                if matches:
                    evidence = {
                        "trigger_reason": f"Matched rule {rule.id}: {rule.name}",
                        "matched_indicators": matched_details,
                        "host": event.host,
                        "user": event.user,
                        "process": event.process_name,
                        "parent_process": event.parent_process,
                        "command_line": event.command_line,
                        "domain": event.domain,
                        "registry_path": event.registry_path,
                        "file_path": event.file_path,
                        "source_ip": event.source_ip,
                        "destination_ip": event.destination_ip,
                    }
                    found.append(self._create_detection(event, rule, rule.confidence, evidence))

        # Deduplicate detections per (event_id, rule_id) deterministically
        unique: dict[tuple[str, str], Detection] = {}
        for d in found:
            key = (d.event_id, d.rule_id)
            if key not in unique or d.confidence > unique[key].confidence:
                unique[key] = d

        return list(unique.values())

    @staticmethod
    def _create_detection(
        event: NormalizedEvent,
        rule: CompiledRule,
        confidence: float,
        evidence: dict[str, Any] | None = None,
    ) -> Detection:
        det_id = str(uuid5(NAMESPACE_DNS, f"{event.event_id}:{rule.id}"))
        return Detection(
            detection_id=det_id,
            event_id=event.event_id,
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            technique_id=rule.technique_id,
            technique_name=rule.technique_name,
            tactic=rule.tactic,
            confidence=round(confidence, 2),
            evidence=evidence or {
                "host": event.host,
                "user": event.user,
                "process": event.process_name,
                "command_line": event.command_line,
                "domain": event.domain,
                "registry_path": event.registry_path,
                "file_path": event.file_path,
            },
        )

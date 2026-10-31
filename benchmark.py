"""Reproducible pipeline benchmarking suite for ChainSight AI.

Measures each processing stage independently and the total end-to-end pipeline:
1. File Reading (MB/s)
2. Parsing (Records/s)
3. Normalization (Records/s)
4. Database Insertion (Records/s)
5. Detection Engine (Events/s)
6. Correlation Engine (Detections/s)
7. Graph Construction (Time & Memory)
8. Full Pipeline Throughput (Events/s & Total Duration)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import psutil
from backend.config import CHUNK_SIZE
from backend.correlation.correlator import StreamingCorrelator, correlate
from backend.detection.engine import DetectionEngine
from backend.graph.attack_graph import build_graph
from backend.ingestion.parser import detect_format, normalize, parse_line
from backend.ingestion.reader import stream_lines
from backend.ingestion.storage import Storage


def get_memory_mb() -> float:
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)


def benchmark_stage(name: str, fn, count: int) -> tuple[float, float, float]:
    mem_before = get_memory_mb()
    start = time.perf_counter()
    result = fn()
    duration = max(time.perf_counter() - start, 1e-6)
    mem_after = get_memory_mb()
    rate = count / duration
    mem_diff = max(0.0, mem_after - mem_before)
    return duration, rate, mem_diff, result


def run_benchmarks(sample_file: Path, record_limits: list[int]):
    print("=" * 80)
    print("CHAINSIGHT AI - PERFORMANCE BENCHMARK REPORT")
    print(f"Dataset: {sample_file.name} ({sample_file.stat().st_size / (1024*1024):.2f} MB)")
    print(f"Python: {sys.version.split()[0]} | Platform: {sys.platform} | CPU cores: {psutil.cpu_count()}")
    print("=" * 80)

    for limit in record_limits:
        print(f"\n>>> BENCHMARKING WITH {limit:,} RECORDS <<<")

        # 1. Reading
        file_bytes = 0
        raw_lines = []
        t0 = time.perf_counter()
        mem0 = get_memory_mb()
        for idx, line in stream_lines(sample_file):
            raw_lines.append(line)
            file_bytes += len(line.encode("utf-8"))
            if len(raw_lines) >= limit:
                break
        read_time = max(time.perf_counter() - t0, 1e-6)
        actual_count = len(raw_lines)
        read_mb = file_bytes / (1024 * 1024)
        read_mb_s = read_mb / read_time
        print(f"1. Reading:          {actual_count:,} records ({read_mb:.2f} MB) in {read_time:.4f}s -> {read_mb_s:.2f} MB/s")

        # 2. Parsing
        t0 = time.perf_counter()
        parsed_records = []
        fmt = detect_format(raw_lines[0])
        for line in raw_lines:
            parsed_records.append(parse_line(line, source_format=fmt))
        parse_time = max(time.perf_counter() - t0, 1e-6)
        parse_rate = actual_count / parse_time
        print(f"2. Parsing:          {actual_count:,} records in {parse_time:.4f}s -> {parse_rate:,.1f} records/s (Format: {fmt})")

        # 3. Normalization
        t0 = time.perf_counter()
        normalized_events = []
        for idx, p in enumerate(parsed_records, 1):
            normalized_events.append(normalize(p, line_no=idx))
        norm_time = max(time.perf_counter() - t0, 1e-6)
        norm_rate = actual_count / norm_time
        print(f"3. Normalization:    {actual_count:,} events in {norm_time:.4f}s -> {norm_rate:,.1f} events/s")

        # 4. Database Insertion
        temp_dir = tempfile.mkdtemp()
        temp_db_path = Path(temp_dir) / f"bench_{limit}.duckdb"
        try:
            store = Storage(temp_db_path)
            t0 = time.perf_counter()
            # Batch insertion in chunks
            for i in range(0, len(normalized_events), CHUNK_SIZE):
                store.insert_events(normalized_events[i : i + CHUNK_SIZE])
            db_time = max(time.perf_counter() - t0, 1e-6)
            db_rate = actual_count / db_time
            print(f"4. DB Insertion:     {actual_count:,} events in {db_time:.4f}s -> {db_rate:,.1f} inserts/s")
            store.close()
        finally:
            if temp_db_path.exists():
                try:
                    temp_db_path.unlink()
                except Exception:
                    pass

        # 5. Detection Engine
        engine = DetectionEngine()
        t0 = time.perf_counter()
        detections = []
        for i in range(0, len(normalized_events), CHUNK_SIZE):
            batch = normalized_events[i : i + CHUNK_SIZE]
            dets = engine.detect_batch(batch)
            detections.extend(dets)
        det_time = max(time.perf_counter() - t0, 1e-6)
        det_rate = actual_count / det_time
        print(f"5. Detection:        {actual_count:,} events in {det_time:.4f}s -> {det_rate:,.1f} events/s ({len(detections):,} detections)")

        # 6. Correlation Engine
        t0 = time.perf_counter()
        correlator = StreamingCorrelator()
        event_map = {e.event_id: e for e in normalized_events}
        for det in detections:
            ev = event_map.get(det.event_id)
            if ev:
                correlator.add(det, ev)
        incidents = correlator.incidents()
        corr_time = max(time.perf_counter() - t0, 1e-6)
        corr_rate = len(detections) / corr_time if detections else 0
        print(f"6. Correlation:      {len(detections):,} detections in {corr_time:.4f}s -> {corr_rate:,.1f} detections/s ({len(incidents):,} incidents)")

        # 7. Graph Construction
        graph_time = 0.0
        graph_nodes = 0
        graph_edges = 0
        if incidents:
            top_inc = incidents[0]
            inc_events = [event_map[eid] for eid in top_inc.evidence_event_ids if eid in event_map]
            inc_dets = [d for d in detections if d.event_id in top_inc.evidence_event_ids]
            t0 = time.perf_counter()
            g = build_graph(top_inc, inc_events, inc_dets)
            graph_time = time.perf_counter() - t0
            graph_nodes = len(g["nodes"])
            graph_edges = len(g["edges"])
            print(f"7. Graph Build:      Incident {top_inc.incident_id} ({graph_nodes} nodes, {graph_edges} edges) in {graph_time*1000:.2f}ms")

        # 8. Total End-to-End Pipeline
        total_time = read_time + parse_time + norm_time + db_time + det_time + corr_time + graph_time
        total_throughput = actual_count / total_time
        peak_mem = get_memory_mb()
        print(f"8. Total Pipeline:   {actual_count:,} records in {total_time:.4f}s -> {total_throughput:,.1f} events/s (Memory: {peak_mem:.1f} MB)")


if __name__ == "__main__":
    sample_path = ROOT / "data" / "firex-sample.log"
    if not sample_path.exists():
        sample_path = ROOT / "data" / "edr_events.json"

    # Test with 1,000, 10,000, and 20,000 records
    limits = [1_000, 10_000, 20_000]
    run_benchmarks(sample_path, limits)

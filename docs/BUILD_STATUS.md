# Build status

- [x] Repository inspected; synthetic generator preserved unchanged.
- [x] Normalized JSONL/CEF/FortiGate streaming pipeline and local DuckDB storage.
- [x] Configurable detections, ATT&CK mapping, correlation, risk, graph, reachability and reporting.
- [x] FastAPI routes and React dashboard wired to real API requests.
- [x] FortiGate key/value parser and dataset-specific evidence rules added after a bounded 20,000-line sample of `firex-10G.log`.
- [x] Implemented bounded-batch processing: event ingestion and detection iterate DuckDB batches; correlation keeps only active time-window entity state plus incident summaries, while membership evidence is persisted in `incident_events`.
- [x] Attack graph edges now require same-event evidence; reachability follows only observed host/source-IP and source/destination-IP links.
- [x] Frontend verification on 2026-10-31: `npm install --force --no-audit --no-fund` completed, followed by `npm run build`; Vite emitted `frontend/dist/index.html`, CSS, and JavaScript bundles.
- [ ] Python test verification remains blocked: `py -0p` reports no installed Python, and `.venv\Scripts\python.exe -m pytest -q` cannot launch because its interpreter is inaccessible.

# Build status

- [x] Repository inspected; synthetic generator preserved unchanged.
- [x] Normalized JSONL/CEF streaming pipeline and local DuckDB storage.
- [x] Configurable detections, ATT&CK mapping, correlation, risk, graph, reachability and reporting.
- [x] FastAPI routes and React dashboard wired to real API requests.
- [x] FortiGate key/value parser and dataset-specific evidence rules added after a bounded 20,000-line sample of `firex-10G.log`.
- [x] Unit tests written for parsing, detection, correlation and graph.
- [ ] Run Python tests and local end-to-end demo once Python 3.11+ is installed/working. The checked-in virtual environment cannot launch on this machine.
- [ ] Complete a clean `frontend/npm install` then run `npm run build`; the present local install was interrupted during dependency extraction.

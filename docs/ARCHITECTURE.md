# ChainSight AI architecture

ChainSight runs entirely on the analyst workstation. The FastAPI service streams source records one at a time, chooses a JSONL, CEF, or FortiGate key/value parser, and normalizes each record into a schema that retains the raw event. It writes bounded batches to DuckDB; no complete input file is loaded into RAM. Detection reads events back in bounded DuckDB batches, and correlation keeps only a correlation-window entity index plus compact incident summaries. Event-to-incident membership is stored in DuckDB for later timelines and graphs.

`DetectionEngine` evaluates JSON-configured event and threshold rules after ingestion. The correlator only joins detections when they share an evidence-bearing entity (host, user, IP, or domain) inside the configured 60-minute window. NetworkX adds an entity relationship only when both fields co-occur in the same evidence event; it does not chain unrelated entities by display order. The look-ahead endpoint follows observed host/source-IP and source/destination-IP links as defensive leads; it does not scan, probe, or assert compromise.

The React/Vite dashboard calls the local API. The graph, timeline, chart and report are all derived from API responses.

## Extension point when data arrives

Run `inspect_data.py` first. Add a parser adapter in `backend/ingestion/parser.py` (or a dedicated parser module) that returns the common `NormalizedEvent`; detection, correlation, graph, reporting and UI need no schema-specific rewrite.

# API

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Health and offline mode |
| `POST /api/ingest/upload` | Save a log file locally |
| `POST /api/ingest/process?filename=` | Stream, normalize, detect and correlate |
| `GET /api/ingest/status` | Run progress and bounded errors |
| `GET /api/dashboard/summary` | Dashboard metrics from persisted data |
| `GET /api/events` | Normalized events (`limit`, `offset`, `severity`) |
| `GET /api/incidents` | Correlated incidents |
| `GET /api/incidents/{id}/timeline` | Ordered evidence |
| `GET /api/incidents/{id}/graph` | Evidence-backed entity graph |
| `GET /api/incidents/{id}/reachability` | Potential relationships, not compromise claims |
| `GET /api/mitre/techniques` | Mapped detection evidence |
| `GET /api/reports/{id}?format=html` | JSON or printable HTML report |

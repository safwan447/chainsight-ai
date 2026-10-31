# ChainSight AI

ChainSight AI is a local-first defensive investigation prototype that turns EDR telemetry into evidence-backed alerts, MITRE ATT&CK context, correlated incidents, timelines, relationship graphs and downloadable reports. It is designed for a 24-hour hackathon: the architecture is modular enough for an unknown competition dataset but deliberately avoids cloud dependencies and heavyweight infrastructure.

> **Demo-data warning:** Synthetic events produced by `edr_log_generator.py` demonstrate parser, detection and UI behavior. They are not proof of a coordinated, successful attack chain. Potentially reachable entities are investigative leads, never compromise assertions.

## What it does

- Streams JSONL, CEF, and FortiGate key/value records without loading a whole log into memory.
- Retains original raw records alongside a stable normalized event shape in local DuckDB.
- Applies editable JSON rules for suspicious PowerShell, Office child processes, failed-auth thresholds, suspicious demo C2 domains, Run-key persistence and ransomware-like rename indicators.
- Maps evidence to T1110, T1059.001, T1547.001, T1071.001 and T1486.
- Correlates only when an evidence-bearing host, user, IP or domain is shared within a time window.
- Produces explainable risk scores, NetworkX-backed observed relationship graphs, safe reachability leads, JSON/HTML reports, and a React Flow investigation dashboard.

## Architecture

`Log file → streamed parser → normalized events + raw record → DuckDB → rules → detections → correlation → incidents → graph/risk/report/API → React dashboard`

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/API.md](docs/API.md) for the component and endpoint details.

## Windows setup

Install **Python 3.11+** and Node.js 20+ first. From PowerShell in this directory:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

cd frontend
npm install
cd ..
```

Start the API in one terminal:

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn backend.main:app --reload --port 8000
```

Start the dashboard in another:

```powershell
cd frontend
npm run dev
```

Open the Vite URL (normally `http://localhost:5173`). API docs are at `http://localhost:8000/docs`.

## Demo workflow

Generate a safe local synthetic source (the generator is preserved and not used by the app automatically):

```powershell
.\.venv\Scripts\python.exe edr_log_generator.py --count 1000 --output file --file data\edr_events.json --rate 0
```

Upload that file in **Ingest** and process it, or call:

```powershell
Invoke-RestMethod -Method Post http://localhost:8000/api/ingest/process?filename=edr_events.json
```

Use Incident Explorer to select evidence, then Timeline, Graph, MITRE and Report. All dashboard quantities come from the local API; no placeholder metrics are displayed.

### Processing the supplied FortiGate dataset in place

The app recognizes the FortiGate export format used by `firex-10G.log`. In **Ingest**, enter `C:\Users\moham\Downloads\firex-10G.log` into **Process in place**. This avoids creating a second multi-gigabyte upload. It streams `traffic`, `event`, and `utm` records; the current source starts a new investigation rather than mixing unrelated source files.

## Testing

```powershell
.\.venv\Scripts\pytest.exe -q
cd frontend; npm run build
```

Tests cover JSONL/CEF normalization and invalid records, context-aware detection, false-positive handling, correlation and observed graph edges. Add source-format fixtures when the official dataset arrives.

## Dataset arrival plan

1. Place the supplied file in `data/` and run `inspect_data.py` against a bounded sample.
2. Identify its format and field names; do not infer its schema.
3. Add a parser adapter in `backend/ingestion/` that creates `NormalizedEvent` values.
4. Run ingestion and validate results against source records before trusting a detection or incident relationship.

## Limitations and honest scoring

This is a rule-driven prototype, not a validated detection product. Scores are explainable prioritization aids: highest detection severity + detection volume + tactic breadth + average evidence confidence, capped at 100. It does not make active network probes, does not invoke external AI APIs, and cannot calculate precision, recall, detection rate or false-positive rate without labelled ground truth. See [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Project map

```
backend/       FastAPI, ingestion, rules, correlation, graph, risk, reports
frontend/      Vite + React dashboard
rules/         editable JSON detection rules
tests/         synthetic unit tests
data/          local telemetry and DuckDB (ignored by Git)
docs/          architecture, API, benchmarks, progress checklist
```

## Team contribution notes

One teammate can own dataset inspection/parser mapping and validation; the other can tune rules, investigate UI output and refine demo/report narrative. Keep raw evidence and assumptions visible during judging.

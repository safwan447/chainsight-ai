import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "chainsight.duckdb"
RULES_PATH = ROOT / "rules" / "detection_rules.json"

# Conservative defaults for developer machines with limited RAM.
CHUNK_SIZE = max(500, int(os.getenv("CHAINSIGHT_CHUNK_SIZE", "2000")))
DUCKDB_MEMORY_LIMIT = os.getenv("CHAINSIGHT_DUCKDB_MEMORY_LIMIT", "2GB")
DUCKDB_THREADS = max(1, int(os.getenv("CHAINSIGHT_DUCKDB_THREADS", "2")))
DUCKDB_TEMP_DIR = DATA_DIR / "duckdb_tmp"

CORRELATION_WINDOW_MINUTES = 60

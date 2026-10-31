from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "chainsight.duckdb"
RULES_PATH = ROOT / "rules" / "detection_rules.json"
CHUNK_SIZE = 2_000
CORRELATION_WINDOW_MINUTES = 60

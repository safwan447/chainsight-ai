from pathlib import Path
from typing import Iterator

def stream_lines(path: str | Path) -> Iterator[tuple[int, str]]:
    """Read one record at a time; this deliberately never materializes the file."""
    with open(path, "r", encoding="utf-8", errors="replace") as source:
        for number, line in enumerate(source, 1):
            if line.strip():
                yield number, line

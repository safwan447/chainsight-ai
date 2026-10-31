from __future__ import annotations

import io
from pathlib import Path
from typing import Iterator

# 1MB buffer for streaming multi-gigabyte files efficiently
BUFFER_SIZE = 1024 * 1024


def stream_lines(path: str | Path, buffer_size: int = BUFFER_SIZE) -> Iterator[tuple[int, str]]:
    """Read one record at a time with buffered I/O; never materializes the full file in memory."""
    target = Path(path)
    if not target.is_file():
        raise FileNotFoundError(f"Source file not found: {path}")

    with io.open(target, "r", encoding="utf-8", errors="replace", buffering=buffer_size) as source:
        for number, raw_line in enumerate(source, 1):
            line = raw_line.rstrip("\r\n")
            if line and not line.isspace():
                yield number, line

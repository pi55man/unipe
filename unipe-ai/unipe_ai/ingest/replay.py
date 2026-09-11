"""replay recorded flow batches from a file instead of a live socket.

same interface as FlowSocket so the engine does not care which one it got.
each line of the file is one json array of flows, i.e. one exporter tick.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

Flow = dict[str, Any]


class ReplaySource:
    def __init__(self, path: Path, tick_secs: float = 0.0) -> None:
        self.path = path
        self.tick_secs = tick_secs

    def connect(self) -> None:
        if not self.path.is_file():
            raise FileNotFoundError(self.path)

    def batches(self) -> Iterator[list[Flow]]:
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                batch = json.loads(line)
                if not isinstance(batch, list):
                    raise ValueError("each replay line must be a JSON array of flows")
                yield batch
                if self.tick_secs > 0:
                    time.sleep(self.tick_secs)

    def close(self) -> None:
        return

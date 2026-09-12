"""live status file the desktop ui polls.

written next to alerts.jsonl so tauri can read pipeline health without
attaching to the unix socket itself.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class StatusSink:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, payload: dict[str, Any]) -> None:
        if self.path is None:
            return
        body = dict(payload)
        body["updated_at"] = time.time()
        self.path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")

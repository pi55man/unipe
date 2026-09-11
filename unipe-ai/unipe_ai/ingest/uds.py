from __future__ import annotations

import json
import socket
import struct
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

Flow = dict[str, Any]


class FlowSocket:
    def __init__(self, path: Path, retry_secs: float = 1.0) -> None:
        self.path = path
        self.retry_secs = retry_secs
        self._sock: socket.socket | None = None

    def connect(self) -> None:
        while True:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(str(self.path))
                self._sock = sock
                return
            except (FileNotFoundError, ConnectionRefusedError):
                sock.close()
                time.sleep(self.retry_secs)

    def batches(self) -> Iterator[list[Flow]]:
        if self._sock is None:
            raise RuntimeError("not connected")
        while True:
            header = self._recvall(4)
            if header is None:
                return
            (nbytes,) = struct.unpack("<I", header)
            payload = self._recvall(nbytes)
            if payload is None:
                return
            batch = json.loads(payload)
            if not isinstance(batch, list):
                raise TypeError("expected a JSON array of flows")
            yield batch

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def _recvall(self, n: int) -> bytes | None:
        assert self._sock is not None
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

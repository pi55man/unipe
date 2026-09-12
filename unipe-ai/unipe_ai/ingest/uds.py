from __future__ import annotations

import json
import logging
import socket
import struct
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

Flow = dict[str, Any]
LOG = logging.getLogger("unipe_ai.uds")


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
            except (FileNotFoundError, ConnectionRefusedError, ConnectionResetError):
                sock.close()
                time.sleep(self.retry_secs)

    def batches(self) -> Iterator[list[Flow]]:
        """Yield flow batches forever; reconnect with backoff after disconnect."""
        while True:
            if self._sock is None:
                self.connect()
            while True:
                try:
                    header = self._recvall(4)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    header = None
                if header is None:
                    break
                (nbytes,) = struct.unpack("<I", header)
                try:
                    payload = self._recvall(nbytes)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    payload = None
                if payload is None:
                    break
                batch = json.loads(payload)
                if not isinstance(batch, list):
                    raise TypeError("expected a JSON array of flows")
                yield batch
            LOG.warning("flow socket disconnected; reconnecting to %s", self.path)
            self.close()
            time.sleep(self.retry_secs)

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

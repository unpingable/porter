from __future__ import annotations

import re
import select
import socket
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class SerialRunResult:
    transcript: bytes
    ended_by_eof: bool
    timed_out: bool


class SerialConsole:
    def __init__(self, socket_path: str, connect_timeout: float = 5.0) -> None:
        self.socket_path = socket_path
        self.connect_timeout = connect_timeout

    def _connect(self) -> socket.socket:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(self.connect_timeout)
        try:
            conn.connect(self.socket_path)
        except OSError:
            conn.close()
            raise
        return conn

    def probe(self) -> None:
        with self._connect():
            pass

    def run_line_until_token(self, line: str, token: str, timeout: float = 120.0) -> SerialRunResult:
        token_re = re.compile(re.escape(token.encode("ascii")) + rb":[0-9]{1,3}")
        transcript = bytearray()
        deadline = time.monotonic() + timeout
        ended_by_eof = False

        with self._connect() as conn:
            conn.sendall(line.encode("utf-8") + b"\n")
            conn.setblocking(False)

            while time.monotonic() < deadline:
                remaining = max(0.0, deadline - time.monotonic())
                readable, _writable, _errors = select.select([conn], [], [], min(0.1, remaining))
                if not readable:
                    continue

                chunk = conn.recv(65536)
                if not chunk:
                    ended_by_eof = True
                    break
                transcript.extend(chunk)
                if token_re.search(bytes(transcript)):
                    break

        timed_out = not ended_by_eof and not token_re.search(bytes(transcript))
        return SerialRunResult(bytes(transcript), ended_by_eof=ended_by_eof, timed_out=timed_out)


def parse_serial_target(target: str) -> str:
    if not target.startswith("serial:"):
        raise ValueError(f"unsupported target {target!r}; expected serial:<unix-socket-path>")
    socket_path = target[len("serial:") :]
    if not socket_path:
        raise ValueError("serial target requires a unix socket path")
    return socket_path

from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Any


# Porter's neutral exit-code sentinel. The payload cannot spoof it (random per run).
SENTINEL_PREFIX = "__PORTER_RC_"


def new_token() -> str:
    return f"{SENTINEL_PREFIX}{secrets.token_hex(8)}__"


def parse_exec_result(transcript: bytes, token: str) -> tuple[bool, int | None]:
    pattern = re.compile(rb"^" + re.escape(token.encode("ascii")) + rb":([0-9]{1,3})\s*$")
    rc: int | None = None
    for line in transcript.splitlines():
        match = pattern.match(line)
        if match:
            rc = int(match.group(1))
    return (rc is not None), rc


def parse_observed(stdout: bytes) -> dict[str, str]:
    observed: dict[str, str] = {}
    for raw in stdout.decode("utf-8", errors="replace").splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        if key in {"hostname", "os", "kernel", "arch"}:
            observed[key] = value
    return observed


def record_transport(record: dict[str, Any]) -> str:
    return str(record.get("substrate", {}).get("transport", ""))


def remote_workdir(record: dict[str, Any]) -> str:
    return str(record["substrate"]["declared"]["workdir"])


class SubstrateAdapter:
    """Post-shell, record-driven transport operations.

    Provisioning (`up`) is deliberately NOT here — DESIGN §1: "abstract only what
    happens after you have a shell." An adapter acts on a record whose substrate
    already exists, and declares its capabilities rather than implying them
    (pre-figures the §10 C2 capability model without touching the schema).
    """

    transport: str = ""
    supports_push: bool = False
    supports_pull: bool = False

    def observe(self, record: dict[str, Any]) -> str | None:
        """Probe observed identity into record['substrate']['observed'].

        Returns a refusal reason, or None on success.
        """
        raise NotImplementedError

    def exec_command(
        self, record: dict[str, Any], base: Path, command: list[str], env: dict[str, str] | None = None
    ) -> dict[str, Any]:
        raise NotImplementedError

    def push(
        self, record: dict[str, Any], base: Path, src: Path, dst: str | None = None, *, worktree: bool = False
    ) -> dict[str, Any]:
        raise NotImplementedError

    def pull(
        self, record: dict[str, Any], base: Path, remote_glob: str, local: str | None = None
    ) -> dict[str, Any]:
        raise NotImplementedError

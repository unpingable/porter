from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import record as records
from ..exact_ssh import ExactSSHProfileError, ExactSSHTransport
from ..ssh import CommandResult, shell_join
from .ssh_adapter import SSHAdapter


class ExactSSHAdapter(SSHAdapter):
    """Pinned SSH courier for a caller-owned, already-running endpoint."""

    transport = "ssh-exact"

    def _transport(self, record: dict[str, Any]) -> ExactSSHTransport:
        return ExactSSHTransport(record["substrate"]["declared"])

    def _observe(
        self, record: dict[str, Any]
    ) -> tuple[str | None, CommandResult | None, dict[str, Any] | None, list[str] | None]:
        declared = record["substrate"]["declared"]
        try:
            transport = self._transport(record)
        except ExactSSHProfileError as exc:
            return str(exc), None, None, None
        identity_argv = list(declared["identity_argv"])
        transport_argv = transport.argv_for(identity_argv)
        result = transport.run_remote_argv(identity_argv)
        if result.returncode != 0:
            return f"exact SSH identity command exited {result.returncode}", result, None, transport_argv
        try:
            actual = json.loads(result.stdout)
        except json.JSONDecodeError:
            return "exact SSH identity response was not JSON", result, None, transport_argv
        if not isinstance(actual, dict):
            return "exact SSH identity response was not an object", result, None, transport_argv
        expected = declared["expected_identity"]
        for key, expected_value in expected.items():
            if actual.get(key) != expected_value:
                return f"exact SSH identity mismatch: {key}", result, actual, transport_argv
        if actual.get("session_id") != declared["session_id"]:
            return "exact SSH session substitution", result, actual, transport_argv
        return None, result, actual, transport_argv

    def _record_observation(
        self,
        record: dict[str, Any],
        base: Path,
        *,
        purpose: str,
    ) -> str | None:
        started = records.utc_now()
        reason, result, actual, transport_argv = self._observe(record)
        ended = records.utc_now()
        seq = records.next_seq(record)
        transcript = records.transcript_rel(seq, "transport-check")
        if result is None:
            payload = f"porter exact SSH refusal: {reason}\n".encode("utf-8")
            exit_code = None
        else:
            payload = result.stdout + b"--- stderr ---\n" + result.stderr
            exit_code = result.returncode
        (base / transcript).write_bytes(payload)
        declared = record["substrate"]["declared"]
        records.add_step(
            record,
            kind="transport-check",
            declared=shell_join(list(declared["identity_argv"])),
            started_at=started,
            ended_at=ended,
            transcript=transcript,
            exit_code_observed=result is not None,
            exit_code=exit_code,
            extra={
                "purpose": purpose,
                "endpoint_id": declared["endpoint_id"],
                "endpoint_socket": declared["endpoint_socket"],
                "session_id": declared["session_id"],
                "transport_argv": transport_argv or [],
            },
        )
        if reason is not None:
            records.mark_refused(record, reason)
        elif actual is not None:
            record["substrate"]["observed"] = {
                "endpoint_id": declared["endpoint_id"],
                "endpoint_socket": declared["endpoint_socket"],
                "client_key_fingerprint": declared["client_key_fingerprint"],
                "guest_host_key_fingerprint": declared["guest_host_key_fingerprint"],
                "guest_transport_identity": actual,
            }
        records.save_record(base, record)
        return reason

    def observe(self, record: dict[str, Any]) -> str | None:
        reason, _, actual, _ = self._observe(record)
        if reason is None and actual is not None:
            declared = record["substrate"]["declared"]
            record["substrate"]["observed"] = {
                "endpoint_id": declared["endpoint_id"],
                "endpoint_socket": declared["endpoint_socket"],
                "guest_transport_identity": actual,
            }
        return reason

    def observe_and_record(self, record: dict[str, Any], base: Path) -> str | None:
        return self._record_observation(record, base, purpose="connect")

    def exec_command(
        self,
        record: dict[str, Any],
        base: Path,
        command: list[str],
        env: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if self._record_observation(record, base, purpose="exec") is not None:
            return record
        return super().exec_command(record, base, command, env)

    def push(
        self,
        record: dict[str, Any],
        base: Path,
        src: Path,
        dst: str | None = None,
        *,
        worktree: bool = False,
    ) -> dict[str, Any]:
        if self._record_observation(record, base, purpose="push") is not None:
            return record
        return super().push(record, base, src, dst, worktree=worktree)

    def pull(
        self,
        record: dict[str, Any],
        base: Path,
        remote_glob: str,
        local: str | None = None,
    ) -> dict[str, Any]:
        if self._record_observation(record, base, purpose="pull") is not None:
            return record
        return super().pull(record, base, remote_glob, local)

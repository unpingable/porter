from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from .. import record as records
from ..serial import SerialConsole
from ..ssh import shell_join
from .base import SubstrateAdapter, new_token, parse_exec_result


def build_serial_exec_line(command: list[str], token: str, env: dict[str, str] | None = None) -> str:
    command_string = shell_join(command)
    env_prefix = "".join(f"export {k}={shlex.quote(v)}; " for k, v in env.items()) if env else ""
    return f"{env_prefix}({command_string}); __porter_rc=$?; printf '\\n{token}:%s\\n' \"$__porter_rc\""


class SerialAdapter(SubstrateAdapter):
    transport = "serial-socket"
    supports_push = False
    supports_pull = False

    def _console(self, record: dict[str, Any]) -> SerialConsole:
        return SerialConsole(str(record["substrate"]["declared"]["socket_path"]))

    def observe(self, record: dict[str, Any]) -> str | None:
        try:
            self._console(record).probe()
        except OSError as exc:
            return f"could not open recipe serial socket: {exc}"
        observed = dict(record["substrate"].get("observed", {}))
        observed.setdefault("socket_path", record["substrate"]["declared"]["socket_path"])
        record["substrate"]["observed"] = observed
        return None

    def exec_command(
        self, record: dict[str, Any], base: Path, command: list[str], env: dict[str, str] | None = None
    ) -> dict[str, Any]:
        console = self._console(record)
        token = new_token()
        line = build_serial_exec_line(command, token, env)
        seq = records.next_seq(record)
        transcript = records.transcript_rel(seq, "exec")

        started = records.utc_now()
        try:
            result = console.run_line_until_token(line, token)
        except OSError as exc:
            ended = records.utc_now()
            (base / transcript).write_text(f"porter serial exec failed: {exc}\n", encoding="utf-8")
            extra: dict[str, Any] = {}
            if env:
                extra["env_keys"] = sorted(env.keys())
            records.add_step(
                record,
                kind="exec",
                declared=shell_join(command),
                started_at=started,
                ended_at=ended,
                transcript=transcript,
                exit_code_observed=False,
                extra=extra or None,
            )
            record["declared_command"] = command
            records.mark_refused(record, f"could not run command on serial socket: {exc}")
            records.save_record(base, record)
            return record

        ended = records.utc_now()
        (base / transcript).write_bytes(result.transcript)
        observed, rc = parse_exec_result(result.transcript, token)

        extra2: dict[str, Any] = {}
        if env:
            extra2["env_keys"] = sorted(env.keys())
        records.add_step(
            record,
            kind="exec",
            declared=shell_join(command),
            started_at=started,
            ended_at=ended,
            transcript=transcript,
            exit_code=rc,
            exit_code_observed=observed,
            extra=extra2 or None,
        )
        record["declared_command"] = command
        if not observed:
            reason = "command exit code was not observed over serial socket"
            if result.timed_out:
                reason = f"{reason} before timeout"
            elif result.ended_by_eof:
                reason = f"{reason} before console closed"
            records.mark_refused(record, reason)
        records.save_record(base, record)
        return record

from __future__ import annotations

import hashlib
import shlex
from pathlib import Path
from typing import Any

from .. import record as records
from ..ssh import (
    SSHTransport,
    git_archive_or_tar,
    is_dirty_worktree,
    make_tar_bytes,
    safe_extract_tar_bytes,
    shell_join,
)
from .base import SubstrateAdapter, new_token, parse_exec_result, parse_observed, remote_workdir


def build_exec_script(workdir: str, command: list[str], token: str, env: dict[str, str] | None = None) -> str:
    command_string = shell_join(command)
    env_lines = (
        "\n".join(f"export {k}={shlex.quote(v)}" for k, v in env.items()) + "\n"
        if env
        else ""
    )
    return f"""
{env_lines}cd {shlex.quote(workdir)} || exit 125
(
  {command_string}
)
__porter_rc=$?
printf '\n{token}:%s\n' "$__porter_rc"
"""


class SSHAdapter(SubstrateAdapter):
    transport = "ssh"
    supports_push = True
    supports_pull = True

    def _transport(self, record: dict[str, Any]) -> SSHTransport:
        return SSHTransport(str(record["substrate"]["declared"]["host"]))

    def observe(self, record: dict[str, Any]) -> str | None:
        workdir = remote_workdir(record)
        script = f"""
set -u
mkdir -p {shlex.quote(workdir)}
printf 'hostname=%s\n' "$(hostname 2>/dev/null || true)"
printf 'os=%s\n' "$(uname -s 2>/dev/null || true)"
printf 'kernel=%s\n' "$(uname -r 2>/dev/null || true)"
printf 'arch=%s\n' "$(uname -m 2>/dev/null || true)"
"""
        result = self._transport(record).run_script(script)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).decode("utf-8", errors="replace").strip()
            return "could not obtain recipe ssh shell" + (f": {detail}" if detail else "")
        observed = dict(record["substrate"].get("observed", {}))
        observed.update(parse_observed(result.stdout))
        record["substrate"]["observed"] = observed
        return None

    def exec_command(
        self, record: dict[str, Any], base: Path, command: list[str], env: dict[str, str] | None = None
    ) -> dict[str, Any]:
        transport = self._transport(record)
        token = new_token()
        script = build_exec_script(remote_workdir(record), command, token, env)
        seq = records.next_seq(record)
        transcript = records.transcript_rel(seq, "exec")

        started = records.utc_now()
        result = transport.run_script_combined(script)
        ended = records.utc_now()
        transcript_bytes = result.stdout
        (base / transcript).write_bytes(transcript_bytes)
        observed, rc = parse_exec_result(transcript_bytes, token)

        extra: dict[str, Any] = {}
        extra["transport_argv"] = transport.argv_for(["sh", "-s"])
        extra["payload_argv"] = list(command)
        if env:
            extra["env_keys"] = sorted(env.keys())
        records.add_step(
            record,
            kind="exec",
            declared=shell_join(command),
            started_at=started,
            ended_at=ended,
            transcript=transcript,
            exit_code=rc,
            exit_code_observed=observed,
            extra=extra or None,
        )
        record["declared_command"] = command
        if not observed:
            records.mark_refused(record, f"command exit code was not observed; ssh exited {result.returncode}")
        records.save_record(base, record)
        return record

    def push(
        self, record: dict[str, Any], base: Path, src: Path, dst: str | None = None, *, worktree: bool = False
    ) -> dict[str, Any]:
        transport = self._transport(record)
        remote_dst = dst or remote_workdir(record)
        if not remote_dst.startswith("/"):
            remote_dst = f"{record['substrate']['declared']['remote_root'].rstrip('/')}/{remote_dst}"

        seq = records.next_seq(record)
        transcript = records.transcript_rel(seq, "push")
        started = records.utc_now()
        dirty_worktree: bool | None = None
        try:
            if worktree:
                tar_bytes = make_tar_bytes(src)
                method = "tar (worktree)"
            else:
                tar_bytes, method = git_archive_or_tar(src)
                if method.startswith("git archive"):
                    dirty_worktree = is_dirty_worktree(src)
            input_artifact: dict[str, Any] = {
                "local_path": str(src.resolve()),
                "archive_sha256": hashlib.sha256(tar_bytes).hexdigest(),
                "archive_size": len(tar_bytes),
            }
            if src.is_file():
                input_artifact.update(
                    sha256=records.sha256_file(src),
                    size=records.file_size(src),
                )
            result = transport.push_tar_stream(remote_dst, tar_bytes)
        except Exception as exc:  # noqa: BLE001 - record courier failure instead of hiding it.
            ended = records.utc_now()
            (base / transcript).write_text(f"porter push failed: {exc}\n", encoding="utf-8")
            records.add_step(
                record,
                kind="push",
                declared=f"push {src} {remote_dst}",
                started_at=started,
                ended_at=ended,
                transcript=transcript,
                exit_code_observed=True,
                exit_code=1,
                extra={"remote_dst": remote_dst},
            )
            records.mark_porter_failed(record, str(exc))
            records.save_record(base, record)
            return record

        ended = records.utc_now()
        transcript_bytes = result.stdout + result.stderr
        (base / transcript).write_bytes(transcript_bytes)
        push_extra: dict[str, Any] = {
            "remote_dst": remote_dst,
            "input_artifacts": [input_artifact],
            "transport_argv": transport.argv_for(
                [transport.push_remote_command(remote_dst)]
            ),
        }
        if dirty_worktree is True:
            push_extra["dirty_worktree"] = True
        records.add_step(
            record,
            kind="push",
            declared=f"{method} {src} -> {remote_dst}",
            started_at=started,
            ended_at=ended,
            transcript=transcript,
            exit_code_observed=True,
            exit_code=result.returncode,
            extra=push_extra,
        )
        if result.returncode != 0:
            records.mark_porter_failed(record, f"push failed with exit code {result.returncode}")
        records.save_record(base, record)
        return record

    def pull(
        self, record: dict[str, Any], base: Path, remote_glob: str, local: str | None = None
    ) -> dict[str, Any]:
        transport = self._transport(record)
        artifact_root = base / "artifacts"
        if local:
            artifact_root = artifact_root / local
        artifact_root.mkdir(parents=True, exist_ok=True)

        seq = records.next_seq(record)
        transcript = records.transcript_rel(seq, "pull")
        started = records.utc_now()
        result = transport.pull_tar_stream(remote_workdir(record), remote_glob)
        ended = records.utc_now()

        transcript_bytes = result.stderr
        (base / transcript).write_bytes(transcript_bytes)
        records.add_step(
            record,
            kind="pull",
            declared=f"pull {remote_glob}",
            started_at=started,
            ended_at=ended,
            transcript=transcript,
            exit_code_observed=True,
            exit_code=result.returncode,
            extra={
                "remote_glob": remote_glob,
                "transport_argv": transport.argv_for(
                    [transport.pull_remote_command(remote_workdir(record), remote_glob)]
                ),
            },
        )
        if result.returncode != 0:
            records.mark_refused(record, f"requested artifact was not available: {remote_glob}")
            records.save_record(base, record)
            return record

        try:
            extracted = safe_extract_tar_bytes(result.stdout, artifact_root)
        except Exception as exc:  # noqa: BLE001 - unsafe tar output is a courier refusal.
            records.mark_refused(record, f"could not extract pulled artifact: {exc}")
            records.save_record(base, record)
            return record

        if not extracted:
            records.mark_refused(record, f"requested artifact produced no files: {remote_glob}")
            records.save_record(base, record)
            return record

        for path in extracted:
            rel = path.relative_to(base).as_posix()
            remote_path = path.relative_to(artifact_root).as_posix()
            record.setdefault("artifacts", []).append(
                {
                    "class": records.CUSTODY_BLOB,
                    "remote_path": remote_path,
                    "local_path": rel,
                    "sha256": records.sha256_file(path),
                    "size": records.file_size(path),
                }
            )
        records.save_record(base, record)
        return record

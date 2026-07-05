from __future__ import annotations

import re
import secrets
import shlex
from pathlib import Path
from typing import Any

from . import record as records
from .recipe import (
    copy_recipe,
    normalize_recipe_substrate,
    parse_recipe_metadata,
    parse_recipe_target,
    recipe_hook_path,
    run_recipe_hook,
)
from .serial import SerialConsole, parse_serial_target
from .ssh import SSHTransport, git_archive_or_tar, parse_target as parse_ssh_target, safe_extract_tar_bytes, shell_join


SENTINEL_PREFIX = "__PORTER_RC_"


class PorterError(Exception):
    pass


def resolve_run_base(runs_dir: Path, run_id: str) -> Path:
    base = records.run_dir(runs_dir, run_id)
    if not records.record_path(base).exists():
        raise PorterError(f"run not found: {run_id}")
    return base


def load_record(run_id: str, runs_dir: Path) -> dict[str, Any]:
    base = resolve_run_base(runs_dir, run_id)
    return records.load_record(base)


def default_remote_root(run_id: str) -> str:
    return f"/tmp/porter-{run_id}"


def record_transport(record: dict[str, Any]) -> str:
    return str(record.get("substrate", {}).get("transport", ""))


def remote_workdir(record: dict[str, Any]) -> str:
    return str(record["substrate"]["declared"]["workdir"])


def ssh_transport_for_record(record: dict[str, Any]) -> SSHTransport:
    host = str(record["substrate"]["declared"]["host"])
    return SSHTransport(host)


def serial_console_for_record(record: dict[str, Any]) -> SerialConsole:
    socket_path = str(record["substrate"]["declared"]["socket_path"])
    return SerialConsole(socket_path)


def parse_observed(stdout: bytes) -> dict[str, str]:
    observed: dict[str, str] = {}
    for raw in stdout.decode("utf-8", errors="replace").splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        if key in {"hostname", "os", "kernel", "arch"}:
            observed[key] = value
    return observed


def up(target: str, runs_dir: Path, remote_root: str | None = None) -> tuple[str, dict[str, Any]]:
    if target.startswith("ssh:"):
        return up_ssh(target, runs_dir, remote_root)
    if target.startswith("serial:"):
        return up_serial(target, runs_dir)
    if target.startswith("recipe:"):
        return up_recipe(target, runs_dir)
    raise ValueError(
        f"unsupported target {target!r}; expected ssh:<host>, serial:<unix-socket-path>, or recipe:<script-path>"
    )


def up_ssh(target: str, runs_dir: Path, remote_root: str | None = None) -> tuple[str, dict[str, Any]]:
    host = parse_ssh_target(target)
    run_id = records.new_run_id()
    remote_root = remote_root or default_remote_root(run_id)
    base = records.run_dir(runs_dir, run_id)
    records.ensure_layout(base)
    record = records.new_record(run_id, target, host, remote_root)
    records.save_record(base, record)

    transport = SSHTransport(host)
    script = f"""
set -u
mkdir -p {shlex.quote(remote_root)}/work
printf 'hostname=%s\n' "$(hostname 2>/dev/null || true)"
printf 'os=%s\n' "$(uname -s 2>/dev/null || true)"
printf 'kernel=%s\n' "$(uname -r 2>/dev/null || true)"
printf 'arch=%s\n' "$(uname -m 2>/dev/null || true)"
"""
    result = transport.run_script(script)
    if result.returncode != 0:
        reason = "could not obtain ssh shell"
        detail = (result.stderr or result.stdout).decode("utf-8", errors="replace").strip()
        if detail:
            reason = f"{reason}: {detail}"
        records.mark_refused(record, reason)
    else:
        record["substrate"]["observed"] = parse_observed(result.stdout)
    records.save_record(base, record)
    return run_id, record


def up_serial(target: str, runs_dir: Path) -> tuple[str, dict[str, Any]]:
    socket_path = parse_serial_target(target)
    run_id = records.new_run_id()
    base = records.run_dir(runs_dir, run_id)
    records.ensure_layout(base)
    record = records.new_serial_record(run_id, target, socket_path)
    records.save_record(base, record)

    try:
        SerialConsole(socket_path).probe()
    except OSError as exc:
        records.mark_refused(record, f"could not open serial socket: {exc}")
    else:
        record["substrate"]["observed"] = {"socket_path": socket_path}
    records.save_record(base, record)
    return run_id, record




def write_hook_transcript(base: Path, rel: str, stdout: bytes, stderr: bytes) -> None:
    payload = b"--- stdout ---\n" + stdout + b"--- stderr ---\n" + stderr
    (base / rel).write_bytes(payload)


def probe_declared_transport(record: dict[str, Any]) -> str | None:
    transport = record_transport(record)
    if transport == "ssh":
        workdir = remote_workdir(record)
        script = f"""
set -u
mkdir -p {shlex.quote(workdir)}
printf 'hostname=%s\n' "$(hostname 2>/dev/null || true)"
printf 'os=%s\n' "$(uname -s 2>/dev/null || true)"
printf 'kernel=%s\n' "$(uname -r 2>/dev/null || true)"
printf 'arch=%s\n' "$(uname -m 2>/dev/null || true)"
"""
        result = ssh_transport_for_record(record).run_script(script)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).decode("utf-8", errors="replace").strip()
            return f"could not obtain recipe ssh shell" + (f": {detail}" if detail else "")
        observed = dict(record["substrate"].get("observed", {}))
        observed.update(parse_observed(result.stdout))
        record["substrate"]["observed"] = observed
        return None
    if transport == "serial-socket":
        try:
            serial_console_for_record(record).probe()
        except OSError as exc:
            return f"could not open recipe serial socket: {exc}"
        observed = dict(record["substrate"].get("observed", {}))
        observed.setdefault("socket_path", record["substrate"]["declared"]["socket_path"])
        record["substrate"]["observed"] = observed
        return None
    return f"unsupported recipe transport: {transport or 'unknown'}"


def up_recipe(target: str, runs_dir: Path) -> tuple[str, dict[str, Any]]:
    source = parse_recipe_target(target)
    run_id = records.new_run_id()
    base = records.run_dir(runs_dir, run_id)
    records.ensure_layout(base)
    record = records.new_recipe_record(run_id, target, str(source))
    records.save_record(base, record)

    try:
        entry = copy_recipe(source, base)
    except Exception as exc:  # noqa: BLE001 - inability to capture the recipe is a refusal.
        records.mark_refused(record, f"could not capture recipe: {exc}")
        records.save_record(base, record)
        return run_id, record

    record["recipes"] = [entry]
    record.setdefault("lifecycle", {})["recipe"] = entry
    records.save_record(base, record)

    seq = records.next_seq(record)
    transcript = records.transcript_rel(seq, "up")
    started = records.utc_now()
    try:
        result = run_recipe_hook(base / entry["local_path"], "up", run_id, base)
    except OSError as exc:
        ended = records.utc_now()
        (base / transcript).write_text(f"porter recipe up failed: {exc}\n", encoding="utf-8")
        records.add_step(
            record,
            kind="up",
            declared=f"recipe up {source}",
            started_at=started,
            ended_at=ended,
            transcript=transcript,
            exit_code_observed=True,
            exit_code=1,
        )
        records.mark_refused(record, f"could not run recipe up hook: {exc}")
        records.save_record(base, record)
        return run_id, record

    ended = records.utc_now()
    write_hook_transcript(base, transcript, result.stdout, result.stderr)
    records.add_step(
        record,
        kind="up",
        declared=f"recipe up {source}",
        started_at=started,
        ended_at=ended,
        transcript=transcript,
        exit_code_observed=True,
        exit_code=result.returncode,
    )
    if result.returncode != 0:
        records.mark_refused(record, f"recipe up hook failed with exit code {result.returncode}")
        records.save_record(base, record)
        return run_id, record

    try:
        metadata = parse_recipe_metadata(result.stdout)
        record["substrate"] = normalize_recipe_substrate(metadata, run_id)
    except ValueError as exc:
        records.mark_refused(record, str(exc))
        records.save_record(base, record)
        return run_id, record

    record["preserved"] = record["substrate"].get("ephemeral") is not True
    refusal = probe_declared_transport(record)
    if refusal is not None:
        records.mark_refused(record, refusal)
    records.save_record(base, record)
    return run_id, record


def mark_unsupported_transport_step(record: dict[str, Any], base: Path, *, kind: str, declared: str) -> dict[str, Any]:
    transport = record_transport(record) or "unknown"
    reason = f"{kind} is not supported for {transport} targets"
    seq = records.next_seq(record)
    transcript = records.transcript_rel(seq, kind)
    now = records.utc_now()
    (base / transcript).write_text(f"porter {kind} failed: {reason}\n", encoding="utf-8")
    records.add_step(
        record,
        kind=kind,
        declared=declared,
        started_at=now,
        ended_at=now,
        transcript=transcript,
        exit_code_observed=True,
        exit_code=1,
    )
    records.mark_porter_failed(record, reason)
    records.save_record(base, record)
    return record


def push(run_id: str, runs_dir: Path, src: Path, dst: str | None = None) -> dict[str, Any]:
    base = resolve_run_base(runs_dir, run_id)
    record = records.load_record(base)
    if record_transport(record) != "ssh":
        return mark_unsupported_transport_step(record, base, kind="push", declared=f"push {src} {dst or ''}".strip())

    transport = ssh_transport_for_record(record)
    remote_dst = dst or remote_workdir(record)
    if not remote_dst.startswith("/"):
        remote_dst = f"{record['substrate']['declared']['remote_root'].rstrip('/')}/{remote_dst}"

    seq = records.next_seq(record)
    transcript = records.transcript_rel(seq, "push")
    started = records.utc_now()
    try:
        tar_bytes, method = git_archive_or_tar(src)
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
    records.add_step(
        record,
        kind="push",
        declared=f"{method} {src} -> {remote_dst}",
        started_at=started,
        ended_at=ended,
        transcript=transcript,
        exit_code_observed=True,
        exit_code=result.returncode,
        extra={"remote_dst": remote_dst},
    )
    if result.returncode != 0:
        records.mark_porter_failed(record, f"push failed with exit code {result.returncode}")
    records.save_record(base, record)
    return record


def build_exec_script(workdir: str, command: list[str], token: str) -> str:
    command_string = shell_join(command)
    return f"""
cd {shlex.quote(workdir)} || exit 125
(
  {command_string}
)
__porter_rc=$?
printf '\n{token}:%s\n' "$__porter_rc"
"""


def build_serial_exec_line(command: list[str], token: str) -> str:
    command_string = shell_join(command)
    return f"({command_string}); __porter_rc=$?; printf '\\n{token}:%s\\n' \"$__porter_rc\""


def parse_exec_result(transcript: bytes, token: str) -> tuple[bool, int | None]:
    pattern = re.compile(rb"^" + re.escape(token.encode("ascii")) + rb":([0-9]{1,3})\s*$")
    rc: int | None = None
    for line in transcript.splitlines():
        match = pattern.match(line)
        if match:
            rc = int(match.group(1))
    return (rc is not None), rc


def exec_command(run_id: str, runs_dir: Path, command: list[str]) -> dict[str, Any]:
    if not command:
        raise PorterError("exec requires a command after --")
    base = resolve_run_base(runs_dir, run_id)
    record = records.load_record(base)
    transport = record_transport(record)
    if transport == "ssh":
        return exec_ssh_command(record, base, command)
    if transport == "serial-socket":
        return exec_serial_command(record, base, command)
    raise PorterError(f"unsupported transport in record: {transport or 'unknown'}")


def exec_ssh_command(record: dict[str, Any], base: Path, command: list[str]) -> dict[str, Any]:
    transport = ssh_transport_for_record(record)
    token = f"{SENTINEL_PREFIX}{secrets.token_hex(8)}__"
    script = build_exec_script(remote_workdir(record), command, token)
    seq = records.next_seq(record)
    transcript = records.transcript_rel(seq, "exec")

    started = records.utc_now()
    result = transport.run_script_combined(script)
    ended = records.utc_now()
    transcript_bytes = result.stdout
    (base / transcript).write_bytes(transcript_bytes)
    observed, rc = parse_exec_result(transcript_bytes, token)

    records.add_step(
        record,
        kind="exec",
        declared=shell_join(command),
        started_at=started,
        ended_at=ended,
        transcript=transcript,
        exit_code=rc,
        exit_code_observed=observed,
    )
    record["declared_command"] = command
    if not observed:
        records.mark_refused(record, f"command exit code was not observed; ssh exited {result.returncode}")
    records.save_record(base, record)
    return record


def exec_serial_command(record: dict[str, Any], base: Path, command: list[str]) -> dict[str, Any]:
    console = serial_console_for_record(record)
    token = f"{SENTINEL_PREFIX}{secrets.token_hex(8)}__"
    line = build_serial_exec_line(command, token)
    seq = records.next_seq(record)
    transcript = records.transcript_rel(seq, "exec")

    started = records.utc_now()
    try:
        result = console.run_line_until_token(line, token)
    except OSError as exc:
        ended = records.utc_now()
        (base / transcript).write_text(f"porter serial exec failed: {exc}\n", encoding="utf-8")
        records.add_step(
            record,
            kind="exec",
            declared=shell_join(command),
            started_at=started,
            ended_at=ended,
            transcript=transcript,
            exit_code_observed=False,
        )
        record["declared_command"] = command
        records.mark_refused(record, f"could not run command on serial socket: {exc}")
        records.save_record(base, record)
        return record

    ended = records.utc_now()
    (base / transcript).write_bytes(result.transcript)
    observed, rc = parse_exec_result(result.transcript, token)

    records.add_step(
        record,
        kind="exec",
        declared=shell_join(command),
        started_at=started,
        ended_at=ended,
        transcript=transcript,
        exit_code=rc,
        exit_code_observed=observed,
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


def pull(run_id: str, runs_dir: Path, remote_glob: str, local: str | None = None) -> dict[str, Any]:
    base = resolve_run_base(runs_dir, run_id)
    record = records.load_record(base)
    if record_transport(record) != "ssh":
        return mark_unsupported_transport_step(record, base, kind="pull", declared=f"pull {remote_glob}")

    transport = ssh_transport_for_record(record)
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
        extra={"remote_glob": remote_glob},
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


def seal(run_id: str, runs_dir: Path) -> dict[str, Any]:
    base = resolve_run_base(runs_dir, run_id)
    return records.seal_run(base)


def down(run_id: str, runs_dir: Path, preserve: bool = False) -> dict[str, Any]:
    base = resolve_run_base(runs_dir, run_id)
    record = records.load_record(base)
    hook = recipe_hook_path(base, record)

    if preserve:
        record["preserved"] = True
        if hook is not None:
            record.setdefault("lifecycle", {})["down"] = {"invoked": False, "preserve": True}
        records.save_record(base, record)
        return records.seal_run(base)

    if hook is None:
        record["preserved"] = True
        records.save_record(base, record)
        return records.seal_run(base)

    lifecycle = record.setdefault("lifecycle", {})
    seq = records.next_seq(record)
    transcript = records.transcript_rel(seq, "down")
    started = records.utc_now()
    try:
        result = run_recipe_hook(hook, "down", run_id, base)
    except OSError as exc:
        ended = records.utc_now()
        (base / transcript).write_text(f"porter recipe down failed: {exc}\n", encoding="utf-8")
        records.add_step(
            record,
            kind="down",
            declared=f"recipe down {hook}",
            started_at=started,
            ended_at=ended,
            transcript=transcript,
            exit_code_observed=True,
            exit_code=1,
        )
        lifecycle["down"] = {"invoked": True, "preserve": False, "transcript": transcript, "exit_code": 1}
        if record.get("outcome") != records.OUTCOME_REFUSED:
            records.mark_porter_failed(record, f"could not run recipe down hook: {exc}")
        records.save_record(base, record)
        return records.seal_run(base)

    ended = records.utc_now()
    write_hook_transcript(base, transcript, result.stdout, result.stderr)
    records.add_step(
        record,
        kind="down",
        declared=f"recipe down {hook}",
        started_at=started,
        ended_at=ended,
        transcript=transcript,
        exit_code_observed=True,
        exit_code=result.returncode,
    )
    lifecycle["down"] = {
        "invoked": True,
        "preserve": False,
        "transcript": transcript,
        "exit_code": result.returncode,
    }
    if result.returncode != 0:
        if record.get("outcome") != records.OUTCOME_REFUSED:
            records.mark_porter_failed(record, f"recipe down hook failed with exit code {result.returncode}")
    else:
        record["preserved"] = record.get("substrate", {}).get("ephemeral") is not True
    records.save_record(base, record)
    return records.seal_run(base)


def ls(runs_dir: Path) -> list[str]:
    if not runs_dir.exists():
        return []
    return sorted(path.name for path in runs_dir.iterdir() if (path / "record.json").exists())


def process_exit_for(record: dict[str, Any], propagate_exit: bool = False) -> int:
    outcome = record.get("outcome")
    if outcome == records.OUTCOME_COMPLETED:
        return 0
    if outcome == records.OUTCOME_RUN_FAILED:
        if propagate_exit:
            rc = records.payload_exit_code(record)
            if rc is None:
                return 1
            return rc if 0 <= rc <= 255 else 1
        return 0
    return 1

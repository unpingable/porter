from __future__ import annotations

import functools
import shlex
from pathlib import Path
from typing import Any, Callable

from . import record as records
from .adapters import (
    ExactSSHAdapter,
    adapter_for_record,
    parse_observed,
    record_transport,
)
from .exact_ssh import load_profile
from .recipe import (
    copy_recipe,
    normalize_recipe_substrate,
    parse_recipe_metadata,
    parse_recipe_target,
    recipe_hook_path,
    run_recipe_hook,
)
from .serial import SerialConsole, parse_serial_target
from .ssh import SSHTransport, parse_target as parse_ssh_target


class PorterError(Exception):
    pass


def resolve_run_base(runs_dir: Path, run_id: str) -> Path:
    base = records.run_dir(runs_dir, run_id)
    if not records.record_path(base).exists():
        raise PorterError(f"run not found: {run_id}")
    return base


def with_run_lock(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Serialize a mutating step over its run dir (F5 / DESIGN §8 Q2).

    Wraps commands whose shape is load→append→save on an existing run_id; a
    concurrent process on the same run raises records.RunLockedError instead of
    clobbering the first process's step. `up` is not wrapped — it mints a fresh
    run_id, so it never contends.
    """

    @functools.wraps(fn)
    def wrapper(run_id: str, runs_dir: Path, *args: Any, **kwargs: Any) -> Any:
        base = resolve_run_base(runs_dir, run_id)
        with records.run_lock(base):
            return fn(run_id, runs_dir, *args, **kwargs)

    return wrapper


def load_record(run_id: str, runs_dir: Path) -> dict[str, Any]:
    base = resolve_run_base(runs_dir, run_id)
    return records.load_record(base)


def default_remote_root(run_id: str) -> str:
    return f"/tmp/porter-{run_id}"


# ── Provisioning (`up`) — deliberately NOT behind the adapter seam ─────────────
# DESIGN §1: "abstract only what happens after you have a shell." Getting a shell
# is per-substrate; the post-shell ops (exec/push/pull/observe) live in adapters.

def up(
    target: str,
    runs_dir: Path,
    remote_root: str | None = None,
    declared_facts: dict[str, Any] | None = None,
    evidence_reservation: str | None = None,
) -> tuple[str, dict[str, Any]]:
    if target.startswith("ssh-exact:"):
        return up_exact_ssh(target, runs_dir, remote_root, declared_facts, evidence_reservation)
    if target.startswith("ssh:"):
        return up_ssh(target, runs_dir, remote_root, declared_facts, evidence_reservation)
    if target.startswith("serial:"):
        return up_serial(target, runs_dir, declared_facts, evidence_reservation)
    if target.startswith("recipe:"):
        return up_recipe(target, runs_dir, declared_facts, evidence_reservation)
    raise ValueError(
        f"unsupported target {target!r}; expected ssh:<host>, ssh-exact:<profile-path>, serial:<unix-socket-path>, or recipe:<script-path>"
    )


def up_ssh(
    target: str,
    runs_dir: Path,
    remote_root: str | None = None,
    declared_facts: dict[str, Any] | None = None,
    evidence_reservation: str | None = None,
) -> tuple[str, dict[str, Any]]:
    host = parse_ssh_target(target)
    run_id = records.new_run_id()
    remote_root = remote_root or default_remote_root(run_id)
    base = records.run_dir(runs_dir, run_id)
    records.ensure_layout(base)
    record = records.new_record(run_id, target, host, remote_root)
    if evidence_reservation is not None:
        records.bind_reservation(record, evidence_reservation)
    records.set_declared_facts(record["substrate"], declared_facts)
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
        records.refresh_fact_mismatches(record["substrate"])
    records.save_record(base, record)
    return run_id, record


def up_exact_ssh(
    target: str,
    runs_dir: Path,
    remote_root: str | None = None,
    declared_facts: dict[str, Any] | None = None,
    evidence_reservation: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Connect one pinned endpoint; VM lifecycle remains caller-owned."""
    profile = load_profile(target)
    if remote_root is not None and remote_root != profile.remote_root:
        raise ValueError("--remote-root conflicts with exact SSH profile")
    run_id = records.new_run_id()
    base = records.run_dir(runs_dir, run_id)
    records.ensure_layout(base)
    profile_snapshot = base / "exact-endpoint-profile.json"
    profile_snapshot.write_bytes(profile.source.read_bytes())
    profile_snapshot.chmod(0o600)

    record = records.new_record(
        run_id,
        target,
        f"{profile.user}@{profile.host}:{profile.port}",
        profile.remote_root,
    )
    if evidence_reservation is not None:
        records.bind_reservation(record, evidence_reservation)
    record["substrate"].update(
        {
            "kind": "vm",
            "transport": ExactSSHAdapter.transport,
            "ephemeral": False,
            "declared": profile.declared(),
            "observed": {},
            "fact_mismatches": [],
        }
    )
    record["transport_profiles"] = [
        {
            "class": records.CUSTODY_RECEIPT,
            "local_path": profile_snapshot.name,
            "sha256": profile.source_sha256,
            "size": profile_snapshot.stat().st_size,
        }
    ]
    record["notes"] = "exact SSH endpoint lifecycle is caller-owned"
    records.set_declared_facts(record["substrate"], declared_facts)
    records.save_record(base, record)
    ExactSSHAdapter().observe_and_record(record, base)
    return run_id, record


def up_serial(
    target: str,
    runs_dir: Path,
    declared_facts: dict[str, Any] | None = None,
    evidence_reservation: str | None = None,
) -> tuple[str, dict[str, Any]]:
    socket_path = parse_serial_target(target)
    run_id = records.new_run_id()
    base = records.run_dir(runs_dir, run_id)
    records.ensure_layout(base)
    record = records.new_serial_record(run_id, target, socket_path)
    if evidence_reservation is not None:
        records.bind_reservation(record, evidence_reservation)
    records.set_declared_facts(record["substrate"], declared_facts)
    records.save_record(base, record)

    try:
        SerialConsole(socket_path).probe()
    except OSError as exc:
        records.mark_refused(record, f"could not open serial socket: {exc}")
    else:
        record["substrate"]["observed"] = {"socket_path": socket_path}
        records.refresh_fact_mismatches(record["substrate"])
    records.save_record(base, record)
    return run_id, record


def write_hook_transcript(base: Path, rel: str, stdout: bytes, stderr: bytes) -> None:
    payload = b"--- stdout ---\n" + stdout + b"--- stderr ---\n" + stderr
    (base / rel).write_bytes(payload)


def probe_declared_transport(record: dict[str, Any]) -> str | None:
    """Probe the observed identity of a recipe-yielded substrate via its adapter."""
    adapter = adapter_for_record(record)
    if adapter is None:
        return f"unsupported recipe transport: {record_transport(record) or 'unknown'}"
    return adapter.observe(record)


def up_recipe(
    target: str,
    runs_dir: Path,
    declared_facts: dict[str, Any] | None = None,
    evidence_reservation: str | None = None,
) -> tuple[str, dict[str, Any]]:
    source = parse_recipe_target(target)
    run_id = records.new_run_id()
    base = records.run_dir(runs_dir, run_id)
    records.ensure_layout(base)
    record = records.new_recipe_record(run_id, target, str(source))
    if evidence_reservation is not None:
        records.bind_reservation(record, evidence_reservation)
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
    # Merge any CLI --expect facts over the recipe-declared facts, then probe.
    records.set_declared_facts(record["substrate"], declared_facts)
    refusal = probe_declared_transport(record)
    if refusal is not None:
        records.mark_refused(record, refusal)
    # Porter computes the authoritative fact_mismatches now that observed facts
    # are probed — the recipe's own declaration never controls the result (F1).
    records.refresh_fact_mismatches(record["substrate"])
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


# ── Post-shell ops — routed to the substrate adapter for the record's transport ──

@with_run_lock
def push(run_id: str, runs_dir: Path, src: Path, dst: str | None = None, *, worktree: bool = False) -> dict[str, Any]:
    base = resolve_run_base(runs_dir, run_id)
    record = records.load_record(base)
    adapter = adapter_for_record(record)
    if adapter is None or not adapter.supports_push:
        return mark_unsupported_transport_step(record, base, kind="push", declared=f"push {src} {dst or ''}".strip())
    return adapter.push(record, base, src, dst, worktree=worktree)


@with_run_lock
def exec_command(run_id: str, runs_dir: Path, command: list[str], env: dict[str, str] | None = None) -> dict[str, Any]:
    if not command:
        raise PorterError("exec requires a command after --")
    base = resolve_run_base(runs_dir, run_id)
    record = records.load_record(base)
    adapter = adapter_for_record(record)
    if adapter is None:
        raise PorterError(f"unsupported transport in record: {record_transport(record) or 'unknown'}")
    return adapter.exec_command(record, base, command, env)


@with_run_lock
def pull(run_id: str, runs_dir: Path, remote_glob: str, local: str | None = None) -> dict[str, Any]:
    base = resolve_run_base(runs_dir, run_id)
    record = records.load_record(base)
    adapter = adapter_for_record(record)
    if adapter is None or not adapter.supports_pull:
        return mark_unsupported_transport_step(record, base, kind="pull", declared=f"pull {remote_glob}")
    return adapter.pull(record, base, remote_glob, local)


@with_run_lock
def seal(run_id: str, runs_dir: Path) -> dict[str, Any]:
    base = resolve_run_base(runs_dir, run_id)
    return records.seal_run(base)


@with_run_lock
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

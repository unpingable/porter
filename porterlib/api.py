from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from . import record as records
from . import runner


Pathish = str | os.PathLike[str]


def _is_terminal(record: dict[str, Any]) -> bool:
    return record.get("outcome") in {records.OUTCOME_REFUSED, records.OUTCOME_PORTER_FAILED}


def _command_argv(command: Sequence[object]) -> list[str]:
    if isinstance(command, (str, bytes)):
        raise TypeError("command must be an argv sequence, not a shell string")
    argv = [str(part) for part in command]
    if not argv:
        raise runner.PorterError("run requires a command")
    return argv


def _push_paths(push: Pathish | Iterable[Pathish] | None) -> list[Path]:
    if push is None:
        return []
    if isinstance(push, (str, os.PathLike)):
        return [Path(push)]
    return [Path(item) for item in push]


def _pull_globs(pulls: str | Iterable[str] | None) -> list[str]:
    if pulls is None:
        return []
    if isinstance(pulls, str):
        return [pulls]
    return [str(item) for item in pulls]


def _finish(run_id: str, runs_dir: Path, *, preserve: bool) -> dict[str, Any]:
    runner.seal(run_id, runs_dir)
    return runner.down(run_id, runs_dir, preserve=preserve)


def run(
    *,
    target: str,
    command: Sequence[object],
    push: Pathish | Iterable[Pathish] | None = None,
    pulls: str | Iterable[str] | None = None,
    runs_dir: Pathish = "runs",
    remote_root: str | None = None,
    preserve: bool = False,
) -> dict[str, Any]:
    """Run a declared command and return the final Porter record."""
    argv = _command_argv(command)
    run_root = Path(runs_dir)
    run_id, record = runner.up(target, run_root, remote_root)
    if _is_terminal(record):
        return _finish(run_id, run_root, preserve=preserve)

    for src in _push_paths(push):
        record = runner.push(run_id, run_root, src)
        if _is_terminal(record):
            return _finish(run_id, run_root, preserve=preserve)

    record = runner.exec_command(run_id, run_root, argv)
    if _is_terminal(record):
        return _finish(run_id, run_root, preserve=preserve)

    for remote_glob in _pull_globs(pulls):
        record = runner.pull(run_id, run_root, remote_glob)
        if _is_terminal(record):
            return _finish(run_id, run_root, preserve=preserve)

    return _finish(run_id, run_root, preserve=preserve)

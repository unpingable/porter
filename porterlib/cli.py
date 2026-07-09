from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import api
from . import record as records
from . import runner


def strip_double_dash(items: list[str]) -> list[str]:
    if items and items[0] == "--":
        return items[1:]
    return items


def add_runs_dir(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runs-dir", default="runs", help="directory for Porter run records")


def parse_env(env_list: list[str] | None) -> dict[str, str]:
    """Parse ['KEY=VAL', ...] into {'KEY': 'VAL', ...}; empty list → empty dict."""
    if not env_list:
        return {}
    result: dict[str, str] = {}
    for item in env_list:
        if "=" not in item:
            raise ValueError(f"--env requires KEY=VAL format, got: {item!r}")
        key, _, value = item.partition("=")
        if not key:
            raise ValueError(f"--env requires a non-empty key, got: {item!r}")
        result[key] = value
    return result


def parse_expect(expect_list: list[str] | None) -> dict[str, str]:
    """Parse ['os=darwin', ...] into declared expected host facts; empty → {}.

    These are the caller's *claims* about the substrate; Porter compares them to
    what it observes and computes fact_mismatches itself (never a verdict).
    """
    if not expect_list:
        return {}
    result: dict[str, str] = {}
    for item in expect_list:
        if "=" not in item:
            raise ValueError(f"--expect requires KEY=VAL format, got: {item!r}")
        key, _, value = item.partition("=")
        if not key:
            raise ValueError(f"--expect requires a non-empty key, got: {item!r}")
        result[key] = value
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="porter")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="up, optional push, exec, optional pull, seal")
    add_runs_dir(run_p)
    run_p.add_argument("--target", required=True, help="target substrate: ssh:<host>, serial:<unix-socket-path>, or recipe:<script-path>")
    run_p.add_argument("--remote-root", help="remote custody root; defaults to /tmp/porter-<run_id>")
    run_p.add_argument("--push", action="append", default=[], help="local file/tree to push")
    run_p.add_argument("--pull", action="append", default=[], help="remote path/glob to pull from workdir")
    run_p.add_argument("--env", action="append", default=[], metavar="KEY=VAL", help="set env var before command (repeatable); keys recorded, values never stored")
    run_p.add_argument("--expect", action="append", default=[], metavar="KEY=VAL", help="declare an expected host fact, e.g. os=darwin (repeatable); Porter computes fact_mismatches vs observed")
    run_p.add_argument("--worktree", action="store_true", help="push the dirty working tree instead of git archive HEAD")
    run_p.add_argument("--propagate-exit", action="store_true", help="return payload exit for run_failed")
    run_p.add_argument("--preserve", action="store_true", help="preserve recipe-created substrate instead of invoking teardown")
    run_p.add_argument("cmd", nargs=argparse.REMAINDER)

    up_p = sub.add_parser("up", help="create/connect substrate and write record stub")
    add_runs_dir(up_p)
    up_p.add_argument("target", help="target substrate: ssh:<host>, serial:<unix-socket-path>, or recipe:<script-path>")
    up_p.add_argument("--remote-root", help="remote custody root; defaults to /tmp/porter-<run_id>")
    up_p.add_argument("--expect", action="append", default=[], metavar="KEY=VAL", help="declare an expected host fact, e.g. os=darwin (repeatable); Porter computes fact_mismatches vs observed")

    push_p = sub.add_parser("push", help="push a local file/tree to the substrate")
    add_runs_dir(push_p)
    push_p.add_argument("--worktree", action="store_true", help="push the dirty working tree instead of git archive HEAD")
    push_p.add_argument("run")
    push_p.add_argument("src")
    push_p.add_argument("dst", nargs="?")

    exec_p = sub.add_parser("exec", help="run declared command and capture transcript")
    add_runs_dir(exec_p)
    exec_p.add_argument("--env", action="append", default=[], metavar="KEY=VAL", help="set env var before command (repeatable); keys recorded, values never stored")
    exec_p.add_argument("--propagate-exit", action="store_true", help="return payload exit for run_failed")
    exec_p.add_argument("run")
    exec_p.add_argument("cmd", nargs=argparse.REMAINDER)

    pull_p = sub.add_parser("pull", help="pull a remote artifact under custody")
    add_runs_dir(pull_p)
    pull_p.add_argument("run")
    pull_p.add_argument("remote")
    pull_p.add_argument("local", nargs="?")

    seal_p = sub.add_parser("seal", help="finalize hashes, aggregate, and outcome")
    add_runs_dir(seal_p)
    seal_p.add_argument("run")

    down_p = sub.add_parser("down", help="teardown a recipe-created substrate or preserve it")
    add_runs_dir(down_p)
    down_p.add_argument("--preserve", action="store_true", help="record preservation and skip teardown hook")
    down_p.add_argument("run")

    show_p = sub.add_parser("show", help="print record.json")
    add_runs_dir(show_p)
    show_p.add_argument("run")

    ls_p = sub.add_parser("ls", help="list runs")
    add_runs_dir(ls_p)

    return parser



def cmd_run(args: argparse.Namespace) -> int:
    cmd = strip_double_dash(args.cmd)
    record = api.run(
        target=args.target,
        command=cmd,
        push=[Path(src) for src in args.push],
        pulls=args.pull,
        runs_dir=Path(args.runs_dir),
        remote_root=args.remote_root,
        preserve=args.preserve,
        env=parse_env(args.env) or None,
        expect=parse_expect(args.expect) or None,
        worktree=args.worktree,
    )
    print(record["run_id"])
    return runner.process_exit_for(record, args.propagate_exit)


def cmd_up(args: argparse.Namespace) -> int:
    run_id, record = runner.up(
        args.target, Path(args.runs_dir), args.remote_root, parse_expect(args.expect) or None
    )
    print(run_id)
    return 0 if record.get("outcome") not in {records.OUTCOME_REFUSED, records.OUTCOME_PORTER_FAILED} else 1


def cmd_push(args: argparse.Namespace) -> int:
    record = runner.push(args.run, Path(args.runs_dir), Path(args.src), args.dst, worktree=args.worktree)
    return 0 if record.get("outcome") not in {records.OUTCOME_REFUSED, records.OUTCOME_PORTER_FAILED} else 1


def cmd_exec(args: argparse.Namespace) -> int:
    cmd = strip_double_dash(args.cmd)
    record = runner.exec_command(args.run, Path(args.runs_dir), cmd, parse_env(args.env) or None)
    if record.get("outcome") == records.OUTCOME_REFUSED:
        return 1
    records.decide_outcome(record)
    return runner.process_exit_for(record, args.propagate_exit)


def cmd_pull(args: argparse.Namespace) -> int:
    record = runner.pull(args.run, Path(args.runs_dir), args.remote, args.local)
    return 0 if record.get("outcome") not in {records.OUTCOME_REFUSED, records.OUTCOME_PORTER_FAILED} else 1


def cmd_seal(args: argparse.Namespace) -> int:
    record = runner.seal(args.run, Path(args.runs_dir))
    return runner.process_exit_for(record)


def cmd_down(args: argparse.Namespace) -> int:
    record = runner.down(args.run, Path(args.runs_dir), preserve=args.preserve)
    return runner.process_exit_for(record)


def cmd_show(args: argparse.Namespace) -> int:
    record = runner.load_record(args.run, Path(args.runs_dir))
    print(records.dumps_record(record), end="")
    return 0


def cmd_ls(args: argparse.Namespace) -> int:
    for run_id in runner.ls(Path(args.runs_dir)):
        print(run_id)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            return cmd_run(args)
        if args.command == "up":
            return cmd_up(args)
        if args.command == "push":
            return cmd_push(args)
        if args.command == "exec":
            return cmd_exec(args)
        if args.command == "pull":
            return cmd_pull(args)
        if args.command == "seal":
            return cmd_seal(args)
        if args.command == "down":
            return cmd_down(args)
        if args.command == "show":
            return cmd_show(args)
        if args.command == "ls":
            return cmd_ls(args)
    except records.RunLockedError as exc:
        print(f"porter: {exc}", file=sys.stderr)
        return 2
    except runner.PorterError as exc:
        print(f"porter: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"porter: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(vars(args), indent=2), file=sys.stderr)
    return 2

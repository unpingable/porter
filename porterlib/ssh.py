from __future__ import annotations

import io
import os
import re
import shlex
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path


SAFE_REMOTE_GLOB = re.compile(r"^[A-Za-z0-9_./*?\[\]-]+$")


@dataclass
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class SSHTransport:
    def __init__(self, host: str) -> None:
        self.host = host

    def run_script(self, script: str) -> CommandResult:
        proc = subprocess.run(
            ["ssh", self.host, "sh", "-s"],
            input=script.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    def run_script_combined(self, script: str) -> CommandResult:
        proc = subprocess.run(
            ["ssh", self.host, "sh", "-s"],
            input=script.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        return CommandResult(proc.returncode, proc.stdout, b"")

    def push_tar_stream(self, dst: str, tar_bytes: bytes) -> CommandResult:
        remote = f"mkdir -p {shlex.quote(dst)} && tar -x -C {shlex.quote(dst)}"
        proc = subprocess.run(
            ["ssh", self.host, remote],
            input=tar_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    def pull_tar_stream(self, workdir: str, remote_glob: str) -> CommandResult:
        if not SAFE_REMOTE_GLOB.match(remote_glob) or ".." in Path(remote_glob).parts:
            return CommandResult(2, b"", f"unsafe remote glob: {remote_glob}\n".encode())
        remote = f"cd {shlex.quote(workdir)} && tar -cf - -- {remote_glob}"
        proc = subprocess.run(
            ["ssh", self.host, remote],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)


def parse_target(target: str) -> str:
    if not target.startswith("ssh:"):
        raise ValueError(f"unsupported target {target!r}; expected ssh:<host>")
    host = target[4:]
    if not host:
        raise ValueError("ssh target requires a host")
    return host


def shell_join(command: list[str]) -> str:
    return shlex.join(command)


def make_tar_bytes(src: Path) -> bytes:
    src = src.resolve()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        if src.is_dir():
            for path in sorted(src.rglob("*")):
                if ".git" in path.relative_to(src).parts:
                    continue
                arcname = path.relative_to(src).as_posix()
                tar.add(path, arcname=arcname, recursive=False)
        else:
            tar.add(src, arcname=src.name)
    return buffer.getvalue()


def git_archive_or_tar(src: Path) -> tuple[bytes, str]:
    src = src.resolve()
    if src.is_dir():
        proc = subprocess.run(
            ["git", "-C", str(src), "archive", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.returncode == 0:
            return proc.stdout, "git archive HEAD"
    return make_tar_bytes(src), "tar"


def is_dirty_worktree(src: Path) -> bool:
    """Return True if src is a git repo with uncommitted changes in the working tree."""
    if not src.is_dir():
        return False
    try:
        proc = subprocess.run(
            ["git", "-C", str(src.resolve()), "status", "--porcelain"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return proc.returncode == 0 and bool(proc.stdout.strip())
    except OSError:
        return False


def safe_extract_tar_bytes(tar_bytes: bytes, dst: Path) -> list[Path]:
    dst = dst.resolve()
    extracted: list[Path] = []
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tar:
        for member in tar.getmembers():
            member_path = dst / member.name
            resolved = member_path.resolve()
            if os.path.commonpath([dst, resolved]) != str(dst):
                raise ValueError(f"unsafe tar member path: {member.name}")
            if member.isdir():
                resolved.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            resolved.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                continue
            with resolved.open("wb") as f:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    f.write(chunk)
            extracted.append(resolved)
    return extracted

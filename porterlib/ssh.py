from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import tarfile
from dataclasses import dataclass


SAFE_REMOTE_GLOB = re.compile(r"^[A-Za-z0-9_./*?\[\]-]+$")


@dataclass
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class TransferMember:
    path: str
    size: int
    sha256: str


class SSHTransport:
    def __init__(self, host: str) -> None:
        self.host = host

    def argv_for(self, remote_argv: list[str]) -> list[str]:
        return ["ssh", self.host, *remote_argv]

    def run_script(self, script: str) -> CommandResult:
        proc = subprocess.run(
            self.argv_for(["sh", "-s"]),
            input=script.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    def run_script_combined(self, script: str) -> CommandResult:
        proc = subprocess.run(
            self.argv_for(["sh", "-s"]),
            input=script.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        return CommandResult(proc.returncode, proc.stdout, b"")

    def push_tar_stream(self, dst: str, tar_bytes: bytes) -> CommandResult:
        remote = self.push_remote_command(dst)
        proc = subprocess.run(
            self.argv_for([remote]),
            input=tar_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    def push_remote_command(self, dst: str) -> str:
        return f"mkdir -p {shlex.quote(dst)} && tar -x -C {shlex.quote(dst)}"

    def pull_tar_stream(self, workdir: str, remote_glob: str) -> CommandResult:
        if not SAFE_REMOTE_GLOB.match(remote_glob) or ".." in Path(remote_glob).parts:
            return CommandResult(2, b"", f"unsafe remote glob: {remote_glob}\n".encode())
        remote = self.pull_remote_command(workdir, remote_glob)
        proc = subprocess.run(
            self.argv_for([remote]),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    def pull_remote_command(self, workdir: str, remote_glob: str) -> str:
        return f"cd {shlex.quote(workdir)} && tar -cf - -- {remote_glob}"

    def run_remote_argv(self, remote_argv: list[str]) -> CommandResult:
        proc = subprocess.run(
            self.argv_for(remote_argv),
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


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def transfer_members_from_path(src: Path) -> list[TransferMember]:
    src = src.resolve()
    if src.is_dir():
        members: list[TransferMember] = []
        for path in sorted(src.rglob("*")):
            if ".git" in path.relative_to(src).parts:
                continue
            if not path.is_file():
                continue
            members.append(
                TransferMember(
                    path=path.relative_to(src).as_posix(),
                    size=path.stat().st_size,
                    sha256=_sha256_path(path),
                )
            )
        return members
    if src.is_file():
        return [TransferMember(path=src.name, size=src.stat().st_size, sha256=_sha256_path(src))]
    raise FileNotFoundError(src)


def _canonical_members(members: list[TransferMember]) -> bytes:
    return json.dumps(
        [{"path": member.path, "size": member.size, "sha256": member.sha256} for member in members],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def transfer_manifest_sha256(members: list[TransferMember]) -> str:
    return hashlib.sha256(_canonical_members(members)).hexdigest()


def _safe_member_path(raw: str) -> str:
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe tar member path: {raw}")
    return path.as_posix()


def transfer_members_from_tar_bytes(tar_bytes: bytes) -> list[TransferMember]:
    members: list[TransferMember] = []
    seen: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tar:
        for member in tar.getmembers():
            path = _safe_member_path(member.name)
            if member.isdir():
                continue
            if not member.isfile():
                continue
            if path in seen:
                raise ValueError(f"duplicate tar member path: {path}")
            source = tar.extractfile(member)
            if source is None:
                raise ValueError(f"regular tar member has no content stream: {path}")
            digest = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
            if size != member.size:
                raise ValueError(f"tar member size mismatch: {path}")
            seen.add(path)
            members.append(TransferMember(path=path, size=size, sha256=digest.hexdigest()))
    members.sort(key=lambda member: member.path)
    return members


def is_exact_git_worktree_root(src: Path) -> bool:
    if not src.is_dir():
        return False
    try:
        proc = subprocess.run(
            ["git", "-C", str(src.resolve()), "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError:
        return False
    if proc.returncode != 0:
        return False
    top = proc.stdout.decode("utf-8", errors="replace").strip()
    return bool(top) and Path(top).resolve() == src.resolve()


def git_archive_or_tar(src: Path) -> tuple[bytes, str]:
    src = src.resolve()
    if is_exact_git_worktree_root(src):
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


def build_remote_verification_script(dst: str, members: list[TransferMember]) -> str:
    lines = [
        "set -eu",
        f"cd {shlex.quote(dst)}",
        "verified_count=0",
        "check_file() {",
        '  rel="$1"',
        '  expected_size="$2"',
        '  expected_sha="$3"',
        '  if [ ! -f "$rel" ] || [ -L "$rel" ]; then',
        "    printf 'MISSING\\t%s\\n' \"$rel\"",
        "    exit 97",
        "  fi",
        '  observed_size="$(wc -c < \"$rel\" | tr -d \"[:space:]\")"',
        '  if [ "$observed_size" != "$expected_size" ]; then',
        "    printf 'SIZE\\t%s\\t%s\\n' \"$rel\" \"$observed_size\"",
        "    exit 98",
        "  fi",
        '  observed_sha="$(sha256sum -- \"$rel\" | awk \'{print $1}\')"',
        '  if [ "$observed_sha" != "$expected_sha" ]; then',
        "    printf 'SHA\\t%s\\t%s\\n' \"$rel\" \"$observed_sha\"",
        "    exit 99",
        "  fi",
        "  printf 'OK\\t%s\\t%s\\t%s\\n' \"$rel\" \"$observed_size\" \"$observed_sha\"",
        '  verified_count="$((verified_count + 1))"',
        "}",
    ]
    for member in members:
        lines.append(
            f"check_file {shlex.quote(member.path)} {shlex.quote(str(member.size))} {shlex.quote(member.sha256)}"
        )
    lines.append("printf 'COUNT\\t%s\\n' \"$verified_count\"")
    return "\n".join(lines) + "\n"


def parse_remote_verification(stdout: bytes) -> tuple[list[TransferMember], int]:
    members: list[TransferMember] = []
    count: int | None = None
    for raw_line in stdout.decode("utf-8", errors="replace").splitlines():
        if not raw_line:
            continue
        fields = raw_line.split("\t")
        if fields[0] == "OK" and len(fields) == 4:
            path, size_text, sha256 = fields[1:]
            members.append(TransferMember(path=path, size=int(size_text), sha256=sha256))
            continue
        if fields[0] == "COUNT" and len(fields) == 2:
            count = int(fields[1])
            continue
    members.sort(key=lambda member: member.path)
    if count is None:
        raise ValueError("remote transfer verification omitted member count")
    if count != len(members):
        raise ValueError("remote transfer verification count mismatch")
    return members, count


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
            with resolved.open("wb") as handle:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    handle.write(chunk)
            extracted.append(resolved)
    return extracted

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any

from .ssh import SSHTransport


PROFILE_SCHEMA = "porter.ssh-exact-profile.v1"
PROFILE_FIELDS = frozenset(
    {
        "schema",
        "endpoint_id",
        "session_id",
        "host",
        "port",
        "user",
        "ssh_executable",
        "ssh_executable_sha256",
        "identity_file",
        "identity_public_file",
        "client_key_fingerprint",
        "known_hosts_file",
        "known_hosts_sha256",
        "guest_host_key_fingerprint",
        "remote_root",
        "workdir",
        "identity_argv",
        "expected_identity",
    }
)
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class ExactSSHProfileError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def exact_regular_path(value: Any, field: str, *, executable: bool = False) -> Path:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ExactSSHProfileError(f"{field} must be an absolute path")
    path = Path(value)
    try:
        stat = path.lstat()
    except OSError as exc:
        raise ExactSSHProfileError(f"{field} is unavailable: {exc}") from exc
    if path.is_symlink() or not path.is_file() or path.resolve() != path:
        raise ExactSSHProfileError(f"{field} must be one exact regular file")
    if executable and not os.access(path, os.X_OK):
        raise ExactSSHProfileError(f"{field} is not executable")
    if stat.st_mode & 0o022:
        raise ExactSSHProfileError(f"{field} is group/world writable")
    return path


def ssh_fingerprint_from_line(line: str) -> str:
    fields = line.strip().split()
    if len(fields) < 2:
        raise ExactSSHProfileError("malformed SSH public key line")
    try:
        wire = base64.b64decode(fields[1], validate=True)
    except ValueError as exc:
        raise ExactSSHProfileError("malformed SSH public key bytes") from exc
    value = base64.b64encode(hashlib.sha256(wire).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{value}"


def public_key_fingerprint(path: Path) -> str:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) != 1:
        raise ExactSSHProfileError("identity_public_file must contain exactly one key")
    return ssh_fingerprint_from_line(lines[0])


def known_host_fingerprints(path: Path) -> set[str]:
    values: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3:
            raise ExactSSHProfileError("known_hosts_file contains a malformed line")
        values.add(ssh_fingerprint_from_line(" ".join(fields[1:3])))
    if not values:
        raise ExactSSHProfileError("known_hosts_file contains no host key")
    return values


def exact_remote_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\n" in value or "\x00" in value:
        raise ExactSSHProfileError(f"{field} must be an absolute remote path")
    path = PurePosixPath(value)
    if ".." in path.parts or str(path) != value.rstrip("/"):
        raise ExactSSHProfileError(f"{field} is not canonical")
    return value


@dataclass(frozen=True)
class ExactSSHProfile:
    source: Path
    source_sha256: str
    endpoint_id: str
    session_id: str
    host: str
    port: int
    user: str
    ssh_executable: Path
    ssh_executable_sha256: str
    identity_file: Path
    identity_public_file: Path
    client_key_fingerprint: str
    known_hosts_file: Path
    known_hosts_sha256: str
    guest_host_key_fingerprint: str
    remote_root: str
    workdir: str
    identity_argv: tuple[str, ...]
    expected_identity: dict[str, Any]

    def declared(self) -> dict[str, Any]:
        return {
            "profile_schema": PROFILE_SCHEMA,
            "profile_path": str(self.source),
            "profile_sha256": self.source_sha256,
            "endpoint_id": self.endpoint_id,
            "session_id": self.session_id,
            "endpoint_socket": f"{self.host}:{self.port}",
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "ssh_executable": str(self.ssh_executable),
            "ssh_executable_sha256": self.ssh_executable_sha256,
            "identity_file": str(self.identity_file),
            "identity_public_file": str(self.identity_public_file),
            "client_key_fingerprint": self.client_key_fingerprint,
            "known_hosts_file": str(self.known_hosts_file),
            "known_hosts_sha256": self.known_hosts_sha256,
            "guest_host_key_fingerprint": self.guest_host_key_fingerprint,
            "remote_root": self.remote_root,
            "workdir": self.workdir,
            "identity_argv": list(self.identity_argv),
            "expected_identity": self.expected_identity,
        }


def parse_exact_target(target: str) -> Path:
    prefix = "ssh-exact:"
    if not target.startswith(prefix) or not target[len(prefix) :]:
        raise ExactSSHProfileError("ssh-exact target requires an absolute profile path")
    return exact_regular_path(target[len(prefix) :], "profile")


def load_profile(target: str) -> ExactSSHProfile:
    source = parse_exact_target(target)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExactSSHProfileError(f"could not read exact SSH profile: {exc}") from exc
    if not isinstance(value, dict) or set(value) != PROFILE_FIELDS:
        raise ExactSSHProfileError("exact SSH profile fields mismatch")
    if value["schema"] != PROFILE_SCHEMA:
        raise ExactSSHProfileError("exact SSH profile schema mismatch")
    for field in ("endpoint_id", "session_id"):
        if not isinstance(value[field], str) or not ID_RE.fullmatch(value[field]):
            raise ExactSSHProfileError(f"invalid {field}")
    if value["host"] != "127.0.0.1":
        raise ExactSSHProfileError("exact SSH endpoint must be loopback IPv4")
    if type(value["port"]) is not int or not 1024 <= value["port"] <= 65535:
        raise ExactSSHProfileError("invalid exact SSH port")
    if not isinstance(value["user"], str) or not USER_RE.fullmatch(value["user"]):
        raise ExactSSHProfileError("invalid exact SSH user")

    ssh_executable = exact_regular_path(value["ssh_executable"], "ssh_executable", executable=True)
    if not isinstance(value["ssh_executable_sha256"], str) or not HEX64_RE.fullmatch(value["ssh_executable_sha256"]):
        raise ExactSSHProfileError("invalid ssh_executable_sha256")
    if sha256_file(ssh_executable) != value["ssh_executable_sha256"]:
        raise ExactSSHProfileError("SSH executable substitution")
    identity_file = exact_regular_path(value["identity_file"], "identity_file")
    if identity_file.stat().st_mode & 0o077:
        raise ExactSSHProfileError("identity_file must be owner-only")
    identity_public = exact_regular_path(value["identity_public_file"], "identity_public_file")
    client_fingerprint = public_key_fingerprint(identity_public)
    if client_fingerprint != value["client_key_fingerprint"]:
        raise ExactSSHProfileError("SSH client identity substitution")
    known_hosts = exact_regular_path(value["known_hosts_file"], "known_hosts_file")
    if not isinstance(value["known_hosts_sha256"], str) or not HEX64_RE.fullmatch(value["known_hosts_sha256"]):
        raise ExactSSHProfileError("invalid known_hosts_sha256")
    if sha256_file(known_hosts) != value["known_hosts_sha256"]:
        raise ExactSSHProfileError("known_hosts substitution")
    if value["guest_host_key_fingerprint"] not in known_host_fingerprints(known_hosts):
        raise ExactSSHProfileError("guest host key fingerprint substitution")

    remote_root = exact_remote_path(value["remote_root"], "remote_root")
    workdir = exact_remote_path(value["workdir"], "workdir")
    if PurePosixPath(remote_root) not in PurePosixPath(workdir).parents and workdir != remote_root:
        raise ExactSSHProfileError("workdir is outside remote_root")
    identity_argv = value["identity_argv"]
    if not isinstance(identity_argv, list) or not identity_argv or len(identity_argv) > 16:
        raise ExactSSHProfileError("invalid identity_argv")
    if any(not isinstance(arg, str) or not arg or "\x00" in arg or "\n" in arg for arg in identity_argv):
        raise ExactSSHProfileError("unsafe identity_argv")
    expected = value["expected_identity"]
    if not isinstance(expected, dict) or not expected or len(expected) > 32:
        raise ExactSSHProfileError("invalid expected_identity")
    if expected.get("session_id") != value["session_id"]:
        raise ExactSSHProfileError("expected identity session mismatch")
    if any(not isinstance(key, str) or key in {"success", "passed", "supported", "admissible"} for key in expected):
        raise ExactSSHProfileError("unsafe expected identity key")

    return ExactSSHProfile(
        source=source,
        source_sha256=sha256_file(source),
        endpoint_id=value["endpoint_id"],
        session_id=value["session_id"],
        host=value["host"],
        port=value["port"],
        user=value["user"],
        ssh_executable=ssh_executable,
        ssh_executable_sha256=value["ssh_executable_sha256"],
        identity_file=identity_file,
        identity_public_file=identity_public,
        client_key_fingerprint=client_fingerprint,
        known_hosts_file=known_hosts,
        known_hosts_sha256=value["known_hosts_sha256"],
        guest_host_key_fingerprint=value["guest_host_key_fingerprint"],
        remote_root=remote_root,
        workdir=workdir,
        identity_argv=tuple(identity_argv),
        expected_identity=dict(expected),
    )


class ExactSSHTransport(SSHTransport):
    def __init__(self, declared: dict[str, Any]) -> None:
        self.declared = declared
        target = f"ssh-exact:{declared['profile_path']}"
        profile = load_profile(target)
        if profile.source_sha256 != declared["profile_sha256"] or profile.declared() != declared:
            raise ExactSSHProfileError("exact SSH profile changed after custody")
        self.profile = profile
        super().__init__(f"{profile.user}@{profile.host}")

    def argv_for(self, remote_argv: list[str]) -> list[str]:
        profile = self.profile
        return [
            str(profile.ssh_executable),
            "-F", "/dev/null",
            "-p", str(profile.port),
            "-i", str(profile.identity_file),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={profile.known_hosts_file}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "PreferredAuthentications=publickey",
            "-o", "ClearAllForwardings=yes",
            "-o", "ControlMaster=no",
            "-o", "RequestTTY=no",
            "-o", "ConnectTimeout=10",
            "-o", "ConnectionAttempts=1",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=2",
            "-o", "TCPKeepAlive=yes",
            "--",
            f"{profile.user}@{profile.host}",
            *remote_argv,
        ]

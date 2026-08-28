from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from porterlib import record as records
from porterlib import runner
from porterlib.exact_ssh import (
    ExactSSHProfileError,
    load_profile,
    public_key_fingerprint,
    sha256_file,
)


class ExactEndpointFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.runs = root / "runs"
        self.state = root / "identity.json"
        self.identity = root / "client-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.identity)],
            check=True,
        )
        self.known_hosts = root / "known_hosts"
        public_fields = self.identity.with_suffix(".pub").read_text(encoding="utf-8").split()
        self.known_hosts.write_text(
            f"[127.0.0.1]:23022 {public_fields[0]} {public_fields[1]}\n",
            encoding="utf-8",
        )
        self.fake_ssh = root / "exact-ssh"
        self.known_hosts.chmod(0o644)
        self.fake_ssh.write_text(
            """#!/usr/bin/python3
import pathlib, re, sys
args = sys.argv[1:]
if args[-2:] == ['/usr/local/libexec/porter-fixture', 'identity']:
    sys.stdout.buffer.write(pathlib.Path(%r).read_bytes())
elif args[-2:] == ['sh', '-s']:
    script = sys.stdin.buffer.read().decode('utf-8')
    token = re.findall(r'__PORTER_RC_[0-9a-f]+__', script)[-1]
    sys.stdout.write('fixture payload\\n' + token + ':0\\n')
else:
    sys.stdin.buffer.read()
""" % str(self.state),
            encoding="utf-8",
        )
        self.fake_ssh.chmod(0o755)
        self.profile = root / "endpoint.json"
        self.session_id = "session-0001"
        self.expected = {
            "schema": "porter.fixture-identity/v1",
            "session_id": self.session_id,
            "agent_sha256": "a" * 64,
            "capacity": 3,
        }
        self.write_identity(self.session_id)
        self.write_profile()

    @property
    def target(self) -> str:
        return f"ssh-exact:{self.profile}"

    def write_identity(self, session_id: str) -> None:
        actual = dict(self.expected)
        actual["session_id"] = session_id
        actual["boot_id"] = "boot-fixture-0001"
        self.state.write_text(json.dumps(actual, sort_keys=True) + "\n", encoding="utf-8")

    def write_profile(self) -> None:
        guest_fingerprint = public_key_fingerprint(self.identity.with_suffix(".pub"))
        value = {
            "schema": "porter.ssh-exact-profile.v1",
            "endpoint_id": "endpoint-0001",
            "session_id": self.session_id,
            "host": "127.0.0.1",
            "port": 23022,
            "user": "fixture",
            "ssh_executable": str(self.fake_ssh),
            "ssh_executable_sha256": sha256_file(self.fake_ssh),
            "identity_file": str(self.identity),
            "identity_public_file": str(self.identity.with_suffix(".pub")),
            "client_key_fingerprint": guest_fingerprint,
            "known_hosts_file": str(self.known_hosts),
            "known_hosts_sha256": sha256_file(self.known_hosts),
            "guest_host_key_fingerprint": guest_fingerprint,
            "remote_root": "/var/lib/porter-fixture",
            "workdir": "/var/lib/porter-fixture/work",
            "identity_argv": ["/usr/local/libexec/porter-fixture", "identity"],
            "expected_identity": self.expected,
        }
        self.profile.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        self.profile.chmod(0o644)


def test_exact_profile_builds_pinned_argv_and_rejects_extra_fields() -> None:
    with tempfile.TemporaryDirectory() as raw:
        fixture = ExactEndpointFixture(Path(raw))
        profile = load_profile(fixture.target)
        declared = profile.declared()
        assert declared["endpoint_socket"] == "127.0.0.1:23022"
        assert declared["profile_sha256"] == sha256_file(fixture.profile)

        value = json.loads(fixture.profile.read_text(encoding="utf-8"))
        value["qualification"] = "not-a-porter-field"
        fixture.profile.write_text(json.dumps(value), encoding="utf-8")
        try:
            load_profile(fixture.target)
        except ExactSSHProfileError as exc:
            assert "fields mismatch" in str(exc)
        else:
            raise AssertionError("profile with an extra field was accepted")


def test_exact_endpoint_records_identity_argv_exit_and_transcript_hash() -> None:
    with tempfile.TemporaryDirectory() as raw:
        fixture = ExactEndpointFixture(Path(raw))
        run_id, record = runner.up(fixture.target, fixture.runs)
        assert record["substrate"]["transport"] == "ssh-exact"
        assert record["substrate"]["observed"]["guest_transport_identity"]["boot_id"] == "boot-fixture-0001"
        snapshot = fixture.runs / run_id / "exact-endpoint-profile.json"
        assert snapshot.read_bytes() == fixture.profile.read_bytes()
        assert snapshot.stat().st_mode & 0o777 == 0o600
        assert record["transport_profiles"][0]["sha256"] == sha256_file(snapshot)


        record = runner.exec_command(run_id, fixture.runs, ["printf", "payload"])
        record = runner.seal(run_id, fixture.runs)
        assert record["outcome"] == records.OUTCOME_COMPLETED
        exec_step = next(step for step in record["steps"] if step["kind"] == "exec")
        assert exec_step["payload_argv"] == ["printf", "payload"]
        assert exec_step["exit_code"] == 0
        assert exec_step["exit_code_observed"] is True
        assert exec_step["transport_argv"][0] == str(fixture.fake_ssh)
        assert "StrictHostKeyChecking=yes" in exec_step["transport_argv"]
        assert len(exec_step["transcript_sha256"]) == 64
        checks = [step for step in record["steps"] if step["kind"] == "transport-check"]
        assert [step["purpose"] for step in checks] == ["connect", "exec"]
        assert all(len(step["transcript_sha256"]) == 64 for step in checks)


def test_exact_push_records_source_and_transport_payload_hashes() -> None:
    with tempfile.TemporaryDirectory() as raw:
        fixture = ExactEndpointFixture(Path(raw))
        run_id, _ = runner.up(fixture.target, fixture.runs)
        source = fixture.root / "predecessor.bundle"
        source.write_bytes(b"exact bundle bytes\n")
        record = runner.push(run_id, fixture.runs, source, "/var/lib/porter-fixture/inbox")
        step = next(step for step in record["steps"] if step["kind"] == "push")
        artifact = step["input_artifacts"][0]
        assert artifact["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
        assert artifact["size"] == source.stat().st_size
        assert len(artifact["archive_sha256"]) == 64
        assert step["transport_argv"][0] == str(fixture.fake_ssh)


def test_remote_session_substitution_refuses_before_payload_invocation() -> None:
    with tempfile.TemporaryDirectory() as raw:
        fixture = ExactEndpointFixture(Path(raw))
        run_id, _ = runner.up(fixture.target, fixture.runs)
        fixture.write_identity("session-evil")
        record = runner.exec_command(run_id, fixture.runs, ["printf", "must-not-run"])
        assert record["outcome"] == records.OUTCOME_REFUSED
        assert "session_id" in record["refusal_reason"]
        assert not any(step["kind"] == "exec" for step in record["steps"])


def test_known_hosts_substitution_refuses_and_records_no_payload() -> None:
    with tempfile.TemporaryDirectory() as raw:
        fixture = ExactEndpointFixture(Path(raw))
        run_id, _ = runner.up(fixture.target, fixture.runs)
        fixture.known_hosts.write_text("substituted\n", encoding="utf-8")
        record = runner.exec_command(run_id, fixture.runs, ["printf", "must-not-run"])
        assert record["outcome"] == records.OUTCOME_REFUSED
        assert "known_hosts substitution" in record["refusal_reason"]
        check = record["steps"][-1]
        assert check["kind"] == "transport-check"
        assert check["exit_code_observed"] is False
        assert not any(step["kind"] == "exec" for step in record["steps"])

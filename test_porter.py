from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from unittest import mock
from pathlib import Path
from typing import Any

import porter
from porterlib import record as records
from porterlib import runner
from porterlib import ssh as sshlib


ROOT = Path(__file__).resolve().parent
PORTER = ROOT / "porter"
FIXTURES = ROOT / "tests" / "fixtures"


class RecordContractTests(unittest.TestCase):
    def load_golden(self) -> dict[str, Any]:
        with (FIXTURES / "porter-record-v0.completed.json").open("r", encoding="utf-8") as f:
            return json.load(f)

    def assert_json_subset(self, expected: Any, actual: Any) -> None:
        if isinstance(expected, dict):
            self.assertIsInstance(actual, dict)
            for key, value in expected.items():
                self.assertIn(key, actual)
                self.assert_json_subset(value, actual[key])
            return
        if isinstance(expected, list):
            self.assertIsInstance(actual, list)
            self.assertEqual(len(actual), len(expected))
            for expected_item, actual_item in zip(expected, actual):
                self.assert_json_subset(expected_item, actual_item)
            return
        self.assertEqual(actual, expected)

    def fixture_shaped_record(self) -> dict[str, Any]:
        record = records.new_record(
            "2026-06-30T18-22-05Z-ab12cd",
            "ssh:fixture",
            "fixture",
            "/tmp/porter-fixture",
        )
        record["substrate"]["observed"] = {
            "hostname": "fixture-host",
            "os": "Linux",
            "kernel": "6.8.0-fixture",
            "arch": "x86_64",
        }
        record["declared_command"] = ["sh", "-c", "printf data > out.txt"]
        step = records.add_step(
            record,
            kind="exec",
            declared="sh -c 'printf data > out.txt'",
            started_at="2026-06-30T18:22:05Z",
            ended_at="2026-06-30T18:22:06Z",
            transcript="transcripts/0001-exec.log",
            exit_code=0,
            exit_code_observed=True,
        )
        step["transcript_sha256"] = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        record["artifacts"].append(
            {
                "class": records.CUSTODY_BLOB,
                "remote_path": "out.txt",
                "local_path": "artifacts/out.txt",
                "sha256": "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7",
                "size": 4,
            }
        )
        record["outcome"] = records.OUTCOME_COMPLETED
        return record

    def test_golden_record_fixture_is_valid_v0(self) -> None:
        record = self.load_golden()

        records.validate_record_contract(record)

        self.assertEqual(record["schema"], records.RECORD_SCHEMA)
        self.assertEqual(set(record), records.REQUIRED_RECORD_V0_FIELDS)

        # Pin: every step carries class="receipt"; every artifact carries class="blob".
        for step in record["steps"]:
            self.assertEqual(step["class"], records.CUSTODY_RECEIPT, f"step {step.get('seq')} class wrong")
        for artifact in record["artifacts"]:
            self.assertEqual(artifact["class"], records.CUSTODY_BLOB, f"artifact {artifact.get('local_path')} class wrong")

    def test_generated_record_preserves_golden_v0_shape(self) -> None:
        golden = self.load_golden()
        record = self.fixture_shaped_record()

        records.validate_record_contract(record)

        # The golden is a full-shape pin including class fields; assert_json_subset
        # verifies the generated record contains every key/value the golden declares.
        self.assert_json_subset(golden, record)

        # Explicit class-field assertions so the intent is stated at read time.
        for step in record["steps"]:
            self.assertEqual(step["class"], records.CUSTODY_RECEIPT)
        for artifact in record["artifacts"]:
            self.assertEqual(artifact["class"], records.CUSTODY_BLOB)

    def test_no_ag_vocabulary_in_porter_tree(self) -> None:
        """Porter must not carry AG-internal vocabulary in code or data files.

        AG-specific field names (cage + attestation, not_live + testimony) belong
        to agent_gov, not porter.  If they appear in .py/.sh/.json files in this
        tree it means AG-specific records were committed here — a domain-separation
        violation (porter charter §1 / DESIGN.md F6).

        Terms are assembled from parts so this file does not self-trigger.
        """
        # Split so this file does not match its own scan.
        ag_terms = [
            "cage_" + "attestation",
            "not_live_" + "testimony",
        ]
        scan_suffixes = {".py", ".sh", ".json"}
        violations: list[str] = []

        for path in sorted(ROOT.rglob("*")):
            if ".git" in path.parts or "__pycache__" in path.parts:
                continue
            if path.suffix not in scan_suffixes or not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for term in ag_terms:
                if term in text:
                    violations.append(f"{path.relative_to(ROOT)}: contains {term!r}")

        if violations:
            self.fail("AG vocabulary in porter tree (domain-separation violation):\n" + "\n".join(violations))

    def test_domain_verdict_fields_are_rejected_at_any_depth(self) -> None:
        for field in records.DOMAIN_VERDICT_FIELDS:
            bad = copy.deepcopy(self.load_golden())
            bad[field] = True
            with self.assertRaises(records.RecordContractError):
                records.validate_record_contract(bad)

        bad = copy.deepcopy(self.load_golden())
        bad["steps"][0]["passed"] = True
        with self.assertRaises(records.RecordContractError):
            records.validate_record_contract(bad)

    def test_unobserved_exit_code_cannot_be_recorded(self) -> None:
        bad = copy.deepcopy(self.load_golden())
        bad["steps"][0]["exit_code_observed"] = False

        with self.assertRaises(records.RecordContractError):
            records.validate_record_contract(bad)

        with self.assertRaises(records.RecordContractError):
            records.add_step(
                records.new_record("run", "ssh:fixture", "fixture", "/tmp/porter-fixture"),
                kind="exec",
                declared="false",
                started_at="2026-06-30T18:22:05Z",
                ended_at="2026-06-30T18:22:06Z",
                exit_code=0,
                exit_code_observed=False,
            )

    def test_exit_policy_is_recorded_and_mapped_to_process_status(self) -> None:
        completed = records.new_record("completed", "ssh:fixture", "fixture", "/tmp/porter-fixture")
        records.add_step(
            completed,
            kind="exec",
            declared="true",
            started_at="2026-06-30T18:22:05Z",
            ended_at="2026-06-30T18:22:06Z",
            exit_code=0,
        )
        records.decide_outcome(completed)
        self.assertEqual(completed["outcome"], records.OUTCOME_COMPLETED)
        self.assertEqual(runner.process_exit_for(completed), 0)

        run_failed = records.new_record("failed", "ssh:fixture", "fixture", "/tmp/porter-fixture")
        records.add_step(
            run_failed,
            kind="exec",
            declared="exit 7",
            started_at="2026-06-30T18:22:05Z",
            ended_at="2026-06-30T18:22:06Z",
            exit_code=7,
        )
        records.decide_outcome(run_failed)
        self.assertEqual(run_failed["outcome"], records.OUTCOME_RUN_FAILED)
        self.assertEqual(runner.process_exit_for(run_failed), 0)
        self.assertEqual(runner.process_exit_for(run_failed, propagate_exit=True), 7)

        refused = records.new_record("refused", "ssh:fixture", "fixture", "/tmp/porter-fixture")
        records.add_step(
            refused,
            kind="exec",
            declared="unknown",
            started_at="2026-06-30T18:22:05Z",
            ended_at="2026-06-30T18:22:06Z",
            exit_code_observed=False,
        )
        records.decide_outcome(refused)
        self.assertEqual(refused["outcome"], records.OUTCOME_REFUSED)
        self.assertEqual(runner.process_exit_for(refused), 1)

        porter_failed = records.new_record("porter-failed", "ssh:fixture", "fixture", "/tmp/porter-fixture")
        records.mark_porter_failed(porter_failed, "transport failed")
        self.assertEqual(runner.process_exit_for(porter_failed), 1)

    # ── F1: Porter-computed fact_mismatches (declared vs observed) ──────────

    def test_fact_mismatches_match_yields_zero(self) -> None:
        observed = {"os": "Linux", "arch": "x86_64", "hostname": "h1"}
        declared = {"os": "Linux", "arch": "x86_64"}
        self.assertEqual(records.compute_fact_mismatches(declared, observed), [])

    def test_fact_mismatches_mismatch_is_emitted(self) -> None:
        observed = {"os": "Linux", "arch": "x86_64"}
        declared = {"os": "Darwin", "arch": "x86_64"}
        self.assertEqual(
            records.compute_fact_mismatches(declared, observed),
            [{"fact": "os", "declared": "Darwin", "observed": "Linux"}],
        )

    def test_fact_mismatches_only_compares_observed_facts(self) -> None:
        # arch is declared but never observed → nothing to compare, not a mismatch.
        observed = {"os": "Linux"}
        declared = {"os": "Linux", "arch": "arm64"}
        self.assertEqual(records.compute_fact_mismatches(declared, observed), [])

    # ── F5: run-state locking ──────────────────────────────────────────────

    def test_run_lock_is_exclusive_then_reacquirable(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            records.ensure_layout(base)
            with records.run_lock(base):
                with self.assertRaises(records.RunLockedError):
                    with records.run_lock(base):
                        pass
            # released on exit → acquirable again (steps are sequential, not blocked forever)
            with records.run_lock(base):
                pass

    def test_run_lock_file_is_excluded_from_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            records.ensure_layout(base)
            (base / records.RUN_LOCK_NAME).write_bytes(b"")
            names = {p.name for p in records.iter_checksum_files(base)}
            self.assertNotIn(records.RUN_LOCK_NAME, names)


class FakeSerialServer:
    def __init__(self, socket_path: Path) -> None:
        self.socket_path = socket_path
        self.stop_event = threading.Event()
        self.server: socket.socket | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> "FakeSerialServer":
        self.socket_path.unlink(missing_ok=True)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.socket_path))
        self.server.listen()
        self.server.settimeout(0.1)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.stop_event.set()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as wake:
                wake.connect(str(self.socket_path))
        except OSError:
            pass
        if self.server is not None:
            self.server.close()
        if self.thread is not None:
            self.thread.join(timeout=1)
        self.socket_path.unlink(missing_ok=True)

    def _serve(self) -> None:
        assert self.server is not None
        while not self.stop_event.is_set():
            try:
                conn, _addr = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                self._handle(conn)

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(0.5)
        chunks: list[bytes] = []
        while not self.stop_event.is_set():
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                return
            except OSError:
                return
            if not chunk:
                return
            chunks.append(chunk)
            if b"\n" in chunk:
                break

        line = b"".join(chunks).decode("utf-8", errors="replace")
        if "PORTER_TEST_DROP" in line:
            conn.sendall(b"serial before drop\r\n")
            return

        token_match = re.search(r"(__PORTER_RC_[0-9a-f]+__)", line)
        if token_match is None:
            conn.sendall(b"serial command had no porter token\r\n")
            return

        rc = 7 if "exit 7" in line else 0
        token = token_match.group(1)
        conn.sendall(f"serial output\r\n{token}:{rc}\r\n".encode("ascii"))


class PorterCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.fakebin = self.tmp_path / "fakebin"
        self.fakebin.mkdir()
        fake_ssh = self.fakebin / "ssh"
        fake_ssh.write_text(
            textwrap.dedent(
                """\
                #!/bin/sh
                _host="$1"
                shift
                if [ "$1" = "sh" ] && [ "$2" = "-s" ]; then
                  script="$(mktemp)"
                  cat > "$script"
                  if grep -q PORTER_TEST_DROP "$script"; then
                    printf 'simulated dropped connection\\n'
                    rm -f "$script"
                    exit 255
                  fi
                  sh "$script"
                  rc="$?"
                  rm -f "$script"
                  exit "$rc"
                fi
                exec sh -c "$*"
                """
            ),
            encoding="utf-8",
        )
        fake_ssh.chmod(0o755)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_porter(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PATH"] = f"{self.fakebin}{os.pathsep}{env['PATH']}"
        return subprocess.run(
            [sys.executable, str(PORTER), *args],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def load_record(self, runs_dir: Path, run_id: str) -> dict:
        with (runs_dir / run_id / "record.json").open("r", encoding="utf-8") as f:
            record = json.load(f)
        records.validate_record_contract(record)
        return record

    def class_values(self, value: Any) -> list[str]:
        values: list[str] = []
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "class" and isinstance(child, str):
                    values.append(child)
                values.extend(self.class_values(child))
        elif isinstance(value, list):
            for child in value:
                values.extend(self.class_values(child))
        return values

    def write_recipe(self, remote_root: Path, marker: Path) -> Path:
        recipe = self.tmp_path / f"recipe-{len(list(self.tmp_path.glob('recipe-*.py')))}.py"
        recipe.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env python3
                import json
                import pathlib
                import sys

                action = sys.argv[1]
                run_id = sys.argv[2]
                if action == "up":
                    print(json.dumps({{
                        "kind": "vm",
                        "transport": "ssh",
                        "ephemeral": True,
                        "declared": {{
                            "host": "fake",
                            "remote_root": {str(remote_root)!r},
                            "workdir": {str(remote_root / 'work')!r},
                        }},
                        "observed": {{"recipe_run_id": run_id}},
                        "fact_mismatches": [],
                    }}))
                elif action == "down":
                    pathlib.Path({str(marker)!r}).write_text(run_id, encoding="utf-8")
                    print("down")
                else:
                    sys.exit(64)
                """
            ),
            encoding="utf-8",
        )
        recipe.chmod(0o755)
        return recipe

    def write_facts_recipe(
        self,
        remote_root: Path,
        declared_facts: dict,
        caller_mismatches: list,
    ) -> Path:
        """Recipe that declares expected facts and (hostilely) predeclares its own
        fact_mismatches — used to prove the caller cannot control Porter's result."""
        idx = len(list(self.tmp_path.glob("facts-recipe-*.py")))
        recipe = self.tmp_path / f"facts-recipe-{idx}.py"
        recipe.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env python3
                import json
                import sys

                action = sys.argv[1]
                run_id = sys.argv[2]
                if action == "up":
                    print(json.dumps({{
                        "kind": "vm",
                        "transport": "ssh",
                        "ephemeral": True,
                        "declared": {{
                            "host": "fake",
                            "remote_root": {str(remote_root)!r},
                            "workdir": {str(remote_root / 'work')!r},
                        }},
                        "declared_facts": {json.dumps(declared_facts)},
                        "observed": {{}},
                        "fact_mismatches": {json.dumps(caller_mismatches)},
                    }}))
                elif action == "down":
                    print("down")
                else:
                    sys.exit(64)
                """
            ),
            encoding="utf-8",
        )
        recipe.chmod(0o755)
        return recipe

    def test_recipe_cannot_force_empty_fact_mismatches(self) -> None:
        """Hostile caller declares an impossible os and forces fact_mismatches=[];
        Porter observes the real os and computes the mismatch itself anyway."""
        runs_dir = self.tmp_path / "facts-runs-1"
        remote_root = self.tmp_path / "facts-remote-1"
        recipe = self.write_facts_recipe(remote_root, {"os": "PorterNoSuchOS"}, [])

        result = self.run_porter(
            "run", "--runs-dir", str(runs_dir), "--target", f"recipe:{recipe}",
            "--", "sh", "-c", "echo ok",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        run_id = result.stdout.strip()
        record = self.load_record(runs_dir, run_id)
        substrate = record["substrate"]

        self.assertEqual(substrate["declared_facts"], {"os": "PorterNoSuchOS"})
        mismatches = substrate["fact_mismatches"]
        self.assertEqual(len(mismatches), 1, f"caller forced empty; Porter must still compute: {mismatches}")
        self.assertEqual(mismatches[0]["fact"], "os")
        self.assertEqual(mismatches[0]["declared"], "PorterNoSuchOS")
        self.assertEqual(mismatches[0]["observed"], substrate["observed"]["os"])
        # A mismatch is a note, not an admission gate — the run still completes.
        self.assertEqual(record["outcome"], "completed")
        # Aggregate count is derived only from Porter's computed list.
        with (runs_dir / run_id / "export" / "aggregate.json").open("r", encoding="utf-8") as f:
            aggregate = json.load(f)
        self.assertEqual(aggregate["substrate"]["fact_mismatch_count"], 1)

    def test_recipe_predeclared_mismatches_do_not_control_result(self) -> None:
        """Hostile caller predeclares a fabricated mismatch but declares no facts;
        Porter computes an empty list and the caller's fabrication is discarded."""
        runs_dir = self.tmp_path / "facts-runs-2"
        remote_root = self.tmp_path / "facts-remote-2"
        bogus = [{"fact": "os", "declared": "Totally", "observed": "Fabricated"}]
        recipe = self.write_facts_recipe(remote_root, {}, bogus)

        result = self.run_porter(
            "run", "--runs-dir", str(runs_dir), "--target", f"recipe:{recipe}",
            "--", "sh", "-c", "echo ok",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        run_id = result.stdout.strip()
        record = self.load_record(runs_dir, run_id)
        substrate = record["substrate"]

        self.assertEqual(substrate["declared_facts"], {})
        self.assertEqual(substrate["fact_mismatches"], [], "caller's fabricated mismatch must be discarded")

    def test_expect_flag_computes_ssh_fact_mismatch(self) -> None:
        """--expect declares a host fact for a plain ssh target; Porter compares it
        to the observed value and computes the mismatch."""
        runs_dir = self.tmp_path / "expect-runs"
        remote_root = self.tmp_path / "expect-remote"

        result = self.run_porter(
            "run", "--runs-dir", str(runs_dir), "--target", "ssh:fake",
            "--remote-root", str(remote_root), "--expect", "os=PorterNoSuchOS",
            "--", "sh", "-c", "echo ok",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        run_id = result.stdout.strip()
        record = self.load_record(runs_dir, run_id)
        substrate = record["substrate"]

        self.assertEqual(substrate["declared_facts"], {"os": "PorterNoSuchOS"})
        self.assertEqual(len(substrate["fact_mismatches"]), 1)
        self.assertEqual(substrate["fact_mismatches"][0]["observed"], substrate["observed"]["os"])

    def test_exec_on_locked_run_is_refused_not_clobbered(self) -> None:
        """A second mutating op on a run whose lock is held refuses (RunLockedError)
        rather than load-append-save over the holder's step (F5)."""
        runs_dir = self.tmp_path / "lock-runs"
        remote_root = self.tmp_path / "lock-remote"
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{self.fakebin}{os.pathsep}{old_path}"
        try:
            run_id, _ = runner.up("ssh:fake", runs_dir, str(remote_root))
            base = runs_dir / run_id
            with records.run_lock(base):
                with self.assertRaises(records.RunLockedError):
                    runner.exec_command(run_id, runs_dir, ["sh", "-c", "echo hi"])
            # lock released → the same op now succeeds (sequential access still works)
            record = runner.exec_command(run_id, runs_dir, ["sh", "-c", "echo hi"])
            self.assertTrue(any(s["kind"] == "exec" for s in record["steps"]))
        finally:
            os.environ["PATH"] = old_path

    def test_nonzero_payload_is_run_failed_but_cli_zero(self) -> None:
        runs_dir = self.tmp_path / "runs"
        remote_root = self.tmp_path / "remote"

        result = self.run_porter(
            "run",
            "--runs-dir",
            str(runs_dir),
            "--target",
            "ssh:fake",
            "--remote-root",
            str(remote_root),
            "--",
            "sh",
            "-c",
            "echo hello; exit 7",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        run_id = result.stdout.strip()
        record = self.load_record(runs_dir, run_id)
        exec_step = next(step for step in record["steps"] if step["kind"] == "exec")
        transcript = runs_dir / run_id / exec_step["transcript"]

        self.assertEqual(record["schema"], records.RECORD_SCHEMA)
        self.assertEqual(record["outcome"], "run_failed")
        self.assertEqual(exec_step["exit_code"], 7)
        self.assertTrue(exec_step["exit_code_observed"])
        self.assertEqual(exec_step["transcript_sha256"], hashlib.sha256(transcript.read_bytes()).hexdigest())

    def test_missing_sentinel_refuses_and_cli_nonzero(self) -> None:
        runs_dir = self.tmp_path / "runs"
        remote_root = self.tmp_path / "remote"

        result = self.run_porter(
            "run",
            "--runs-dir",
            str(runs_dir),
            "--target",
            "ssh:fake",
            "--remote-root",
            str(remote_root),
            "--",
            "sh",
            "-c",
            "echo before drop; PORTER_TEST_DROP",
        )

        self.assertNotEqual(result.returncode, 0)
        run_id = result.stdout.strip()
        record = self.load_record(runs_dir, run_id)
        exec_step = next(step for step in record["steps"] if step["kind"] == "exec")

        self.assertEqual(record["schema"], records.RECORD_SCHEMA)
        self.assertEqual(record["outcome"], "refused")
        self.assertFalse(exec_step["exit_code_observed"])
        self.assertNotIn("exit_code", exec_step)

    def test_serial_nonzero_payload_is_run_failed_but_cli_zero(self) -> None:
        runs_dir = self.tmp_path / "runs"
        socket_path = self.tmp_path / "serial.sock"

        with FakeSerialServer(socket_path):
            result = self.run_porter(
                "run",
                "--runs-dir",
                str(runs_dir),
                "--target",
                f"serial:{socket_path}",
                "--",
                "sh",
                "-c",
                "echo hello; exit 7",
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        run_id = result.stdout.strip()
        record = self.load_record(runs_dir, run_id)
        exec_step = next(step for step in record["steps"] if step["kind"] == "exec")
        transcript = runs_dir / run_id / exec_step["transcript"]

        self.assertEqual(record["substrate"]["transport"], "serial-socket")
        self.assertEqual(record["substrate"]["declared"]["socket_path"], str(socket_path))
        self.assertEqual(record["outcome"], "run_failed")
        self.assertEqual(exec_step["exit_code"], 7)
        self.assertTrue(exec_step["exit_code_observed"])
        self.assertIn(b"serial output", transcript.read_bytes())
        self.assertNotIn(b"__NQDONE__", transcript.read_bytes())

    def test_serial_missing_sentinel_refuses_and_cli_nonzero(self) -> None:
        runs_dir = self.tmp_path / "runs"
        socket_path = self.tmp_path / "serial.sock"

        with FakeSerialServer(socket_path):
            result = self.run_porter(
                "run",
                "--runs-dir",
                str(runs_dir),
                "--target",
                f"serial:{socket_path}",
                "--",
                "sh",
                "-c",
                "echo before drop; PORTER_TEST_DROP",
            )

        self.assertNotEqual(result.returncode, 0)
        run_id = result.stdout.strip()
        record = self.load_record(runs_dir, run_id)
        exec_step = next(step for step in record["steps"] if step["kind"] == "exec")

        self.assertEqual(record["substrate"]["transport"], "serial-socket")
        self.assertEqual(record["outcome"], "refused")
        self.assertFalse(exec_step["exit_code_observed"])
        self.assertNotIn("exit_code", exec_step)
        self.assertIn("serial socket", record["refusal_reason"])

    def test_recipe_run_records_recipe_and_invokes_down_hook(self) -> None:
        runs_dir = self.tmp_path / "runs"
        remote_root = self.tmp_path / "recipe-remote"
        marker = self.tmp_path / "recipe-down.txt"
        recipe = self.write_recipe(remote_root, marker)

        result = self.run_porter(
            "run",
            "--runs-dir",
            str(runs_dir),
            "--target",
            f"recipe:{recipe}",
            "--",
            "sh",
            "-c",
            "printf recipe-run",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        run_id = result.stdout.strip()
        run_base = runs_dir / run_id
        record = self.load_record(runs_dir, run_id)
        step_kinds = [step["kind"] for step in record["steps"]]

        self.assertEqual(marker.read_text(encoding="utf-8"), run_id)
        self.assertEqual(record["substrate"]["kind"], "vm")
        self.assertEqual(record["substrate"]["transport"], "ssh")
        self.assertTrue(record["substrate"]["ephemeral"])
        self.assertEqual(record["substrate"]["declared"]["host"], "fake")
        self.assertEqual(record["substrate"]["observed"]["recipe_run_id"], run_id)
        self.assertEqual(record["outcome"], "completed")
        self.assertFalse(record["preserved"])
        with (run_base / "export" / "aggregate.json").open("r", encoding="utf-8") as f:
            aggregate = json.load(f)

        self.assertEqual(step_kinds, ["up", "exec", "down"])
        self.assertEqual(record["recipes"][0]["class"], records.CUSTODY_RECIPE)
        self.assertTrue((run_base / record["recipes"][0]["local_path"]).exists())
        self.assertTrue(record["lifecycle"]["down"]["invoked"])
        self.assertFalse(record["lifecycle"]["down"]["preserve"])
        self.assertEqual(aggregate["recipes"][0]["class"], records.CUSTODY_RECIPE)
        self.assertNotIn("source_path", aggregate["recipes"][0])
        self.assertNotIn("source_path", aggregate["lifecycle"]["recipe"])

    def test_recipe_down_preserve_skips_teardown_hook(self) -> None:
        runs_dir = self.tmp_path / "runs"
        remote_root = self.tmp_path / "recipe-preserve-remote"
        marker = self.tmp_path / "recipe-preserve-down.txt"
        recipe = self.write_recipe(remote_root, marker)

        up = self.run_porter(
            "up",
            "--runs-dir",
            str(runs_dir),
            f"recipe:{recipe}",
        )
        self.assertEqual(up.returncode, 0, up.stderr)
        run_id = up.stdout.strip()

        down = self.run_porter(
            "down",
            "--runs-dir",
            str(runs_dir),
            "--preserve",
            run_id,
        )

        self.assertEqual(down.returncode, 0, down.stderr)
        record = self.load_record(runs_dir, run_id)

        self.assertFalse(marker.exists())
        self.assertTrue(record["preserved"])
        self.assertFalse(record["lifecycle"]["down"]["invoked"])
        self.assertTrue(record["lifecycle"]["down"]["preserve"])

    def test_pulled_artifact_hash_matches_sha256sums(self) -> None:
        runs_dir = self.tmp_path / "runs"
        remote_root = self.tmp_path / "remote"

        result = self.run_porter(
            "run",
            "--runs-dir",
            str(runs_dir),
            "--target",
            "ssh:fake",
            "--remote-root",
            str(remote_root),
            "--pull",
            "out.txt",
            "--",
            "sh",
            "-c",
            "printf data > out.txt",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        run_id = result.stdout.strip()
        run_base = runs_dir / run_id
        record = self.load_record(runs_dir, run_id)
        artifact = record["artifacts"][0]
        exec_step = next(step for step in record["steps"] if step["kind"] == "exec")
        pull_step = next(step for step in record["steps"] if step["kind"] == "pull")
        expected = hashlib.sha256(b"data").hexdigest()

        with (run_base / "export" / "aggregate.json").open("r", encoding="utf-8") as f:
            aggregate = json.load(f)

        self.assertEqual(record["schema"], records.RECORD_SCHEMA)
        self.assertEqual(aggregate["schema"], records.RECORD_SCHEMA)
        self.assertEqual(record["outcome"], "completed")
        self.assertEqual(exec_step["class"], records.CUSTODY_RECEIPT)
        self.assertEqual(pull_step["class"], records.CUSTODY_RECEIPT)
        self.assertEqual(artifact["class"], records.CUSTODY_BLOB)
        self.assertEqual(artifact["sha256"], expected)
        self.assertEqual((run_base / artifact["local_path"]).read_bytes(), b"data")
        self.assertIn(f"{expected}  {artifact['local_path']}", (run_base / "SHA256SUMS").read_text())

        self.assertEqual(aggregate["export_policy"]["included_classes"], ["recipe", "receipt"])
        self.assertEqual(aggregate["export_policy"]["excluded_classes"], ["blob"])
        self.assertEqual(aggregate["artifacts"], [])
        self.assertNotIn(records.CUSTODY_BLOB, self.class_values(aggregate))
        self.assertEqual(aggregate["artifact_receipts"][0]["class"], records.CUSTODY_RECEIPT)
        self.assertEqual(aggregate["artifact_receipts"][0]["custody_class"], records.CUSTODY_BLOB)
        self.assertEqual(aggregate["artifact_receipts"][0]["sha256"], expected)
        self.assertEqual(aggregate["artifact_receipts"][0]["local_path"], artifact["local_path"])
        self.assertEqual(aggregate["replay"]["record"], "record.json")
        self.assertEqual(aggregate["replay"]["checksums"], "SHA256SUMS")
        self.assertTrue(aggregate["declared_command"]["scrubbed"])
        self.assertNotIn("declared", aggregate["steps"][0])

    def test_library_run_returns_final_record(self) -> None:
        runs_dir = self.tmp_path / "api-runs"
        remote_root = self.tmp_path / "api-remote"
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{self.fakebin}{os.pathsep}{old_path}"
        try:
            record = porter.run(
                target="ssh:fake",
                command=["sh", "-c", "printf api > out.txt"],
                pulls=["out.txt"],
                runs_dir=runs_dir,
                remote_root=str(remote_root),
            )
        finally:
            os.environ["PATH"] = old_path

        run_base = runs_dir / record["run_id"]
        artifact = record["artifacts"][0]

        self.assertIs(type(record), dict)
        self.assertEqual(record["schema"], records.RECORD_SCHEMA)
        self.assertEqual(record["outcome"], records.OUTCOME_COMPLETED)
        self.assertEqual(record["declared_command"], ["sh", "-c", "printf api > out.txt"])
        self.assertEqual(artifact["class"], records.CUSTODY_BLOB)
        self.assertEqual((run_base / artifact["local_path"]).read_bytes(), b"api")
        self.assertTrue((run_base / "export" / "aggregate.json").exists())
        self.assertTrue((run_base / "SHA256SUMS").exists())

    # ── Task A: env injection ──────────────────────────────────────────────

    def _init_git_repo(self, src: Path, filename: str, content: str) -> None:
        """Create a minimal git repo at src with one committed file."""
        src.mkdir(parents=True, exist_ok=True)
        (src / filename).write_text(content, encoding="utf-8")
        for cmd in [
            ["git", "init", str(src)],
            ["git", "-C", str(src), "config", "user.email", "porter-test@test.local"],
            ["git", "-C", str(src), "config", "user.name", "Porter Test"],
            ["git", "-C", str(src), "config", "commit.gpgsign", "false"],
            ["git", "-C", str(src), "add", filename],
            ["git", "-C", str(src), "commit", "-m", "initial commit"],
        ]:
            subprocess.run(cmd, check=True, capture_output=True)

    def test_env_reaches_remote_command(self) -> None:
        """env var set via --env reaches the remote command and appears in transcript."""
        runs_dir = self.tmp_path / "env-runs"
        remote_root = self.tmp_path / "env-remote"

        result = self.run_porter(
            "run",
            "--runs-dir", str(runs_dir),
            "--target", "ssh:fake",
            "--remote-root", str(remote_root),
            "--env", "PORTER_TEST_GREETING=hello-from-env",
            "--",
            "sh", "-c", "echo $PORTER_TEST_GREETING",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        run_id = result.stdout.strip()
        record = self.load_record(runs_dir, run_id)
        exec_step = next(step for step in record["steps"] if step["kind"] == "exec")
        transcript = (runs_dir / run_id / exec_step["transcript"]).read_text(encoding="utf-8")

        self.assertEqual(record["outcome"], records.OUTCOME_COMPLETED)
        self.assertIn("hello-from-env", transcript)
        self.assertEqual(exec_step.get("env_keys"), ["PORTER_TEST_GREETING"])

    def test_env_key_recorded_value_never_in_record_or_transcript(self) -> None:
        """env keys appear in step metadata; raw values appear nowhere in record or transcripts."""
        runs_dir = self.tmp_path / "env-custody-runs"
        remote_root = self.tmp_path / "env-custody-remote"
        # Unique sentinel that must not leak into any porter-written file.
        secret = "xportersecret-custody-z"

        result = self.run_porter(
            "run",
            "--runs-dir", str(runs_dir),
            "--target", "ssh:fake",
            "--remote-root", str(remote_root),
            "--env", f"PORTER_CUSTODY_KEY={secret}",
            "--",
            "sh", "-c", '[ -n "$PORTER_CUSTODY_KEY" ] && echo env-present || echo env-absent',
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        run_id = result.stdout.strip()
        run_base = runs_dir / run_id
        record = self.load_record(runs_dir, run_id)
        exec_step = next(step for step in record["steps"] if step["kind"] == "exec")

        # Step records the key, not the value.
        self.assertEqual(exec_step.get("env_keys"), ["PORTER_CUSTODY_KEY"])

        # Value must not appear in record.json.
        record_text = (run_base / "record.json").read_text(encoding="utf-8")
        self.assertNotIn(secret, record_text, "env value leaked into record.json")

        # Value must not appear in any transcript file.
        for transcript_path in sorted((run_base / "transcripts").iterdir()):
            text = transcript_path.read_text(encoding="utf-8", errors="replace")
            self.assertNotIn(secret, text, f"env value leaked into {transcript_path.name}")

        # Command confirmed env var was accessible (without echoing the value).
        exec_transcript = (run_base / exec_step["transcript"]).read_text(encoding="utf-8")
        self.assertIn("env-present", exec_transcript)

    # ── Task B: dirty-worktree honesty at push ─────────────────────────────

    def test_dirty_worktree_push_records_annotation(self) -> None:
        """Push of a dirty git worktree → push step carries dirty_worktree: True."""
        src = self.tmp_path / "dirty-src"
        self._init_git_repo(src, "tracked.txt", "committed\n")
        # Make worktree dirty by adding an untracked file.
        (src / "untracked.txt").write_text("new and untracked\n", encoding="utf-8")

        runs_dir = self.tmp_path / "dirty-runs"
        remote_root = self.tmp_path / "dirty-remote"
        result = self.run_porter(
            "run",
            "--runs-dir", str(runs_dir),
            "--target", "ssh:fake",
            "--remote-root", str(remote_root),
            "--push", str(src),
            "--",
            "sh", "-c", "echo ok",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        run_id = result.stdout.strip()
        record = self.load_record(runs_dir, run_id)
        push_step = next(step for step in record["steps"] if step["kind"] == "push")
        self.assertTrue(
            push_step.get("dirty_worktree"),
            f"expected dirty_worktree annotation in push step; got: {push_step}",
        )

    def test_clean_worktree_push_no_dirty_annotation(self) -> None:
        """Push of a clean git worktree → dirty_worktree annotation absent from push step."""
        src = self.tmp_path / "clean-src"
        self._init_git_repo(src, "tracked.txt", "committed\n")
        # No modifications — worktree is clean.

        runs_dir = self.tmp_path / "clean-runs"
        remote_root = self.tmp_path / "clean-remote"
        result = self.run_porter(
            "run",
            "--runs-dir", str(runs_dir),
            "--target", "ssh:fake",
            "--remote-root", str(remote_root),
            "--push", str(src),
            "--",
            "sh", "-c", "echo ok",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        run_id = result.stdout.strip()
        record = self.load_record(runs_dir, run_id)
        push_step = next(step for step in record["steps"] if step["kind"] == "push")
        self.assertFalse(
            push_step.get("dirty_worktree"),
            f"expected no dirty_worktree annotation on clean push; got: {push_step}",
        )

    def test_nested_untracked_directory_raw_git_archive_fixture_is_zero_member(self) -> None:
        repo = self.tmp_path / "nested-raw-repo"
        self._init_git_repo(repo, "tracked.txt", "committed\n")
        nested = repo / "nested" / "porter-input" / "inbox" / "attempt-a"
        nested.mkdir(parents=True)
        (nested / "request.json").write_text('{"attempt":"a"}\n', encoding="utf-8")
        proc = subprocess.run(
            ["git", "-C", str(nested), "archive", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(len(proc.stdout), 10240)
        listing = subprocess.run(["tar", "-tf", "-"], input=proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(listing.returncode, 0, listing.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(listing.stdout, b"")

    def test_nested_untracked_directory_push_uses_exact_tar_and_verifies_request(self) -> None:
        repo = self.tmp_path / "nested-repo"
        self._init_git_repo(repo, "tracked.txt", "committed\n")
        package = repo / "nested" / "porter-input"
        inbox = package / "inbox" / "attempt-a"
        inbox.mkdir(parents=True)
        (inbox / "predecessor.bundle").write_bytes(b"bundle-bytes\n")
        (inbox / "prompt.txt").write_text("prompt\n", encoding="utf-8")
        request_bytes = b'{"attempt":"a"}\n'
        (inbox / "request.json").write_bytes(request_bytes)

        runs_dir = self.tmp_path / "nested-runs"
        remote_root = self.tmp_path / "nested-remote"
        result = self.run_porter(
            "run",
            "--runs-dir", str(runs_dir),
            "--target", "ssh:fake",
            "--remote-root", str(remote_root),
            "--push", str(package),
            "--pull", "inbox/attempt-a/request.json",
            "--",
            "sh", "-c", "test -f inbox/attempt-a/request.json && echo ok",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        run_id = result.stdout.strip()
        run_base = runs_dir / run_id
        record = self.load_record(runs_dir, run_id)
        push_step = next(step for step in record["steps"] if step["kind"] == "push")
        admission = push_step["transfer_admission"]
        self.assertEqual(admission["status"], "verified")
        self.assertEqual(admission["archive_member_count"], 3)
        self.assertEqual(admission["remote_member_count"], 3)
        artifact = next(item for item in record["artifacts"] if item["remote_path"] == "inbox/attempt-a/request.json")
        self.assertEqual((run_base / artifact["local_path"]).read_bytes(), request_bytes)

    def test_push_remote_reread_failure_refuses_false_exit_zero(self) -> None:
        src = self.tmp_path / "reread-src"
        src.mkdir()
        (src / "hello.txt").write_text("hello\n", encoding="utf-8")
        runs_dir = self.tmp_path / "reread-runs"
        remote_root = self.tmp_path / "reread-remote"
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{self.fakebin}{os.pathsep}{old_path}"
        try:
            run_id, _ = runner.up("ssh:fake", runs_dir, str(remote_root))
            with mock.patch.object(sshlib.SSHTransport, "run_script", return_value=sshlib.CommandResult(97, b"MISSING\thello.txt\n", b"")):
                record = runner.push(run_id, runs_dir, src)
        finally:
            os.environ["PATH"] = old_path
        push_step = next(step for step in record["steps"] if step["kind"] == "push")
        self.assertEqual(record["outcome"], records.OUTCOME_PORTER_FAILED)
        self.assertEqual(push_step["transport_exit_code"], 0)
        self.assertEqual(push_step["verification_exit_code"], 97)
        self.assertEqual(push_step["transfer_admission"]["status"], "pending")

    def test_interrupted_push_transfer_is_fail_closed(self) -> None:
        src = self.tmp_path / "interrupted-src"
        src.mkdir()
        (src / "hello.txt").write_text("hello\n", encoding="utf-8")
        runs_dir = self.tmp_path / "interrupted-runs"
        remote_root = self.tmp_path / "interrupted-remote"
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{self.fakebin}{os.pathsep}{old_path}"
        try:
            run_id, _ = runner.up("ssh:fake", runs_dir, str(remote_root))
            with mock.patch.object(sshlib.SSHTransport, "push_tar_stream", return_value=sshlib.CommandResult(255, b"", b"interrupted\n")):
                record = runner.push(run_id, runs_dir, src)
        finally:
            os.environ["PATH"] = old_path
        push_step = next(step for step in record["steps"] if step["kind"] == "push")
        self.assertEqual(record["outcome"], records.OUTCOME_PORTER_FAILED)
        self.assertEqual(push_step["transport_exit_code"], 255)
        self.assertIsNone(push_step["verification_exit_code"])

    def test_duplicate_identical_push_is_idempotent(self) -> None:
        src = self.tmp_path / "repeat-src"
        src.mkdir()
        (src / "hello.txt").write_text("hello\n", encoding="utf-8")
        runs_dir = self.tmp_path / "repeat-runs"
        remote_root = self.tmp_path / "repeat-remote"
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{self.fakebin}{os.pathsep}{old_path}"
        try:
            run_id, _ = runner.up("ssh:fake", runs_dir, str(remote_root))
            first = runner.push(run_id, runs_dir, src)
            second = runner.push(run_id, runs_dir, src)
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(first["run_id"], second["run_id"])
        push_steps = [step for step in second["steps"] if step["kind"] == "push"]
        self.assertEqual(len(push_steps), 2)
        self.assertTrue(all(step["transfer_admission"]["status"] == "verified" for step in push_steps))
        self.assertEqual((remote_root / "work" / "hello.txt").read_text(encoding="utf-8"), "hello\n")

    def test_worktree_flag_delivers_dirty_bytes(self) -> None:
        """--worktree pushes the working tree (including uncommitted edits), not git archive HEAD."""
        src = self.tmp_path / "worktree-src"
        self._init_git_repo(src, "hello.txt", "committed-content\n")
        # Modify hello.txt without committing — git archive HEAD would give the old content.
        (src / "hello.txt").write_text("dirty-content\n", encoding="utf-8")

        runs_dir = self.tmp_path / "worktree-runs"
        remote_root = self.tmp_path / "worktree-remote"
        result = self.run_porter(
            "run",
            "--runs-dir", str(runs_dir),
            "--target", "ssh:fake",
            "--remote-root", str(remote_root),
            "--push", str(src),
            "--pull", "hello.txt",
            "--worktree",
            "--",
            "sh", "-c", "echo ok",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        run_id = result.stdout.strip()
        run_base = runs_dir / run_id
        record = self.load_record(runs_dir, run_id)
        artifact = record["artifacts"][0]
        content = (run_base / artifact["local_path"]).read_text(encoding="utf-8")
        self.assertEqual(
            content, "dirty-content\n",
            "expected dirty working-tree bytes to be delivered, not git archive HEAD",
        )


if __name__ == "__main__":
    unittest.main()

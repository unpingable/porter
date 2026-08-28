from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from porterlib import record as records
from porterlib import runner


def reservation(character: str) -> str:
    return "sha256:" + character * 64


def record_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_exact_reservation_replay_and_conflict() -> None:
    record = records.new_record("P", "ssh:worker", "worker", "/work")
    records.bind_reservation(record, reservation("a"))
    exact = records.dumps_record(record)
    records.bind_reservation(record, reservation("a"))
    assert records.dumps_record(record) == exact
    with pytest.raises(records.RecordContractError, match="already bound"):
        records.bind_reservation(record, reservation("b"))


@pytest.mark.parametrize(
    "value",
    ["", "sha256:abc", "a" * 64, "sha256:" + "G" * 64],
)
def test_malformed_reservation_refuses(value: str) -> None:
    record = records.new_record("P", "ssh:worker", "worker", "/work")
    with pytest.raises(records.RecordContractError, match="lowercase sha256"):
        records.bind_reservation(record, value)


def test_v1_record_hash_binds_run_and_reservation(tmp_path: Path) -> None:
    first = records.new_record("P-one", "ssh:worker", "worker", "/work")
    records.bind_reservation(first, reservation("a"))
    first_dir = tmp_path / "first"
    records.save_record(first_dir, first)

    changed_run = records.new_record("P-two", "ssh:worker", "worker", "/work")
    records.bind_reservation(changed_run, reservation("a"))
    changed_run_dir = tmp_path / "changed-run"
    records.save_record(changed_run_dir, changed_run)

    changed_reservation = records.new_record("P-one", "ssh:worker", "worker", "/work")
    records.bind_reservation(changed_reservation, reservation("b"))
    changed_reservation_dir = tmp_path / "changed-reservation"
    records.save_record(changed_reservation_dir, changed_reservation)

    hashes = {
        record_hash(records.record_path(first_dir)),
        record_hash(records.record_path(changed_run_dir)),
        record_hash(records.record_path(changed_reservation_dir)),
    }
    assert len(hashes) == 3


def test_porter_persists_p_r_before_endpoint_activity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, str] = {}

    def inspect_before_transport(_transport: object, _script: str) -> SimpleNamespace:
        record_paths = list(tmp_path.glob("*/record.json"))
        assert len(record_paths) == 1
        retained = records.load_record(record_paths[0].parent)
        observed["run_id"] = retained["run_id"]
        observed["reservation"] = retained["evidence_reservation"]
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"fixture refusal")

    monkeypatch.setattr(runner.SSHTransport, "run_script", inspect_before_transport)
    run_id, retained = runner.up(
        "ssh:worker",
        tmp_path,
        evidence_reservation=reservation("c"),
    )
    assert observed == {"run_id": run_id, "reservation": reservation("c")}
    assert retained["schema"] == records.RECORD_SCHEMA_V1
    assert run_id != reservation("c")


def test_v0_remains_unchanged_and_v1_coordinate_is_scalar() -> None:
    legacy = records.new_record("P", "ssh:worker", "worker", "/work")
    assert legacy["schema"] == records.RECORD_SCHEMA_V0
    records.validate_record_contract(legacy)

    invalid = dict(legacy)
    invalid["schema"] = records.RECORD_SCHEMA_V1
    invalid["evidence_reservation"] = [reservation("a"), reservation("b")]
    with pytest.raises(records.RecordContractError, match="malformed"):
        records.validate_record_contract(invalid)

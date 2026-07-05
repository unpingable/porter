from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__


OUTCOME_COMPLETED = "completed"
OUTCOME_RUN_FAILED = "run_failed"
OUTCOME_PORTER_FAILED = "porter_failed"
OUTCOME_REFUSED = "refused"

RECORD_SCHEMA = "porter.record.v0"

TERMINAL_OUTCOMES = {
    OUTCOME_COMPLETED,
    OUTCOME_RUN_FAILED,
    OUTCOME_PORTER_FAILED,
    OUTCOME_REFUSED,
}

REQUIRED_RECORD_V0_FIELDS = frozenset(
    {
        "schema",
        "porter_version",
        "run_id",
        "target",
        "substrate",
        "declared_command",
        "steps",
        "artifacts",
        "outcome",
        "refusal_reason",
        "preserved",
        "notes",
    }
)

DOMAIN_VERDICT_FIELDS = frozenset({"success", "passed", "supported", "admissible"})

CUSTODY_RECIPE = "recipe"
CUSTODY_RECEIPT = "receipt"
CUSTODY_BLOB = "blob"
CUSTODY_CLASSES = frozenset({CUSTODY_RECIPE, CUSTODY_RECEIPT, CUSTODY_BLOB})


class RecordContractError(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    return f"{stamp}-{secrets.token_hex(3)}"


def run_dir(runs_dir: Path, run_id: str) -> Path:
    return runs_dir / run_id


def record_path(base: Path) -> Path:
    return base / "record.json"


def ensure_layout(base: Path) -> None:
    (base / "transcripts").mkdir(parents=True, exist_ok=True)
    (base / "artifacts").mkdir(parents=True, exist_ok=True)
    (base / "recipes").mkdir(parents=True, exist_ok=True)
    (base / "export").mkdir(parents=True, exist_ok=True)


def new_record(run_id: str, target: str, host: str, remote_root: str) -> dict[str, Any]:
    return {
        "schema": RECORD_SCHEMA,
        "porter_version": __version__,
        "run_id": run_id,
        "target": target,
        "substrate": {
            "kind": "ssh",
            "transport": "ssh",
            "ephemeral": False,
            "declared": {
                "host": host,
                "remote_root": remote_root,
                "workdir": f"{remote_root}/work",
            },
            "observed": {},
            "fact_mismatches": [],
        },
        "declared_command": [],
        "steps": [],
        "artifacts": [],
        "outcome": None,
        "refusal_reason": None,
        "preserved": True,
        "notes": "ssh target was not provisioned by Porter",
    }


def new_serial_record(run_id: str, target: str, socket_path: str) -> dict[str, Any]:
    return {
        "schema": RECORD_SCHEMA,
        "porter_version": __version__,
        "run_id": run_id,
        "target": target,
        "substrate": {
            "kind": "vm",
            "transport": "serial-socket",
            "ephemeral": False,
            "declared": {"socket_path": socket_path},
            "observed": {},
            "fact_mismatches": [],
        },
        "declared_command": [],
        "steps": [],
        "artifacts": [],
        "outcome": None,
        "refusal_reason": None,
        "preserved": True,
        "notes": "serial target was not provisioned by Porter",
    }


def new_recipe_record(run_id: str, target: str, recipe_source: str) -> dict[str, Any]:
    return {
        "schema": RECORD_SCHEMA,
        "porter_version": __version__,
        "run_id": run_id,
        "target": target,
        "substrate": {
            "kind": "recipe",
            "transport": "recipe",
            "ephemeral": True,
            "declared": {"recipe": recipe_source},
            "observed": {},
            "fact_mismatches": [],
        },
        "declared_command": [],
        "steps": [],
        "artifacts": [],
        "recipes": [],
        "lifecycle": {"recipe": {"source_path": recipe_source}, "down": {"invoked": False}},
        "outcome": None,
        "refusal_reason": None,
        "preserved": False,
        "notes": "recipe target lifecycle is caller-provided",
    }


def ensure_record_schema(record: dict[str, Any]) -> None:
    schema = record.get("schema")
    if schema is None:
        record["schema"] = RECORD_SCHEMA
        return
    if schema != RECORD_SCHEMA:
        raise RecordContractError(f"unsupported record schema: {schema!r}")


def _domain_field_paths(value: Any, path: tuple[str, ...] = ()) -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            next_path = (*path, str(key))
            if key in DOMAIN_VERDICT_FIELDS:
                paths.append(".".join(next_path))
            paths.extend(_domain_field_paths(child, next_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(_domain_field_paths(child, (*path, f"[{index}]")))
    return paths


def assert_no_domain_fields(record: dict[str, Any]) -> None:
    paths = sorted(set(_domain_field_paths(record)))
    if paths:
        joined = ", ".join(paths)
        raise RecordContractError(f"record contains domain verdict field(s): {joined}")


def validate_record_contract(record: dict[str, Any]) -> None:
    if not isinstance(record, dict):
        raise RecordContractError("record must be a JSON object")

    ensure_record_schema(record)
    assert_no_domain_fields(record)

    missing = sorted(REQUIRED_RECORD_V0_FIELDS - set(record))
    if missing:
        raise RecordContractError(f"record is missing required v0 field(s): {', '.join(missing)}")

    outcome = record.get("outcome")
    if outcome is not None and outcome not in TERMINAL_OUTCOMES:
        raise RecordContractError(f"unsupported record outcome: {outcome!r}")

    if not isinstance(record.get("substrate"), dict):
        raise RecordContractError("record substrate must be an object")
    if not isinstance(record.get("declared_command"), list):
        raise RecordContractError("record declared_command must be a list")
    if not isinstance(record.get("steps"), list):
        raise RecordContractError("record steps must be a list")
    if not isinstance(record.get("artifacts"), list):
        raise RecordContractError("record artifacts must be a list")
    if "recipes" in record and not isinstance(record.get("recipes"), list):
        raise RecordContractError("record recipes must be a list")

    for index, step in enumerate(record.get("steps", [])):
        if not isinstance(step, dict):
            raise RecordContractError(f"record step {index} must be an object")
        if "class" in step and step["class"] not in CUSTODY_CLASSES:
            raise RecordContractError(f"record step {index} has unsupported custody class")
        if "exit_code_observed" not in step:
            raise RecordContractError(f"record step {index} is missing exit_code_observed")
        observed = step.get("exit_code_observed")
        if observed is not True and observed is not False:
            raise RecordContractError(f"record step {index} has non-boolean exit_code_observed")
        if observed is False and "exit_code" in step:
            raise RecordContractError(f"record step {index} has an exit_code that was not observed")
        if "exit_code" in step and type(step["exit_code"]) is not int:
            raise RecordContractError(f"record step {index} exit_code must be an integer")

    for collection_name, default_class in (("artifacts", CUSTODY_BLOB), ("recipes", CUSTODY_RECIPE)):
        for index, item in enumerate(record.get(collection_name, [])):
            if not isinstance(item, dict):
                raise RecordContractError(f"record {collection_name[:-1]} {index} must be an object")
            custody_class = item.get("class", default_class)
            if custody_class not in CUSTODY_CLASSES:
                raise RecordContractError(
                    f"record {collection_name[:-1]} {index} has unsupported custody class"
                )


def dumps_record(record: dict[str, Any]) -> str:
    validate_record_contract(record)
    return json.dumps(record, indent=2, sort_keys=True) + "\n"


def load_record(base: Path) -> dict[str, Any]:
    with record_path(base).open("r", encoding="utf-8") as f:
        record = json.load(f)
    validate_record_contract(record)
    return record


def save_record(base: Path, record: dict[str, Any]) -> None:
    ensure_layout(base)
    tmp = record_path(base).with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        f.write(dumps_record(record))
    tmp.replace(record_path(base))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def file_size(path: Path) -> int:
    return path.stat().st_size


def next_seq(record: dict[str, Any]) -> int:
    return len(record.get("steps", [])) + 1


def transcript_rel(seq: int, kind: str) -> str:
    return f"transcripts/{seq:04d}-{kind}.log"


def add_step(
    record: dict[str, Any],
    *,
    kind: str,
    declared: str,
    started_at: str,
    ended_at: str,
    transcript: str | None = None,
    exit_code: int | None = None,
    exit_code_observed: bool = True,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if exit_code is not None and exit_code_observed is False:
        raise RecordContractError("unobserved exit code must not be recorded")
    step: dict[str, Any] = {
        "class": CUSTODY_RECEIPT,
        "seq": next_seq(record),
        "kind": kind,
        "declared": declared,
        "exit_code_observed": exit_code_observed,
        "started_at": started_at,
        "ended_at": ended_at,
    }
    if exit_code is not None:
        step["exit_code"] = exit_code
    if transcript is not None:
        step["transcript"] = transcript
    if extra:
        step.update(extra)
    record.setdefault("steps", []).append(step)
    return step


def mark_refused(record: dict[str, Any], reason: str) -> None:
    record["outcome"] = OUTCOME_REFUSED
    record["refusal_reason"] = reason


def mark_porter_failed(record: dict[str, Any], reason: str) -> None:
    record["outcome"] = OUTCOME_PORTER_FAILED
    record["refusal_reason"] = reason


def payload_exit_code(record: dict[str, Any]) -> int | None:
    for step in reversed(record.get("steps", [])):
        if step.get("kind") == "exec" and step.get("exit_code_observed") is True:
            value = step.get("exit_code")
            return int(value) if value is not None else None
    return None


def decide_outcome(record: dict[str, Any]) -> None:
    if record.get("outcome") in {OUTCOME_REFUSED, OUTCOME_PORTER_FAILED}:
        return

    exec_steps = [s for s in record.get("steps", []) if s.get("kind") == "exec"]
    for step in exec_steps:
        if step.get("exit_code_observed") is not True:
            mark_refused(record, "command exit code was not observed")
            return
        if "exit_code" not in step:
            mark_refused(record, "command exit code was not recorded")
            return

    if not exec_steps:
        record["outcome"] = OUTCOME_COMPLETED
        record["refusal_reason"] = None
        return

    rc = payload_exit_code(record)
    if rc == 0:
        record["outcome"] = OUTCOME_COMPLETED
    else:
        record["outcome"] = OUTCOME_RUN_FAILED
    record["refusal_reason"] = None


def update_hashes(base: Path, record: dict[str, Any]) -> None:
    for step in record.get("steps", []):
        step.setdefault("class", CUSTODY_RECEIPT)
        rel = step.get("transcript")
        if rel:
            path = base / rel
            if path.exists():
                step["transcript_sha256"] = sha256_file(path)

    for artifact in record.get("artifacts", []):
        artifact.setdefault("class", CUSTODY_BLOB)
        rel = artifact.get("local_path")
        if rel:
            path = base / rel
            if path.exists():
                artifact["sha256"] = sha256_file(path)
                artifact["size"] = file_size(path)

    for recipe in record.get("recipes", []):
        recipe.setdefault("class", CUSTODY_RECIPE)
        rel = recipe.get("local_path")
        if rel:
            path = base / rel
            if path.exists():
                recipe["sha256"] = sha256_file(path)
                recipe["size"] = file_size(path)


def _json_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _target_summary(target: Any) -> dict[str, Any]:
    text = target if isinstance(target, str) else ""
    scheme = text.split(":", 1)[0] if ":" in text else text
    return {"class": CUSTODY_RECEIPT, "scheme": scheme, "scrubbed": True}


def _substrate_summary(substrate: Any) -> dict[str, Any]:
    if not isinstance(substrate, dict):
        return {"class": CUSTODY_RECEIPT, "scrubbed": True}

    declared = substrate.get("declared", {})
    observed = substrate.get("observed", {})
    mismatches = substrate.get("fact_mismatches", [])
    return {
        "class": CUSTODY_RECEIPT,
        "kind": substrate.get("kind"),
        "transport": substrate.get("transport"),
        "ephemeral": substrate.get("ephemeral"),
        "declared_keys": sorted(declared) if isinstance(declared, dict) else [],
        "observed_keys": sorted(observed) if isinstance(observed, dict) else [],
        "fact_mismatch_count": len(mismatches) if isinstance(mismatches, list) else None,
        "scrubbed": True,
    }


def _command_summary(command: Any) -> dict[str, Any]:
    argv = command if isinstance(command, list) else []
    return {
        "class": CUSTODY_RECEIPT,
        "argc": len(argv),
        "argv_sha256": _json_sha256(argv),
        "scrubbed": True,
    }


def _step_receipt(step: dict[str, Any]) -> dict[str, Any]:
    keep: dict[str, Any] = {
        "class": CUSTODY_RECEIPT,
        "seq": step.get("seq"),
        "kind": step.get("kind"),
        "exit_code_observed": step.get("exit_code_observed"),
        "started_at": step.get("started_at"),
        "ended_at": step.get("ended_at"),
    }
    declared = step.get("declared")
    if declared is not None:
        declared_text = str(declared)
        keep["declared_sha256"] = hashlib.sha256(declared_text.encode("utf-8")).hexdigest()
        keep["declared_length"] = len(declared_text)
        keep["declared_scrubbed"] = True
    if "exit_code" in step:
        keep["exit_code"] = step["exit_code"]
    if "transcript" in step:
        keep["transcript"] = step["transcript"]
    if "transcript_sha256" in step:
        keep["transcript_sha256"] = step["transcript_sha256"]
    return keep


def _scrub_recipe(recipe: dict[str, Any]) -> dict[str, Any]:
    keep: dict[str, Any] = {"class": CUSTODY_RECIPE}
    for key in ("local_path", "sha256", "size"):
        if key in recipe:
            keep[key] = recipe[key]
    return keep


def _artifact_export(artifact: dict[str, Any]) -> dict[str, Any]:
    custody_class = artifact.get("class", CUSTODY_BLOB)
    keep: dict[str, Any] = {"class": custody_class}
    for key in ("local_path", "sha256", "size"):
        if key in artifact:
            keep[key] = artifact[key]
    return keep


def _artifact_receipt(artifact: dict[str, Any]) -> dict[str, Any]:
    keep: dict[str, Any] = {
        "class": CUSTODY_RECEIPT,
        "custody_class": artifact.get("class", CUSTODY_BLOB),
    }
    for key in ("local_path", "remote_path", "sha256", "size"):
        if key in artifact:
            keep[key] = artifact[key]
    return keep


def _lifecycle_receipt(lifecycle: Any) -> dict[str, Any]:
    if not isinstance(lifecycle, dict):
        return {}
    keep: dict[str, Any] = {"class": CUSTODY_RECEIPT}
    recipe = lifecycle.get("recipe")
    if isinstance(recipe, dict):
        keep["recipe"] = _scrub_recipe(recipe)
    down = lifecycle.get("down")
    if isinstance(down, dict):
        keep["down"] = {
            key: down[key]
            for key in ("invoked", "preserve", "transcript", "exit_code")
            if key in down
        }
    return keep


def _replay_instructions(run_id: Any) -> dict[str, Any]:
    run_text = str(run_id or "<run_id>")
    return {
        "class": CUSTODY_RECEIPT,
        "record": "record.json",
        "checksums": "SHA256SUMS",
        "local_custody": {
            "transcripts": "transcripts/",
            "artifacts": "artifacts/",
        },
        "commands": [
            {"cwd": f"runs/{run_text}", "argv": ["sha256sum", "-c", "SHA256SUMS"]},
            {"cwd": ".", "argv": ["./porter", "show", run_text]},
        ],
    }


def aggregate(record: dict[str, Any]) -> dict[str, Any]:
    steps = [_step_receipt(step) for step in record.get("steps", [])]

    artifact_receipts = []
    exported_artifacts = []
    for artifact in record.get("artifacts", []):
        custody_class = artifact.get("class", CUSTODY_BLOB)
        if custody_class == CUSTODY_BLOB:
            artifact_receipts.append(_artifact_receipt(artifact))
        else:
            exported_artifacts.append(_artifact_export(artifact))

    payload = {
        "schema": record.get("schema", RECORD_SCHEMA),
        "porter_version": record.get("porter_version"),
        "run_id": record.get("run_id"),
        "export_policy": {
            "included_classes": [CUSTODY_RECIPE, CUSTODY_RECEIPT],
            "excluded_classes": [CUSTODY_BLOB],
        },
        "target": _target_summary(record.get("target")),
        "substrate": _substrate_summary(record.get("substrate")),
        "declared_command": _command_summary(record.get("declared_command")),
        "steps": steps,
        "artifacts": exported_artifacts,
        "artifact_receipts": artifact_receipts,
        "outcome": record.get("outcome"),
        "refusal_reason": record.get("refusal_reason"),
        "preserved": record.get("preserved"),
        "notes": record.get("notes", ""),
        "replay": _replay_instructions(record.get("run_id")),
    }
    if "recipes" in record:
        payload["recipes"] = [_scrub_recipe(recipe) for recipe in record.get("recipes", [])]
    if "lifecycle" in record:
        payload["lifecycle"] = _lifecycle_receipt(record.get("lifecycle", {}))
    return payload


def write_aggregate(base: Path, record: dict[str, Any]) -> None:
    validate_record_contract(record)
    payload = aggregate(record)
    assert_no_domain_fields(payload)
    export = base / "export" / "aggregate.json"
    with export.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")


def iter_checksum_files(base: Path) -> list[Path]:
    files: list[Path] = []
    for root, _dirs, names in os.walk(base):
        root_path = Path(root)
        for name in names:
            path = root_path / name
            if path == base / "SHA256SUMS":
                continue
            files.append(path)
    return sorted(files, key=lambda p: p.relative_to(base).as_posix())


def write_sha256sums(base: Path) -> None:
    lines = []
    for path in iter_checksum_files(base):
        rel = path.relative_to(base).as_posix()
        lines.append(f"{sha256_file(path)}  {rel}\n")
    with (base / "SHA256SUMS").open("w", encoding="utf-8") as f:
        f.writelines(lines)


def seal_run(base: Path) -> dict[str, Any]:
    record = load_record(base)
    update_hashes(base, record)
    decide_outcome(record)
    save_record(base, record)
    write_aggregate(base, record)
    write_sha256sums(base)
    return record

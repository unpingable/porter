from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from . import record as records


def parse_recipe_target(target: str) -> Path:
    if not target.startswith("recipe:"):
        raise ValueError(f"unsupported target {target!r}; expected recipe:<script-path>")
    raw = target[len("recipe:") :]
    if not raw:
        raise ValueError("recipe target requires a script path")
    return Path(raw).expanduser()


def copy_recipe(source: Path, base: Path) -> dict[str, Any]:
    source = source.resolve()
    if not source.is_file():
        raise FileNotFoundError(f"recipe script not found: {source}")
    recipe_dir = base / "recipes"
    recipe_dir.mkdir(parents=True, exist_ok=True)
    name = source.name or "recipe"
    dst = recipe_dir / name
    shutil.copy2(source, dst)
    rel = dst.relative_to(base).as_posix()
    return {
        "class": "recipe",
        "source_path": str(source),
        "local_path": rel,
        "sha256": records.sha256_file(dst),
        "size": records.file_size(dst),
    }


def run_recipe_hook(script: Path, action: str, run_id: str, base: Path) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env["PORTER_RUN_ID"] = run_id
    env["PORTER_RUN_DIR"] = str(base)
    env["PORTER_RECORD"] = str(records.record_path(base))
    return subprocess.run(
        [str(script), action, run_id],
        cwd=base,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def parse_recipe_metadata(stdout: bytes) -> dict[str, Any]:
    try:
        metadata = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"recipe up did not emit JSON metadata: {exc}") from exc
    if not isinstance(metadata, dict):
        raise ValueError("recipe up metadata must be a JSON object")
    return metadata


def _require_str(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"recipe metadata requires non-empty string field {key!r}")
    return value


def _require_bool(mapping: dict[str, Any], key: str) -> bool:
    value = mapping.get(key)
    if type(value) is not bool:
        raise ValueError(f"recipe metadata requires boolean field {key!r}")
    return value


def _object_field(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    value = mapping.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(f"recipe metadata field {key!r} must be an object")
    return dict(value)


def normalize_recipe_substrate(metadata: dict[str, Any], run_id: str) -> dict[str, Any]:
    kind = _require_str(metadata, "kind")
    transport = _require_str(metadata, "transport")
    ephemeral = _require_bool(metadata, "ephemeral")
    declared = _object_field(metadata, "declared")
    declared_facts = _object_field(metadata, "declared_facts")
    observed = _object_field(metadata, "observed")
    # Caller-supplied fact_mismatches are UNTRUSTED and never adopted: Porter
    # computes the authoritative list itself from declared_facts vs observed
    # (F1). We validate the type here for a clear error, then discard the value.
    caller_mismatches = metadata.get("fact_mismatches", [])
    if not isinstance(caller_mismatches, list):
        raise ValueError("recipe metadata field 'fact_mismatches' must be a list")

    if transport == "ssh":
        host = declared.get("host", metadata.get("host"))
        if not isinstance(host, str) or not host:
            raise ValueError("ssh recipe metadata requires declared.host")
        remote_root = declared.get("remote_root", metadata.get("remote_root", f"/tmp/porter-{run_id}"))
        if not isinstance(remote_root, str) or not remote_root:
            raise ValueError("ssh recipe metadata requires string declared.remote_root")
        workdir = declared.get("workdir", metadata.get("workdir", f"{remote_root.rstrip('/')}/work"))
        if not isinstance(workdir, str) or not workdir:
            raise ValueError("ssh recipe metadata requires string declared.workdir")
        declared.update({"host": host, "remote_root": remote_root, "workdir": workdir})
    elif transport == "serial-socket":
        socket_path = declared.get("socket_path", metadata.get("socket_path"))
        if not isinstance(socket_path, str) or not socket_path:
            raise ValueError("serial recipe metadata requires declared.socket_path")
        declared.update({"socket_path": socket_path})
    else:
        raise ValueError(f"unsupported recipe transport: {transport!r}")

    return {
        "kind": kind,
        "transport": transport,
        "ephemeral": ephemeral,
        "declared": declared,
        "declared_facts": declared_facts,
        "observed": observed,
        # Placeholder; Porter computes the authoritative list after it probes
        # observed facts (see runner.up_recipe → records.refresh_fact_mismatches).
        "fact_mismatches": [],
    }


def recipe_hook_path(base: Path, record: dict[str, Any]) -> Path | None:
    recipe_info = record.get("lifecycle", {}).get("recipe")
    if not isinstance(recipe_info, dict):
        return None
    local_path = recipe_info.get("local_path")
    if not isinstance(local_path, str) or not local_path:
        return None
    return base / local_path

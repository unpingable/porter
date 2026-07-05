# CLAUDE.md — Instructions for Claude Code

## What This Is

porter: a neutral courier that runs a declared command on a declared ephemeral substrate and
keeps honest receipts (transcript, true exit code, artifacts, hashes). A mule with receipts.

**`DESIGN.md` is authoritative for v0** — charter, CLI, run-record schema, custody layout,
lifecycle, refusal semantics, and the slice roadmap (§8). Read it before changing behavior.
`CANDIDATE.md` is historical design input, not a spec.

## What This Is Not

- Not CI, a verifier, admission control, a governor, or an oracle.
- Not a domain judge — Porter never decides whether artifacts satisfy a caller's contract.
- Not a provisioning framework — provisioning is per-substrate; abstract only what happens
  after you have a shell.

## Invariants

1. Porter testifies that a command ran and produced receipts — nothing about their domain meaning.
2. Unknown exit code → `refused`; never coerced to `0` or `failed`.
3. No domain fields and no caller vocabulary (`NQ_*`, `__NQDONE__`, etc.) in the record or wire.
4. `record.json` is a durable contract (`porter.record.v0`): additive-only until an explicit bump.

## Project Structure

- `porter` — CLI entrypoint (`porterlib.cli:main`).
- `porterlib/` — core: `cli.py`, `record.py`, `runner.py`, `ssh.py`.
- `runs/<run_id>/` — per-run local custody (record, transcripts, artifacts, hashes); gitignored.
- `outputs/` — checked-in evidence specimens (e.g. AG bwrap runs).
- `test_porter.py` — tests.

## Conventions

- License: Apache-2.0.
- Python ≥ 3.10, standard library first; `from __future__ import annotations`.
- Tests: pytest. Run them before proposing commits; never claim green without running.
- Process exit policy: `completed`→0, `run_failed`→0 (unless `--propagate-exit`), `refused`→
  nonzero, `porter_failed`→nonzero. A refusal must never read as process-success.

## Status claims

Long-lived docs rot when they carry too many roles at once. If a doc claims `shipped`, `built`,
`done`, treat it as a claim, not evidence — the claim should name its basis (paths, tests,
commits). Design docs (`DESIGN.md`) explain why/how; tests and run records provide evidence.
Use this repo's local vocabulary; do not port field names or taxonomies wholesale from NQ/AG.

## Don't

- Add a `success`/`passed` field, or make `porter run` propagate the payload exit by default.
- Teach Porter any project's domain contract or command semantics.
- Grow provisioning into a DSL, or leak caller vocabulary into the schema/sentinel.

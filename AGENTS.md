# AGENTS.md — Working in this repo

This file is a **travel guide**, not a law.
If anything here conflicts with the user's explicit instructions, the user wins.

> Instruction files shape behavior; the user determines direction.

**`DESIGN.md` is authoritative for v0** (charter, CLI, run-record schema, custody, lifecycle,
refusal semantics, slice roadmap §8). `CANDIDATE.md` is historical design input. Read `DESIGN.md`
before changing behavior.

---

## Quick start

```bash
./porter run --target ssh:<host> [--push <src>] [--pull <glob>] -- <cmd...>
./porter show <run_id>
python3 -m pytest
```

Always run tests before proposing commits. Never claim tests pass without running them.

---

## Safety and irreversibility

### Do not do these without explicit user confirmation
- Push to remote, create/close PRs or issues
- Delete or rewrite git history
- Change the `porter.record.v0` schema in a non-additive way (removing/repurposing a field)
- Add a domain verdict field, or make Porter own substrate provisioning

### Preferred workflow
- Small, reviewable steps; run tests locally before proposing commits
- For anything that affects external state, require explicit confirmation

---

## Repository layout

```
porter            # CLI entrypoint → porterlib.cli:main
porterlib/        # core, SSH/serial/recipe transports, and thin Python API
runs/<run_id>/    # per-run local custody (gitignored)
docs/specimens/   # checked-in qualification specimens
test_porter.py    # tests
DESIGN.md         # authoritative v0 design (roadmap in §8)
CANDIDATE.md      # historical design input
```

---

## Coding conventions

- Python ≥ 3.10, standard library first; `from __future__ import annotations`.
- pytest for tests.
- Porter-neutral sentinel only (`__PORTER_RC_*`) — never caller vocabulary.

---

## Invariants

1. Porter records that a command ran and produced receipts — never their domain meaning.
2. Unknown exit code → `refused`; never coerced to `0` or `failed`.
3. Process exit policy: `completed`→0, `run_failed`→0 (unless `--propagate-exit`),
   `refused`→nonzero, `porter_failed`→nonzero.

---

## What this is not

- Not CI, a verifier, admission control, a governor, or an oracle.
- Not a domain judge, a portability fixer, or a provisioning DSL.

---

## Roadmap

The historical implementation order lives in `DESIGN.md` §8. Public `main`
already contains the SSH, serial-console, caller-recipe, custody-export, and
thin Python API slices. Treat remaining roadmap items as historical design
context or future proposals, not as a statement that these implemented
surfaces are absent.

---

## Status claims

If a doc claims `shipped`/`built`/`done`, treat it as a claim, not evidence — the claim should
name its basis (paths, tests, commits). Design docs explain why/how; tests and run records are
evidence. Use this repo's local vocabulary; don't port field names or taxonomies from NQ/AG.

---

## When you're unsure

Ask rather than guess, especially around:
- Anything that would put a domain judgment inside Porter
- Anything that changes the `porter.record.v0` schema or a documented invariant
- Whether provisioning belongs in Porter (default: no — prefer caller-provided recipes)

---

## Agent-specific instruction files

| Agent | File | Role |
|-------|------|------|
| Claude Code | `CLAUDE.md` | Full operational context, conventions |
| Codex | `AGENTS.md` (this file) | Operating context + defaults |
| Any future agent | `AGENTS.md` (this file) | Start here |

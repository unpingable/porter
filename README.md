# porter

A neutral courier for ephemeral substrates: it runs a declared command on a declared
temporary substrate (VM, container, or reachable host) and brings back honest receipts —
transcript, true exit code, produced artifacts, and their hashes. A mule with receipts.

## What it does

- Runs a declared command on a declared substrate and captures its **true** exit code.
- Preserves full transcripts and artifacts under local custody, with hashes.
- Writes `export/aggregate.json` as the movable subset: recipe custody plus scrubbed receipts,
  never blob custody.
- Records what ran, where, what came back — as a durable `record.json` with schema `porter.record.v0`.
- **Refuses rather than fabricates**: if it cannot observe the exit code, it says so; it never
  reports a guess.

## What this is not

- Not CI, a verifier, admission control, a governor, or an oracle.
- Not a portability *fixer* and not a domain judge — it does not decide whether the artifacts
  satisfy any caller's contract.
- Not a provisioning framework — provisioning stays per-substrate; Porter abstracts what
  happens *after* you have a shell.

## Invariants

1. Porter records that a declared command ran on a declared substrate and produced declared
   receipts. It does **not** testify that those receipts satisfy any caller's domain.
2. An unknown exit code becomes `refused` — never coerced to `0` or to `failed`.
3. The record schema carries no domain verdict (`success`/`passed`/`supported`/`admissible`)
   and no caller-specific vocabulary.

## Quick start

```bash
./porter run --target ssh:<host> [--push <src>] [--pull <glob>] -- <cmd...>
./porter run --target serial:/path/to/console.sock -- <cmd...>
./porter run --target recipe:./target.sh [--preserve] -- <cmd...>
./porter down [--preserve] <run_id>
./porter show <run_id>
python3 -m pytest        # tests
```

## Python API

```python
from pathlib import Path
import porter

record = porter.run(
    target="ssh:host",
    command=["cargo", "test"],
    push=Path("."),
    pulls=["target/release/foo"],
)
```

The API returns the final `porter.record.v0` dict. It does not return a boolean or decide
whether the receipts satisfy a caller's domain.

## Design

`DESIGN.md` is authoritative for v0 (charter, CLI, run-record schema, custody layout,
lifecycle, refusal semantics, and the slice roadmap in §8). `CANDIDATE.md` is historical
design input — the empirical reuse-vs-bespoke split that motivated the design.

## License

Licensed under Apache-2.0.

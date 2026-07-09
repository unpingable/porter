# porter

A neutral courier for ephemeral substrates: it runs a declared command on a declared
temporary substrate (VM, container, or reachable host) and brings back honest receipts —
transcript, true exit code, produced artifacts, and their hashes. A mule with receipts.

## 30-second specimen

```bash
sh demo/refused-exit.sh
```

Simulates a dropped SSH connection so the exit code is never observed. Expected output
(no VM, no live host, no real network needed):

```
outcome: "refused"
refusal_reason: "command exit code was not observed; ssh exited 255"
exit_code_observed: false
```

Porter exits nonzero. A refusal must never look like process-success, even when the
courier machinery itself ran cleanly.

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

**`--env KEY=VAL`** (repeatable) — injects an environment variable before the command on
the substrate. Keys are recorded in the run record; values are never stored in the record
or transcript (the most likely secret carrier).

**`--worktree`** — pushes the dirty working tree instead of `git archive HEAD`. If the
working tree has uncommitted edits and `--worktree` is not set, the push step records that
fact so the receipt cannot silently imply the dirty edits were tested.

**SSH path caveat** — the `ssh:<host>` transport now has **live-transport** evidence against a
real `sshd` (`completed` + `run_failed`, true exit codes, artifact hashes; see
[`docs/specimens/ssh-localhost.md`](docs/specimens/ssh-localhost.md)), which demotes the
fake-ssh test shim to lab-only coverage. That specimen is **localhost** — real transport, local
host — so it is *not* foreign-substrate testimony: a disposable remote host, and a live refusal
capture, are still wanted before calling the path stranger-run-verified.

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

# Specimen — live SSH transport (localhost, real `sshd`)

**Captured:** 2026-07-09 · **Target:** `ssh:localhost` · **Porter:** working tree (F1+F5 branch)

This is Porter's first **live-transport** evidence for the SSH path: the real `ssh(1)` binary
against a real `sshd`, over a real socket — *not* the `fakebin/ssh` shim the test suite uses.
It closes the standing caveat that the ssh transport had only ever been exercised through a fake.

## What this specimen is — and is not

- **It is** live testimony that Porter's ssh transport works end to end against a real `sshd`:
  push (tar stream), exec with the `__PORTER_RC_*` sentinel capturing the **true** exit code,
  pull (tar stream) with on-arrival hashing, seal, and honest process exit.
- **It is not** foreign-host or foreign-OS evidence. The host is `localhost` — same kernel, same
  arch, no network hop. It demotes the fake-ssh shim to **lab-only** coverage; it does **not**
  discharge the full F7 gap, which wants a *disposable, genuinely remote* host (e.g. a throwaway
  VM or `ssh mac`). Treat this as compatibility evidence for the transport mechanics, not as a
  portability claim about any substrate.

## Custody note

The committed artifacts here are the **scrubbed `export/aggregate.json`** receipts, not the raw
`record.json`. The raw record holds observed host facts (hostname, kernel string) — topology that
stays under local custody per §4 and the F6 lesson. The aggregate exposes **keys and hashes, not
values**: `substrate` is reduced to `*_keys` + counts, declared commands to a sha, and blob-class
artifacts are excluded from export (they appear only as `artifact_receipts` with a hash). A scan
of the committed files for this machine's hostname / kernel / home path returns nothing.

## Runs

### 1. `completed` — push · read · uname · write artifact · pull

```
porter run --target ssh:localhost \
  --push <tree-with-input.txt> --pull out.txt --expect os=Linux \
  -- sh -c 'cat input.txt; uname -sm; printf LIVE-ARTIFACT > out.txt'
```

Receipt: [`ssh-localhost.completed.aggregate.json`](./ssh-localhost.completed.aggregate.json)

| criterion (§7 / §10.3 item 2)            | result |
|------------------------------------------|--------|
| run_id                                   | `2026-07-09T18-56-18Z-521ddd` |
| outcome                                  | `completed` |
| exec exit code / observed                | `0` / `true` |
| transcript captured + hashed             | yes (`transcript_sha256` in receipt) |
| pulled artifact hash == disk bytes       | yes (`b'LIVE-ARTIFACT'`, sha `6a38e66d…`) |
| `sha256sum -c SHA256SUMS`                | rc `0` (all match) |
| `record.json` validates `porter.record.v0` | yes |
| aggregate excludes blob custody          | `artifacts: []`, `excluded_classes: ["blob"]`, blob appears only as `artifact_receipts[].custody_class` |
| **F1 live:** `--expect os=Linux` vs observed | Porter-computed `fact_mismatches: []` (matched) |

### 2. `run_failed` — true nonzero exit over the live connection

```
porter run --target ssh:localhost -- sh -c 'echo doing work; exit 7'
```

Receipt: [`ssh-localhost.run_failed.aggregate.json`](./ssh-localhost.run_failed.aggregate.json)

| criterion | result |
|-----------|--------|
| run_id | `2026-07-09T18-56-46Z-4c20ef` |
| outcome | `run_failed` (the mule delivered bad news — not a Porter failure) |
| exec exit code / observed | `7` / `true` |
| Porter process exit | `0` (the payload's `7` lives in the record, not Porter's exit) |

## Still open for full F7 closure

- A **disposable, genuinely remote** host (different machine; ideally a throwaway VM), to move
  from "real transport, local host" to "real transport, foreign substrate."
- The **refusal** path (sentinel never returns → `refused`, nonzero process exit) is currently
  covered only by the shim (`PORTER_TEST_DROP`); capture it live once a killable remote exists.

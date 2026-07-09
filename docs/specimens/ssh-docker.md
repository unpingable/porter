# Specimen — live SSH transport against foreign hosts (Docker sshd)

**Captured:** 2026-07-09 · **Targets:** `ssh:porter-alpine`, `ssh:porter-debian` · **Porter:** working tree (F1+F5 branch)

This closes the foreign-host half of F7. Two disposable containers run a real `sshd`; Porter
reaches them over the real `ssh(1)` binary and real TCP (`127.0.0.1:2222` / `:2223` → container
`:22`). Distinct from the [`ssh-localhost`](./ssh-localhost.md) specimen: these are **separate
substrates** — their own hostnames, filesystems, PID namespaces, and userspace distros (Alpine
3.23 and Debian 12) — not the courier's own machine.

Both containers were driven with the genuine `ssh` binary via a thin wrapper pinning an isolated
`-F <config>` (throwaway host aliases, key auth, `StrictHostKeyChecking no`, null known_hosts).
The wrapper is the real `/usr/bin/ssh`; transport, `sshd`, TCP, and pubkey auth are all live. No
change was made to the operator's `~/.ssh/config`.

## Custody

Committed artifacts are the **scrubbed `export/aggregate.json`** receipts only — the raw records
(holding container hostnames `b3488b583361` / `19b5d696aba0`, kernel string, remote paths) stay
under local custody per §4 / the F6 lesson. The aggregate exposes keys + hashes, not values; a
scan of the committed files for either container hostname, the kernel, or the operator home path
returns nothing.

## Runs — all outcomes exercised live

### 1. `completed` — Alpine — push · read · exec · write · pull, with a live F1 mismatch

```
porter run --target ssh:porter-alpine --push <tree> --pull out.txt \
  --expect os=Linux --expect arch=riscv64 \
  -- sh -c 'cat input.txt; uname -sm; printf FOREIGN-ALPINE > out.txt'
```

Receipt: [`ssh-docker-alpine.completed.aggregate.json`](./ssh-docker-alpine.completed.aggregate.json)

| criterion | result |
|-----------|--------|
| run_id | `2026-07-09T19-17-50Z-7fce99` |
| observed host / os / arch | `b3488b583361` / `Linux` / `x86_64` (a foreign hostname — not the courier's) |
| outcome · exec exit / observed | `completed` · `0` / `true` |
| pulled artifact hash == disk bytes | yes (`b'FOREIGN-ALPINE'`) |
| `sha256sum -c SHA256SUMS` | rc `0` |
| record validates `porter.record.v0` | yes |
| aggregate excludes blob custody | `artifacts: []`, no blob class in export |
| **F1 live** | declared `{os: Linux, arch: riscv64}` → Porter-computed `fact_mismatches: [{fact: arch, declared: riscv64, observed: x86_64}]`; `os` matched, so no entry. Porter compared against the *observed* value itself. |

### 2. `run_failed` — Debian — true nonzero exit

```
porter run --target ssh:porter-debian -- sh -c 'echo working on debian; exit 7'
```

Receipt: [`ssh-docker-debian.run_failed.aggregate.json`](./ssh-docker-debian.run_failed.aggregate.json)

| criterion | result |
|-----------|--------|
| run_id | `2026-07-09T19-17-51Z-8df131` |
| observed host | `19b5d696aba0` (Debian 12) |
| outcome · exec exit / observed | `run_failed` · `7` / `true` |
| Porter process exit | `0` (the payload's `7` lives in the record) |

### 3. `refused` — Alpine — connection killed mid-exec (live refusal, at last)

The container was `docker kill`ed while an exec's sentinel was still pending — the
sentinel-never-returns path that was previously only shim-covered.

```
porter run --target ssh:porter-alpine -- sh -c 'echo starting long task; sleep 25; echo SHOULD_NOT_REACH'
#   ... docker kill porter-f7-alpine  (mid-exec) ...
```

Receipt: [`ssh-docker-alpine.refused.aggregate.json`](./ssh-docker-alpine.refused.aggregate.json)

| criterion | result |
|-----------|--------|
| run_id | `2026-07-09T19-18-06Z-09ab76` |
| outcome | `refused` |
| `exit_code_observed` / `exit_code` present | `false` / **no** (Porter did not fabricate a `0`) |
| refusal_reason | `command exit code was not observed; ssh exited 255` |
| Porter process exit | **`1`** — a refusal never reads as process-success |

## Status

F7 is **closed**: the ssh transport now has live testimony against foreign substrates for all
three reachable outcomes (`completed`, `run_failed`, `refused`), plus a live F1 mismatch. The
containers were disposable and torn down after capture (`docker rm -f`). The fake-ssh shim
remains as fast, no-substrate CI coverage; it is no longer the *only* evidence the path works.

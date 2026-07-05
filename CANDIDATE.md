# Porter — historical design input

> **Status:** historical design input. **`DESIGN.md` is authoritative for Porter v0.**
> This file captures the origin framing and the empirical reuse-vs-bespoke split that fed
> the design. Where it says **"witnesser" / "witnessing layer," read "courier" / "receipt
> (courier) layer."** The final posture is a *courier*, not a witness: Porter has **custody,
> not standing** — it records what ran and preserves the receipts; it does not judge
> admissibility, support, correctness, or domain meaning. Do not resurrect "witnesser."

> **Porter is not a portability fixer. It is a _courier_** (this doc's original line read
> "witnesser" — demoted; see the status note above).

It spins up (or connects to) a substrate, runs the declared commands, captures what
happened, and refuses to launder "green where tested" into "supported."

## The core law (poison pill)

```
compile green   ≠ runtime support
test green      ≠ capability parity
unsupported     ≠ error
artifact exists ≠ authority
```

Synthetic/lab green is **compatibility** evidence, never **live testimony** about the real
substrate. Porter must distinguish "this command produced no artifact" from "this command
could not be run here" — but it stops there: it records the distinction, it does not rule on
what the distinction *means*. (The origin framing reached for NQ's `cannot_testify` contract
here; that was the robes-wearing temptation the courier demotion removes — Porter imports no
AG/NQ doctrine.)

## Sketch CLI

```
porter run --target freebsd --project ./nq --profile rust-cargo
```

emits three evidence buckets:

```
compatibility evidence:   substrate identity; toolchain versions;
                          build/check/test exit codes; fresh-vs-cached build signal;
                          summarized failures
capability evidence:      what ran; what was unsupported; what failed generically;
                          what silently skipped; what must NOT be inferred
artifact custody:         full logs local; sanitized aggregate export;
                          hashes/digests; replay instructions
```

## Proposed shape (sketch)

```
porter/
  profiles/    rust-cargo.yaml   python-pytest.yaml   lean-lake.yaml
  targets/     freebsd.yaml      macos-mini.yaml      linux-vm.yaml
  outputs/     compatibility_report.v0  capability_report.v0  sanitized_aggregate.v0
```

**Priority profiles:** `rust-cargo` and `python-pytest`. `lean-lake` is later/maybe — Lean
is less OS-sensitive but still wants environment reproducibility.

## Reuse surface (why it's bigger than NQ portability scripts)

```
NQ:             Linux/macOS/FreeBSD witness behavior across substrates
AG:             external harness substrate checks
claimc / Rust:  build/test compatibility across OSes
Lean:           environment reproducibility
future agents:  "does this thing survive on another substrate?"
```

## Reuse core vs bespoke tail (observed)

Empirical split from three real substrate runs in one week — pfSense CE lab (2026-06-25),
FreeBSD 14.4 VM, and the M4 mac mini (both 2026-06-30). This is the design input that says
where Porter's weight belongs.

**Reused verbatim or near-verbatim across runs — this is the product:**

- **Serial-console expect driver.** `sercon.py` → `fbsd_con.py` was a direct copy+retarget:
  connect to a unix socket, expect/send, run-a-command-and-capture-its-true-exit-code via a
  sentinel. The single load-bearing reusable artifact.
- **Exit-code-honest remote runner.** `RC=$?` sentinel over the console — verification
  discipline applied to a foreign shell. Reused every time.
- **The three evidence buckets** (compatibility / capability / custody). Held unmodified for
  all three runs. It *is* the product.
- **Custody handling.** Full transcript stays local; sanitized aggregate returns. The mac run
  needed this for real (SECRET box) — not speculative.
- **Cross-cutting gotchas.** Bake the source commit so tarball builds don't masquerade as
  failures (`NQ_BUILD_COMMIT`); checksum-verify the downloaded image; emit a fresh-vs-cached
  build signal so a no-op rebuild can't read as a pass.

**Bespoke every single time — the long tail, do not try to unify it:**

- **Provisioning / boot / install.** pfSense fought serial automation (a manual UFS install
  was the hard part); the plain FreeBSD qcow2 had no serial console, forcing a pivot to the
  CLOUDINIT image + a NoCloud seed ISO; the mac needed **no VM at all** — real hardware over
  `ssh mac`. Three substrates, three completely different "how do I get a shell."

**Design direction this implies:** put the weight in the **courier (receipt) layer** — driver +
record-schema + custody + file-transfer verb — which genuinely repeated. The one place a
declarative framework would over-reach is `targets/*.yaml` as a *provisioning engine*: boot
and install were the opposite of uniform. Keep `targets/` as thin per-substrate recipe
scripts (or just "give me a shell + a way to push a file"), not a provisioning DSL. The
provisioning stays an honest pile of per-substrate scripts; the abstraction lives in what
happens *after* you have a shell.

## Transfer + driver patterns already proven (lift these directly)

- **Source in:** `git archive HEAD | <transport>` — over an HTTP server bound to the libvirt
  bridge + `fetch` (FreeBSD VM), or `| ssh host tar x` (mac). Two transports, one need;
  Porter wants a pluggable "push a tree to the substrate" verb.
- **Drive:** redirect the long build to a logfile on the substrate, surface only the exit code
  + a scraped summary over the slow console; pull the full log under custody afterward.

## First-caller evidence (co-equal, not NQ-owned)

Porter is **constellation infrastructure** discovered independently by two callers in one week.
NQ and AG are **first callers / specimens, not parent authorities** (see `DESIGN.md` §1a). It
imports neither's doctrine.

- **NQ** — three build-time courier runs: pfSense CE declared-deny lab (2026-06-25), FreeBSD
  14.4 VM, and the M4 mac mini (both 2026-06-30). Reusable serial-driver toolkit at
  `~/nqlab/work/{sercon,fbsd_con,build_run}.py`; custody model at `~/nqlab/custody-artifacts/`.
- **AG** — needed a capable Ubuntu KVM host because local *nested* substrate produced refusal /
  false confidence. AG's bwrap validation produced two specimens that are exactly the
  courier-vs-domain split Porter draws:
  - `capable-vm-noble-001`: real bwrap cage started; a FakeProber-masked writable-root gap (C5)
    surfaced; admission refused.
  - `capable-vm-noble-002`: after the C5 fix, C1–C10 witnessed on real bwrap, C11 unavailable,
    admission refused.
  Porter's job is only the left half of those — *the command ran on this substrate and produced
  these transcripts/exit codes*. Whether C1–C11 amount to "admit" is **AG's** domain call, never
  Porter's.

---

_Provenance: James, 2026-06-30. Constellation courier primitive, surfaced by independent NQ + AG
substrate needs (not "NQ generalized"). Observed reuse/bespoke split added the same day from the
FreeBSD/macOS runs while they were fresh. **`DESIGN.md` is authoritative for v0; this file is
historical design input.** Mirrored in agent memory at
`~/.claude/projects/-home-jbeck-git-porter/memory/project_porter_candidate.md`._

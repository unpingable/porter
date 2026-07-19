# Porter — skeleton design (v0)

Companion to `CANDIDATE.md`. This is the smallest repo/CLI skeleton, not an implementation.
Porter is self-contained: it imports no AG or NQ doctrine and defines its terms in courier
language only.

## 1. Charter

Porter is a **courier**. It moves a declared command onto a declared temporary substrate,
runs it, and brings back honest receipts: the transcript, the true exit code, the produced
artifacts, and their hashes.

Porter testifies to exactly one thing:

> *This declared command ran on this declared substrate and produced these transcripts and
> these bytes, with this exit code.*

Porter does **not** testify that the bytes are correct, sufficient, or admissible for any
purpose. That judgment belongs to whoever reads the receipts.

**Non-goals (hard boundaries):** not CI, not a verifier, not admission control, not a
governor, not an oracle. No project doctrine inside. No pass/fail opinion beyond the exit
code the substrate actually returned. A mule with receipts.

The one non-negotiable behavior: **Porter never forges a receipt.** If it cannot observe the
true exit code or the substrate identity, it *refuses* — it does not substitute a plausible
value.

**Boundary illustration (from a real run).** NQ's `build_run.py` sets
`NQ_BUILD_COMMIT=$(git rev-parse ...)` before the build so a `git archive` tarball (no `.git`)
doesn't fail one project-specific test as a false portability failure. Porter offers the
*generic* mechanisms this needs — inject caller-supplied env before the command; transfer a
tree without `.git` — but must **never** know the name `NQ_BUILD_COMMIT` or why it matters.
The specific env var, and the meaning of the test it protects, are the caller's domain
contract. Porter carries the command; it does not understand the cargo.

## 1a. Scope — Porter is constellation infrastructure

Porter is **constellation infrastructure**, not "NQ's substrate-run pattern generalized." It
was discovered independently through repeated substrate needs in **NQ** (Linux/macOS/FreeBSD
courier runs) and **AG** (a capable Ubuntu KVM host, after local nested substrate produced
refusal / false confidence). NQ and AG are **first callers / specimens, not parent
authorities** — Porter is owned by neither and imports neither's doctrine. Any agent building
any tool in the constellation is a valid caller.

Porter serves two related uses, and we are **not** choosing between them:

1. **Build-time courier** — humans or agents drive Porter while developing constellation
   tools. This is the only use exercised to date (NQ ×2, AG ×1) and all of v0 serves it.
2. **Runtime-callable courier** — built tools may *eventually* call Porter to obtain substrate
   receipts without learning substrate mechanics.

The v0 implementation is **CLI-first**, because that is the narrowest useful surface. We do
**not** build the runtime API yet — no daemon, no server, no plugin architecture. The single
forward-looking commitment is smaller and cheaper:

> **`record.json` is a durable contract, not incidental CLI output.** Version it as
> `porter.record.v0` from day one.

Design consequences (constraints on every slice, not new scope):

- **Stabilize + version the record schema** from the start; additive-only until an explicit
  bump.
- **Keep domain judgment out of the schema** — no `success` / `passed` / `supported` /
  `admissible` fields, ever.
- **Avoid caller-specific vocabulary** in the schema and the wire (no `NQ_*`, no `__NQDONE__`).
- **Keep the core courier logic separable from the CLI**, so a later thin library face can wrap
  the same core instead of forking it.
- **Treat future library/API use as a compatibility constraint, not Slice-1 scope.**

The narrow contract is unchanged by any of this:

> Porter records that a declared command ran on a declared substrate and produced declared
> receipts. Porter does not decide whether those receipts satisfy any caller's domain contract.

## 2. CLI commands

Stepwise verbs are canonical; `run` is sugar over them.

```
porter up     <target>                 # create/connect substrate, record declared+observed facts → run_id
porter push   <run> <src> [dst]        # push a tree/file to the substrate (git archive | transport)
porter exec   <run> -- <cmd...>        # run declared command, capture transcript + TRUE exit code
porter pull   <run> <remote> [local]   # pull an artifact under custody, hash it
porter seal   <run>                    # compute all hashes, write manifest, set outcome, close record
porter down   <run> [--preserve]       # teardown ephemeral substrate (or keep it and record that)

porter run    <target> [--push <src>] [--pull <glob>]... -- <cmd...>   # up→push→exec→pull→seal→down
porter ls                              # list runs
porter show   <run>                    # print record.json
```

Current v0 target shapes:
- `ssh:<host>` — already-reachable SSH host; supports push/exec/pull.
- `serial:<unix-socket-path>` — already-booted VM serial console over a Unix socket; exec only.
- `recipe:<script-path>` — caller-provided lifecycle hook; `up` returns an `ssh` or
  `serial-socket` substrate, `down` tears it down unless `--preserve` is set.

Recipe hook contract:
- Porter invokes `<script> up <run_id>` with `PORTER_RUN_ID`, `PORTER_RUN_DIR`, and
  `PORTER_RECORD` in the environment. Stdout must be one JSON object:
  `{ "kind": "vm", "transport": "ssh|serial-socket", "ephemeral": true,
  "declared": {...}, "observed": {...}, "fact_mismatches": [] }`.
- For `transport: "ssh"`, `declared.host` is required; `remote_root` and `workdir` may be
  declared or defaulted. For `transport: "serial-socket"`, `declared.socket_path` is required.
- Porter invokes the paired `<script> down <run_id>` from `porter down` or from `porter run`
  finalization. `--preserve` records preservation and skips the hook. This is still not a
  provisioning DSL; all substrate-specific work stays inside the caller script.

Design choices that keep the boundary clean:
- `porter` exits **0 when the courier job completed**, regardless of the payload's exit code.
  The payload exit code lives in the record. `--propagate-exit` is opt-in for callers who
  want CI-style ergonomics — off by default, because default-propagate would make Porter
  look like a verifier.
- A `target` is a thin recipe (a script or small YAML pointing at one), **not** a
  provisioning DSL. Provisioning stays an honest pile of per-substrate scripts; the
  abstraction lives in what happens *after* you have a shell.

## 3. Run-record schema (`record.json`)

```json
{
  "schema": "porter.record.v0",
  "porter_version": "0.0.1",
  "run_id": "2026-06-30T18-22-05Z-ab12cd",
  "target": "ssh:mac",
  "substrate": {
    "kind": "ssh|vm|container|hardware",
    "transport": "ssh|serial-socket|http-push",
    "ephemeral": true,
    "declared": { "os": "darwin", "arch": "arm64" },
    "observed": { "hostname": "...", "os": "...", "kernel": "...", "arch": "..." },
    "fact_mismatches": []
  },
  "declared_command": ["cargo", "build", "--release"],
  "steps": [
    {
      "seq": 1, "kind": "push|exec|pull",
      "declared": "cargo build --release",
      "exit_code": 0,
      "exit_code_observed": true,
      "transcript": "transcripts/0001-exec.log",
      "transcript_sha256": "…",
      "started_at": "…", "ended_at": "…"
    }
  ],
  "artifacts": [
    { "remote_path": "target/release/nq", "local_path": "artifacts/nq",
      "sha256": "…", "size": 12345678 }
  ],
  "outcome": "completed|run_failed|porter_failed|refused",
  "refusal_reason": null,
  "preserved": false,
  "notes": ""
}
```

Deliberately absent: any `success` / `passed` / `ok` field. The only truths recorded are
*did it run*, *what exit code came back*, *what bytes returned*, *what are their hashes*.
`fact_mismatches` records a declared-vs-observed discrepancy as a **note, not a verdict** —
Porter flags it and moves on; it is not an admission gate.

## 4. Artifact bucket layout

```
runs/
  <run_id>/
    record.json            # the receipt / manifest (schema above)
    transcripts/           # FULL console/exec logs — custody stays local
      0001-exec.log
    artifacts/             # captured artifacts — custody stays local
      nq
    export/                # returnable subset: summary + hashes, NO full logs
      aggregate.json
    SHA256SUMS             # checksums over everything under this run dir
```

**Custody classes (commit-safety gradient).** Borrowed from the proven NQ lab model
(`~/nqlab/custody-artifacts/`), which already states Porter's law in its own words —
*"artifacts are not authority; artifacts are custody-preserving material for later
reproduction, audit, or refusal."* This is a generic custody concern, not imported doctrine.
Every captured item is tagged one of three classes, and each class has a different default
egress:

| class     | examples                                   | default egress                 |
|-----------|--------------------------------------------|--------------------------------|
| `recipe`  | target scripts, seed configs, VM XML       | safe to commit                 |
| `receipt` | hashes, transcripts, exit codes, manifests | safe unless it leaks topology/secrets |
| `blob`    | ISOs, disk images, built binaries, pcaps   | **local/private only**, never default egress |

`export/aggregate.json` is the returnable subset: `recipe` + scrubbed `receipt` only —
never `blob`. `transcripts/` + `artifacts/` stay under local custody; `record.json` +
`SHA256SUMS` tie everything together with hashes.

## 5. Lifecycle model

```
create substrate  →  declare facts  →  run command  →  capture  →  honest exit  →  preserve/teardown
   porter up            (up records         porter exec    porter pull    porter seal      porter down
                         declared +                                                         [--preserve]
                         observed)
```

1. **create substrate** (`up`): run the target recipe until it yields a shell + a push
   channel; mint `run_id`; write the record stub.
2. **declare facts** (`up`): the recipe declares `kind`/`transport`/`ephemeral`; Porter
   probes `observed` identity and records both, plus any `fact_mismatches`.
3. **run command** (`exec`): push source if asked; run the declared command over the
   transport with an `RC=$?` sentinel; redirect long output to a substrate-side logfile and
   surface exit code + a scraped summary over slow transports.
4. **capture** (`pull`): pull the full log and declared artifacts under custody; hash each.
5. **honest exit** (`seal`): compute all hashes, write `SHA256SUMS` + `export/aggregate.json`,
   set `outcome`, close the record.
6. **preserve or teardown** (`down`): tear down ephemeral substrate, or keep it and set
   `preserved: true`. (An `ssh` target that Porter didn't create is preserve-by-nature.)

## 6. Refusal / failure semantics

Four outcomes, kept strictly apart:

| outcome        | meaning                                                                 |
|----------------|-------------------------------------------------------------------------|
| `completed`    | declared command ran, exit code observed and **== 0**                   |
| `run_failed`   | declared command ran, exit code observed and **!= 0** — faithfully reported; **this is not a Porter failure**, the mule delivered |
| `porter_failed`| Porter's own machinery broke (couldn't create substrate, transport dropped) |
| `refused`      | Porter would have to **guess or fabricate** to proceed                   |

**Refusal is the load-bearing behavior.** Porter refuses (never fabricates) when:
- it cannot obtain a shell / the transport is undeclared;
- the `RC=$?` sentinel never returned, so the exit code is **unobservable** — Porter records
  `exit_code_observed: false`, `outcome: refused`, and a `refusal_reason`; it does **not**
  write `exit_code: 0`;
- it was asked to pull an artifact that isn't there (records absence; doesn't invent an empty file).

Invariant: **unknown exit code → `refused`, with reason. Never coerced to `0` or to
`failed`.** A nonzero payload exit is `run_failed`, which is a successful courier job — do
not conflate the two.

**Porter's own process exit code** (distinct from the payload's — the payload's lives only in
the record). This is the courier reporting whether *it* did its job, and it must never let a
refusal masquerade as process-success:

```text
completed     → porter exits 0
run_failed    → porter exits 0        (mule delivered bad news; --propagate-exit → payload's code)
refused       → porter exits nonzero  (mule could not testify to the result — never looks successful)
porter_failed → porter exits nonzero  (courier machinery broke)
```

`--propagate-exit` only affects the `run_failed` row (0 → the payload's real exit code, for CI
ergonomics); it never turns a `refused`/`porter_failed` into 0. The whole point of the
`refused → nonzero` rule is to defeat the dumb-automation trap where a run whose result was
never observed still reads as green.

## 7. First implementation slice (for Codex)

**Slice 1 — SSH courier, no provisioning.** Target is an already-reachable ssh host (e.g.
`ssh mac`). This exercises the entire courier (receipt) layer — the actual reusable product —
while skipping the bespoke provisioning tail entirely.

Build:
- `porter run --target ssh:<host> [--push <src>] [--pull <glob>] -- <cmd...>`, plus the
  stepwise `up`/`exec`/`pull`/`seal`/`show` for the same ssh transport.
- ssh transport module: **push** = `git archive HEAD | ssh host 'tar x -C dst'`; **exec** =
  run with `RC=$?` sentinel, capture full transcript; **pull** = `scp`/`tar`, hash on arrival.
- record writer: `record.json`, `transcripts/`, `artifacts/`, `SHA256SUMS`,
  `export/aggregate.json`.
- outcome taxonomy from §6, including refuse-on-unobserved-RC.

Explicitly **out** of slice 1 (later slices): VM provisioning, the serial-console transport
(slice 2 — port the proven `~/nqlab/work/fbsd_con.py`, whose `run()` already does the
sentinel-based true-exit-code capture; rename its `__NQDONE__` sentinel to a Porter-namespaced
token so no caller vocabulary leaks into the tool), ephemeral teardown.

Acceptance (boring + testable, decided by exit codes, not eyeballing):
1. Command that exits `7` on the host → `record.json` shows `exit_code: 7`,
   `outcome: run_failed`, transcript captured with a hash.
2. Connection killed mid-run so the sentinel never returns → `outcome: refused`,
   `exit_code_observed: false`, **no** `exit_code: 0`, **and `porter` exits nonzero**.
3. A file the command produced, pulled under custody, has a sha256 that matches its entry in
   `SHA256SUMS`.
4. Per the §6 exit policy: cases 1 and 3 → `porter` exits `0` (courier completed; payload's
   `7` lives in the record, not Porter's exit code, unless `--propagate-exit`); case 2 →
   `porter` exits nonzero (a refusal must never read as process-success).

## 8. Slice roadmap + open questions

This roadmap is a **scope-control device**, not a product plan. It exists to stop "later"
from becoming an unbounded surface. Build in the order that proves the courier core without
pretending substrate provisioning is uniform (the empirical split in `CANDIDATE.md` is why:
pfSense, FreeBSD cloud-init, and Mac-over-SSH had three completely different "get me a shell"
paths). **Docs-only — this section authorizes nothing to be built out of order.**

Slice 1 (§7) is the committed baseline — the reusable core over SSH. The roadmap below starts
*after* it.

### Slice 1.5 — contract hardening / CLI-core split

Before adding a second transport, make sure Slice 1 didn't accidentally weld the record to the
CLI. If built tools may call Porter later, the record is the API seed (see §1a).

Scope:
- version `record.json` as `porter.record.v0`;
- separate the core record writer/loader from CLI command handling;
- golden record fixture tests;
- additive-only schema posture (v0 fields never removed/repurposed until an explicit bump);
- assert **no domain fields**: no `success` / `passed` / `supported` / `admissible`;
- exit policy represented in both the record and process behavior.

Purpose: make the "record is a contract" claim mechanically hard to regress.

### Slice 2 — serial-console transport

Port the proven `~/nqlab/work/fbsd_con.py` pattern into Porter terms.

Scope: attach to an **already-booted** VM over a unix-socket serial console; send command; emit
a **Porter-neutral** sentinel; observe the true payload exit code; capture transcript; write the
**same** record + refusal semantics as Slice 1.

Out: provisioning the VM; installing an OS; libvirt/QEMU orchestration; project-specific command
knowledge; NQ-named sentinels or any caller vocabulary.

Purpose: prove the core is not SSH-shaped.

### Slice 3 — caller-recipe lifecycle

Make ephemerality real, but **narrowly**. This is **caller-provided recipe lifecycle, not
Porter owning libvirt** — the first libvirt path must not be mistaken for Porter becoming a
provisioning engine.

Scope:
- `porter up <target>` invokes a **caller-provided** recipe script that yields a shell +
  push/pull channel and returns connection metadata;
- Porter records the recipe (as `recipe` custody), declared facts, observed facts, and the
  preserve/teardown choice;
- `porter down <run>` invokes the paired teardown hook unless `--preserve`.

Out: a provisioning DSL; `targets/*.yaml` as an engine; Porter learning QEMU/libvirt directly.

Purpose: honest ephemerality without YAML necromancy.

### Slice 4 — custody export enforcement

Turn the §4 bucket model from prose into behavior.

Scope: classify every captured item as `recipe` / `receipt` / `blob`; generate
`export/aggregate.json` from `recipe` + scrubbed `receipt` only; **blobs never leave by
default**; emit replay instructions; bind local custody to exported summaries via `record.json`
+ `SHA256SUMS`.

Purpose: let callers move receipts without accidentally exporting disk images, binaries,
secrets, pcaps, or topology.

### Slice 5 — optional library/API face

Only after two transports + custody export exist. A **thin wrapper around the same core** the
CLI uses — not a second implementation, not a daemon, not a server.

Candidate shape:
```python
record = porter.run(
    target="ssh:mac",
    command=["cargo", "test"],
    push=Path("."),
    pulls=["target/release/foo"],
)
```
It returns a **record, not a boolean**. That is the whole point — no `run_and_assert_green()`
goblin. Domain judgment stays with the caller.

### Named but not yet scheduled (soft fence, not jersey barrier)

These are recognized and welcome — just not on the committed order until there's a reason.
A soft fence: step over it when a real repeat or forcing case shows up; don't pour a barrier
that reads as "never."

- **Profiles** (`rust-cargo`, `python-pytest`, maybe `lean-lake`) — command bundles to cut
  caller boilerplate. Reach for one once the same bundle repeats across real caller use; even
  then a profile may *declare* commands + expected artifacts, never *decide* domain success
  beyond the observed payload exit code.

### Open design questions

1. **Provisioning ownership.** Current evidence says provisioning is bespoke. Default answer:
   **no**, Porter does not own QEMU/libvirt — it prefers caller-provided recipe scripts.
   Revisit only if the *same* lifecycle path repeats enough to justify lifting.
2. **Run-state persistence.** The stepwise CLI needs run state across process invocations.
   Slice 1 must define the minimal `runs/<run_id>/` state dir and its update/locking behavior.
   *Resolved (F5, §9): a fail-fast `runs/<run_id>/.lock` flock serializes mutating commands;
   one process per `run_id`, else `RunLockedError`.*
3. **Completeness boundary ("done enough").** Porter is an instrument, not a product platform
   (it may not even be a public repo). It is done when it reliably couriers the substrates we
   **actually use** — current NQ/AG/Lean/dev needs — **not** when it becomes a general
   portability framework.
4. **Domain separation.** Porter records what ran, where, what exited, and what bytes came
   back. It does not decide whether AG, NQ, Lean, or any other caller should accept those bytes
   as satisfying a domain contract.
5. **Expected load shape.** **NQ is the primary, high-volume caller** — it talks to
   systems/apps "in prod," so it will spin up *many* VMs/containers, repeatedly. **AG returns**
   once multi-AG work starts. This isn't a speculative future; it's the standing load. Its
   design consequence: Slice 3 (lifecycle/teardown) and Slice 4 (custody export/rotation) are
   on the **critical path**, not "maybe later" — at volume, un-torn-down substrates and
   unrotated custody blobs become the actual failure mode, and per-run cost (state dir,
   hashing, teardown reliability) matters more than for a one-off harness. Build them boring,
   but don't treat them as optional polish.

### Roadmap invariant

Build the boring mule first. Do not add a feature unless it preserves this contract:

> Porter may testify that a declared command ran on a declared substrate and produced declared
> receipts. Porter may **not** testify that the receipts satisfy the caller's domain.

After the docs land: **Codex gets Slice 1.** No provisioning, no profiles, no serial console
yet. Claude stays in prosecutor/documentarian mode unless Codex creates a boundary ambiguity.

## 9. Prosecutor findings — post-Slice-1 review (2026-07-01)

Documentarian input for Codex, not authorization to build. Each finding was verified against
the tree at review time (paths/lines named). They are sorted by the axis that decides whether
a fix is owed *now*: **completeness debt** on an already-opened surface (the slice promised it;
finishing is an obligation, not new scope) versus a **soft fence** (a real gap, but a new
surface whose build waits on a forcing case). "Refusal-honesty" tags a finding where the
receipt currently implies something Porter did not observe — the one thing Porter must never do.

### Owed now — completeness debt on surfaces already opened

**F1 — `fact_mismatches` is promised but never computed (refusal-honesty).**
§3 puts `fact_mismatches` in the schema and §5 step 2 says Porter "records both [declared and
observed], plus any `fact_mismatches`." But `up_ssh`/`up_serial` (`runner.py:86`, `:117`) probe
`observed` and never diff it against `declared`, and `normalize_recipe_substrate`
(`recipe.py`) copies the recipe's self-declared list verbatim. So the field is either empty or
the recipe grading its own homework — a promised check that isn't performed. The surface is
open (the field ships in every record); the honesty note is unfinished.
*On-doctrine fix, kept narrow:* let callers **declare** the facts they claim (`os`/`arch`), and
have Porter compute the mismatch for any fact it **both declares and observes** — emitting a
note, never a verdict, never an admission gate (§3's "note, not a verdict" still holds). Keep
caller-declared mismatches distinguishable from Porter-computed ones so the recipe can't launder
its own claim through Porter's name. Today the ssh `declared` block carries no `os`/`arch`, so
there is literally nothing to compare — closing F1 means accepting declared facts, not just
diffing what's already there.

**F2 — env injection: the charter's own worked example can't be served.**
§1's boundary illustration is explicit: Porter offers the *generic* mechanisms NQ's
`NQ_BUILD_COMMIT` needs — "inject caller-supplied env before the command; transfer a tree
without `.git`." The tree-without-`.git` half shipped (`git_archive_or_tar`, `ssh.py:95`); the
env half did not — there is no `--env KEY=VAL`, and `build_exec_script` (`runner.py:325`) takes
no env. So the motivating example forces the caller to smuggle env into the command string.
*On-doctrine fix:* `--env KEY=VAL` (repeatable) → `shlex`-quoted `export` prepend in both the
ssh and serial exec builders. **Custody nuance (load-bearing):** env values are the most likely
secret carrier. Record env **keys** (optionally value-hashes), **never raw values**, in the
record or transcript — putting them in unscrubbed would violate Porter's own custody gradient
(§4). This stays additive to `porter.record.v0`.

**F3 — `push = git archive HEAD` ships stale bytes with a clean receipt (refusal-honesty).**
`git_archive_or_tar` (`ssh.py:95`) transfers committed `HEAD` only; uncommitted working-tree
edits vanish, and the receipt does not say so. Reproducibility-positive, but for a build-time
courier it is a trap: edit, forget to commit, courier runs stale code, hands back a clean
receipt for bytes you didn't test. The receipt currently *implies* the working tree was couriered.
*On-doctrine fix:* at push time, if `git status --porcelain` is non-empty, record that fact in
the push step (so the receipt cannot imply the dirty edits were tested), and/or offer
`--worktree` to tar the dirty tree explicitly. Refuse to imply; don't silently pick a tree.

### Soft fence — real, but new surface; step over on a forcing case

**F4 — in-memory transcript capture won't survive NQ volume.**
`run_script_combined` (`ssh.py:36`) buffers the entire transcript via `subprocess.PIPE`. §5
step 3 already describes the fix ("redirect long output to a substrate-side logfile, surface
exit code + a scraped summary over slow transports"), but the ssh path streams everything back.
This is not speculative: §8 Q5 names **NQ as the high-volume, prod-VM primary caller** — a
multi-GB build log per run in memory is a named standing-load failure class, so this is
"build ahead of a known failure class," not YAGNI. *Forcing trigger:* land the tee-to-remote-log
+ scraped-summary pattern before high-volume NQ use, not after it bites. Slice-shaped, so it
rides with Slice 2's transport work or a dedicated hardening pass — not an inline patch.

**F5 — run-state locking (open Q2, still open).** `save_record` is atomic per write, but two
`porter exec` on the same `run_id` do load-append-save with no lock (`runner.py`); the second
clobbers the first's step. Steps are meant sequential, so the risk is low — but §8 Q2 said
Slice 1 "must define the minimal `runs/<run_id>/` state dir and its update/locking behavior,"
and that definition is still absent. *Cheapest close:* a `runs/<run_id>/.lock` or a documented
"one process per `run_id`" invariant. Pick one and write it down; the gap is the silence.

### Housekeeping — cheap, no forcing case needed

**F6 — the committed specimen violates Porter's own custody gradient.**
`outputs/ag-bwrap-substrate/*.json` are not Porter records (no `porter.record.v0`; they carry
AG's `cage_attestation` / `not_live_testimony` vocab and embedded run-ids), and they leak a
full kernel string with a `porter-cage-vm` hostname. By §4 that is a `receipt` that leaks
topology being committed by default. *Fix:* replace with a scrubbed `export/aggregate.json`
specimen — the on-doctrine artifact — or drop it. Tiny, but it's Porter's rules catching
Porter's own repo, and CLAUDE.md already warns against porting AG/NQ field names wholesale.

**F7 — transports are untested without a live substrate.** 13 tests cover the contract core
(matches §7 acceptance), but ssh/serial/recipe are exercised only where a substrate exists.
The recipe transport gives a substrate-free path: a fixture recipe that yields a **local** shell
could drive `up → push → exec → pull → seal` end-to-end in CI without a VM, covering the
sentinel-parse and refusal paths that matter most.

**Priority, per the reviewer and unchanged here:** F1 and F2 are the two that actually move the
needle — F2 closes the design's own worked example, and F1 is the difference between a computed
honesty note and a field that only pretends to check. F3 is a small refusal-honesty patch worth
folding in with F2. F4–F7 are recognized and fenced, not deferred into "never."

### Status update (2026-07-09)

The findings above are the prosecutor record as first written; this block layers what Codex
has since closed (basis named, per the repo's "claim names its basis" rule). Findings are not
rewritten — only annotated.

- **F2 — CLOSED** (`6f8441a`). `--env KEY=VAL` on `run`/`exec`; `build_exec_script(..., env=)`;
  keys recorded, values never stored (asserted by test). The charter's worked example is served.
- **F3 — CLOSED** (`6f8441a`). `is_dirty_worktree` + `push --worktree`; a dirty tree is
  annotated (`dirty_worktree`) so the receipt cannot imply the uncommitted edits were tested.
- **F6 — CLOSED** (`e64b3f6`). The topology-leaking AG specimen was removed from `outputs/`;
  golden-fixture custody classes pinned.
- **F7 — CLOSED.** The ssh path now has live testimony against **foreign substrates**, not just
  the shim: two disposable containers (Alpine 3.23, Debian 12) running real `sshd`, reached over
  real `ssh` + TCP (`docs/specimens/ssh-docker.md`). All three reachable outcomes captured live —
  `completed` (foreign hostname, artifact hash == `sha256sum -c`, v0-valid record, scrubbed
  blob-excluding aggregate), `run_failed` (true exit `7`, Porter exit `0`), and **`refused`**
  (container killed mid-exec → `exit_code_observed: false`, no `exit_code`, Porter exit `1`) —
  plus a live F1 mismatch (declared `arch=riscv64` → Porter-computed against observed `x86_64`).
  A localhost specimen (`docs/specimens/ssh-localhost.md`) also exists. The fake-ssh/fake-serial
  shims remain fast no-substrate CI coverage (28 tests); they are no longer the *only* evidence.
- **F1 — CLOSED** (working tree, uncommitted). Porter now computes `fact_mismatches` itself:
  `record.compute_fact_mismatches` / `refresh_fact_mismatches` is the *sole writer*, comparing a
  new caller-declared `substrate.declared_facts` against probed `observed` only for facts present
  in both — a note, never a gate (outcome is unaffected). Callers declare via `--expect KEY=VAL`
  (ssh/serial) or recipe `declared_facts`; `recipe.py` now *strips* the caller's self-declared
  `fact_mismatches` as untrusted. Aggregate `fact_mismatch_count` is derived from the computed
  list. Tests: `test_fact_mismatches_{match_yields_zero,mismatch_is_emitted,only_compares_observed_facts}`,
  `test_recipe_cannot_force_empty_fact_mismatches`,
  `test_recipe_predeclared_mismatches_do_not_control_result`, `test_expect_flag_computes_ssh_fact_mismatch`
  (25 passed). No schema-breaking rename — `declared_facts` is additive to `porter.record.v0`.
- **F5 — CLOSED** (working tree). `records.run_lock` is a fail-fast POSIX `flock` over
  `runs/<run_id>/.lock`, held across load→save; the mutating commands (`push`/`exec`/`pull`/
  `seal`/`down`) are wrapped by `runner.with_run_lock`, so a second process on the same
  `run_id` raises `RunLockedError` (clean nonzero exit) instead of clobbering a step. `up` is
  unwrapped — it mints a fresh `run_id`, so it never contends. The `.lock` file is excluded
  from `SHA256SUMS` (transient run state, not custody). Answers open question Q2 (§8). Tests:
  `test_run_lock_is_exclusive_then_reacquirable`, `test_run_lock_file_is_excluded_from_checksums`,
  `test_exec_on_locked_run_is_refused_not_clobbered`.
- **F4 — OPEN, fenced.** In-memory transcript buffering stands as written; folds into the §10
  adapter/transport work.

## 10. Substrate-adapter direction (recorded 2026-07-09)

Operator-directed direction, recorded per *name early, ratify lazily*. **This section is a
handle for review, not authorization to build.** Nothing here lands without a forcing case and
testable acceptance; every schema-touching item is **additive** to `porter.record.v0` and needs
deliberate ratification before it ships. Exactly one thing here is recorded as **binding
doctrine** rather than candidate — §10.1, the boundary that keeps the rest from metastasizing.

### 10.1 Boundary doctrine — mechanics yes, kingdom no  [binding]

Transport is never purely semantic: somebody must actually create the sandbox, bind the mounts,
clamp the network, inject env/secrets, collect logs/artifacts, kill the payload when it gets
clever, and prove teardown happened. **That is legitimate Porter work.** The bright line:

> Porter may implement the boundary mechanics needed to preserve courier semantics across a
> substrate. Porter must not schedule, place, reconcile, admit, verify, or judge work.

Operating rule when a backend leaks semantics:

```
Use existing substrate when it preserves the contract.
Wrap substrate when it leaks semantics.
Emulate only the minimum needed to preserve custody.
Never build a general platform when a typed adapter suffices.
```

Backend adapters, not a kingdom. The test:

> If Porter starts deciding *what should run*, it is wrong.
> If Porter decides *how to preserve the admitted run's constraints on this backend*, it is
> doing its job.

The layering Porter sits in — it owns translation fidelity, not fleet destiny:

```
AG:      may this run exist?
Maude:   how is this run supervised?
Porter:  can this run be carried into backend X without semantic damage?
Backend: actually run the thing.
```

The failure mode, refused by name — the moment Porter grows node state it is over:

```
Docker adapter → lifecycle tracking → workers → placement → leases →
health checks → reconciliation → congratulations, you have built haunted Kubernetes.
```

This does **not** repeal §1 / §8's "not a provisioning framework." A typed adapter that binds a
mount or clamps a network for *one* backend is boundary mechanics; a scheduler that places work
across many is the framework §1 forbids. House-style gloss:

> Porter carries the box. It does not decide whether the box should exist, whether the contents
> are good, or whether the warehouse needs a religion.

### 10.2 Candidate surfaces (named, non-binding)

Named early because retrofit cost rises once backends multiply — these are exactly the
APIs / schemas / wire formats to record *before* they spread, not build now.

- **C1 — Adapter seam. LANDED** (behavior-preserving). `porterlib/adapters/` now holds a
  `SubstrateAdapter{ observe, exec_command, push, pull }` interface + `SSHAdapter` / `SerialAdapter`,
  routed by `adapter_for_record` on the record's transport. Scoped to **post-shell** ops only —
  `up`/provisioning stays in `runner` per §1 ("abstract only what happens after you have a shell");
  `recipe` is a target that resolves to ssh/serial, not its own adapter. Each adapter declares
  `supports_push`/`supports_pull` (class attributes, **not** written to the record — pre-figures
  C2 without a schema change). Acceptance met: same CLI, same records/golden fixtures, 28 tests
  green, live re-check against real `sshd`. Not moved: `up_*`, capability metadata in the record
  (C2), any new transport.
- **C2 — Capability model.** Each adapter *declares* what it supports rather than implying it —
  transport truth, not governance: `push / pull / exec / env / teardown / resource_limits /
  network_policy / teardown_attestation`. Without it Porter eventually **lies by omission** (ssh
  and serial can't limit CPU or shape network; Docker can). Additive metadata, not a verdict.
- **C3 — Constraint carriage (schema-danger zone).** For constellation use Porter must *carry*
  constraints (network deny/egress; cpu/mem/wall-time/disk; ro/rw filesystem), never *decide*
  them. The receipt records four typed facts and nothing implying safety:
  `constraint_declared`, `constraint_applied`, `constraint_application_observed`,
  `constraint_refusal_reason`. Declared / backend-support / observed-application-or-refusal —
  never "this was safe." Unsupported constraint → refuse or record-unsupported clearly.
- **C4 — Timeout / cancellation taxonomy.** Typed outcomes are missing: `setup_timeout`,
  `exec_timeout`, `pull_timeout`, `down_timeout`, `operator_cancelled`, `transport_lost`.
  Load-bearing rule, already aligned with the unobserved-exit invariant (§6): **a timeout with
  unknown payload exit is `refused`, not `failed`.**
- **C5 — Secret wall.** Extends the landed env key-only recording (F2). For container exec:
  `--secret KEY=source`, key-names only, never echo values on the command line, file-or-env
  injection per backend, a redaction token for transcripts, and a **hostile test** where the
  payload tries to print the secret. Explicit doctrine, not vibes: if the payload prints a secret
  Porter never held, Porter cannot scrub it — redaction requires Porter to hold the value or a
  token. Name that limit; don't paper over it.
- **C6 — Schema made boringly explicit.** The schema is the product; the CLI is just how the
  mule currently walks. Owed: `docs/schema/porter.record.v0.md`; fixtures for `refused` /
  `run_failed` / `porter_failed`; a schema changelog; a stated unknown-field compatibility rule
  (allowed / rejected / namespaced).
- **C7 — Export verifier.** A neutral integrity checker, not a pass/fail oracle:
  `porter verify-record <run>` / `porter verify-export <aggregate.json>` — asserts hashes line
  up, schema validates, referenced files present, and **no blob-class item leaked into the
  export**. Not "passed"; custody integrity only.
- **C8 — Caller integration seam.** A thin neutral `PorterRequest(target, command, pushes,
  pulls, env_keys, constraints)` over the record-returning API — still returns a record, never a
  boolean, never AG/Maude vocabulary. The domain-separation test is the immune system; keep it.

### 10.3 Candidate build order (soft fences, forcing-case gated)

Not a commitment — the order to *reach for* when a forcing case lands, each slice proving the
contract before an abstraction is frozen:

1. **Adapter seam, zero behavior change** — refactor prefix branching into `adapters/`; every
   test green; no schema change.
2. **Real-SSH specimen** — run the ssh path against a disposable real host (the ssh path is
   still only exercised through the fake shim). Capture record + refusal + artifact-hash +
   caveats under `docs/specimens/`. Closes the live-authority gap F7 left open. Do this
   **before** widening the surface.
3. **Docker via recipe specimen** — prove container semantics through the *recipe* transport
   first (disposable container, mounted workdir, exec, pull, `down` destroys, `--preserve`
   skips); record stays `porter.record.v0`. Recipe-first tells you what the contract needs
   before code freezes a bad shape.
4. **Constraint declaration skeleton** — the C3 fields behind the docker/recipe specimen;
   unsupported → refuse-or-record-unsupported; no safety claim.
5. **Native docker/podman adapter** — only after the recipe specimen proves the shape. Records
   image digest + container id + observed teardown; applies-or-refuses resource/network
   declarations; **no scheduling language.**

Scope-control anchor, recorded verbatim: *Porter does not need a new project. It needs an
adapter seam, capability/refusal vocabulary, real-host evidence, then a container specimen. The
cursed k8s trap starts the moment it grows node state.*

## 11. Qualification-run governance (recorded 2026-07-19)

Operator-directed, recorded per *name early, ratify lazily*. **A handle for review, not
authorization to build.** One item is recorded as **binding doctrine** — §11.1, the verdict
layering — because it is the law that keeps a courier from greenwashing a refusal. The rest
are candidate surfaces: named so they are not rediscovered per-campaign, non-binding until a
forcing case and testable acceptance justify each one.

Origin: a real VM qualification campaign run through hand-rolled harness scripts (see §11.4).
The campaign kept re-deriving machinery that is not product-specific. That machinery is
Porter-grade; the product's gates are not.

### 11.1 Verdict layering — transport completion is not a governed verdict  [binding]

Porter already refuses to let `ssh 255` read as success. Generalize it: an execution stack has
**more than one** honest outcome, and the outer ones must never overwrite the inner ones.

```
transport outcome      — did the carrier (ssh, wrapper, background task) complete?
harness verdict        — did the declared gate sequence run to completion?
qualification verdict  — did the profile's gates pass?
```

> **A completed carrier testifies only that the carrier ran. It never testifies to what it
> carried.**

The firing case is embarrassingly ordinary: a background wrapper exits `0` because the wrapper
finished, while the harness inside it returned `1` because qualification refused. Any layer
that reports the outermost status as *the* status has laundered a refusal into a pass. Porter
should model these as distinct recorded fields, not teach every caller to rediscover shell
exit-code semantics.

Corollary, and the reason this is binding rather than candidate:

> **Only a fully completed, sealed qualification run may produce promotion evidence. A refused
> or diagnostic run may produce knowledge, but never authority.**

Note the boundary this does *not* cross. Porter does not decide what "qualified" means — the
profile does. Porter enforces the **negative**: it must not emit a sealed qualification receipt
when the declared gate sequence did not complete. That is custody discipline, not standing.

### 11.2 Candidate surfaces (named, non-binding)

**Exact input custody.** Source revision plus tree cleanliness; substrate image digest and
provenance; payload/package digest; harness identity; declared host capabilities. One rule has
teeth: **a digest recorded for previously-fetched mutable upstream bytes must never be reused
to declare newly-fetched bytes.** Upstream `current` images are re-spun in place; the receipt
must name what actually ran, not what once ran.

**Resource-envelope preflight.** A run that cannot satisfy its own declared resource envelope
must refuse **before consuming inputs**. This is not defensive scripting — it is custody: a run
that begins without standing over its resource budget produces misleading partial evidence, and
partial evidence is worse than none because it looks like evidence.

**Fresh-run isolation.** Unique run identity; fresh output directory; previous runs immutable;
no writing a result into an existing path; no manual mutation of a qualifying run; no
resume-until-green. A qualification run is a *single* clean execution from declared inputs, not
a sequence of interactive nudges until the dashboard turns green.

**Refusal as a first-class terminal result.** Not an error, not an absence. A refusal record
should carry: the first authoritative failed gate; gates passed before it; gates never reached;
whether artifacts were preserved; and an explicit statement that **no promotion receipt was
minted.** "Gates not reached" matters — a campaign that stops at gate 6 has said nothing at all
about gates 7-12, and silence there must not read as pass.

**Unsealed diagnostic custody.** Logs, consoles, disk images, and metadata from a refused run
are worth preserving and must be marked **diagnostic, not qualifying** — preserved evidence is
not admitted evidence. The record should also note whether later inspection needs privileged or
potentially mutating operations, because that is a property of the evidence, discovered now and
expensive to rediscover later.

**Read-only postmortem protocol.** Operate on a copy; never mount read-write; suppress
filesystem recovery writes (a plain mount of a dirty filesystem *writes* recovery into the
artifact you are trying to preserve); record each extraction step; keep diagnosis outside the
original artifact. Fingerprint the artifact before and after to prove the postmortem did not
disturb it.

**Diagnostic runs versus qualification runs.** Instrumented, interactive, or partial runs are
legitimate and useful — they reduce unknowns. They **cannot qualify.** After a correction,
qualification requires a clean run from exact declared inputs. Two different objects; one
schema field.

**Correction lineage.** `refused run → diagnosis → corrective change → regression → clean run`.
Preserve **both** histories. A successful run that erases the refusal that forced it has
deleted the only evidence that the guarantee was ever tested. The refused run is not
preliminary noise; it is the hostile evidence.

### 11.3 What profiles own, not Porter

Porter supplies custody, ordering, refusal shape, sealing, and lineage. The **profile** declares
the gates and what passing means. A monitoring product's profile might assert "package hooks
start nothing," "the daemon produces an admitted report," "cross-UID boundary holds"; a
different product's gates would be entirely different — and would reuse every mechanism above
unchanged. If Porter ever grows an opinion about what a gate *means*, it has crossed §10.1.

Sketch of the envelope this implies (shape only, **not** a ratified schema; any of it landing
is additive to `porter.record.v0` and needs deliberate ratification):

```
QualificationRun
├── exact inputs           (revision, digests, harness identity)
├── execution environment  (host, accelerator, declared capabilities)
├── ordered gates          (declared, reached, passed, not-reached)
├── transport outcome      ─┐
├── harness verdict         ├── distinct, never collapsed  (§11.1)
├── qualification verdict  ─┘
├── first refusal          (authoritative failed gate)
├── preserved artifacts    (marked diagnostic vs qualifying)
├── sealing status
└── promotion eligibility  (profile-defined; Porter enforces only the negative)
```

### 11.4 Provenance and firing cases

Recorded from an external VM qualification campaign, 2026-07-19. Not imported doctrine — the
mechanics were rediscovered independently in a hand-rolled harness, which is exactly the signal
that they belong in a courier rather than in each campaign.

Firing cases, all from one run:

- **Verdict layering.** A background wrapper returned `0`; the harness inside returned `1`. The
  artifacts, not the notification, held the verdict.
- **Mutable upstream digest.** The campaign's previously-recorded base-image digest no longer
  matched upstream `current`; declaring the historical digest would have named bytes that never
  ran.
- **Resource-envelope preflight.** The harness demanded 12 GiB free with an 8 GiB scratch cap
  against 14.8 GiB available, and stopped before consuming inputs rather than producing a
  half-run.
- **Preserved-but-unsealed.** The refused run kept its disk image and console logs while
  emitting no result file, no sealed manifest, and no receipt. The obstruction was diagnosable
  later precisely because it was preserved without being credited.
- **Read-only postmortem.** Diagnosis required reading a filesystem left dirty by a killed VM;
  the honest path was a converted copy read without mounting, leaving the original artifact
  byte-identical.

Scope-control anchor, recorded verbatim: *exact inputs, bounded execution, authoritative gates,
honest refusal, preserved obstruction, clean rerun, separately minted promotion.* The product
tells Porter what testimony it needs; Porter makes sure nobody invents the testimony afterward.

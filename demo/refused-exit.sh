#!/bin/sh
# demo/refused-exit.sh
#
# Porter refusal specimen: simulates a dropped connection so the exit code
# is never observed.  Runs entirely in a local tmpdir using a fake-ssh
# shim and a recipe script — no VM, no live host, no real network needed.
# Expected runtime: well under 30 seconds.
#
# Exit code: nonzero.  Porter refused — a refusal must never look like
# process-success, even when the courier machinery itself ran cleanly.
#
# Usage:
#   cd <porter-repo-root>
#   sh demo/refused-exit.sh

set -e

DEMO_TMP="$(mktemp -d)"
cleanup() { rm -rf "$DEMO_TMP"; }
trap cleanup EXIT

# ── fake ssh ──────────────────────────────────────────────────────────────
# Runs scripts locally.  When the script body contains PORTER_TEST_DROP it
# returns without printing the sentinel token, simulating a dropped
# connection.  Porter never observes the exit code → refused.
FAKEBIN="$DEMO_TMP/fakebin"
mkdir -p "$FAKEBIN"
cat > "$FAKEBIN/ssh" << 'FAKESSH'
#!/bin/sh
shift  # discard host arg; remainder is: sh -s
if [ "$1" = "sh" ] && [ "$2" = "-s" ]; then
  _script="$(mktemp)"
  cat > "$_script"
  if grep -q PORTER_TEST_DROP "$_script"; then
    printf 'simulated dropped connection\n' >&2
    rm -f "$_script"
    exit 255
  fi
  sh "$_script"
  _rc=$?
  rm -f "$_script"
  exit "$_rc"
fi
exec sh -c "$*"
FAKESSH
chmod +x "$FAKEBIN/ssh"

# ── recipe ────────────────────────────────────────────────────────────────
# Yields a local ssh substrate (host="fake" → resolved by fakebin/ssh).
# The remote_root lives inside the tmpdir so all filesystem ops are local.
REMOTE_ROOT="$DEMO_TMP/remote"
mkdir -p "$REMOTE_ROOT/work"
RUNS_DIR="$DEMO_TMP/runs"

# Embed REMOTE_ROOT into the recipe script via shell expansion.
cat > "$DEMO_TMP/recipe.sh" << EOF
#!/bin/sh
action="\$1"
if [ "\$action" = "up" ]; then
    printf '{"kind":"vm","transport":"ssh","ephemeral":true,"declared":{"host":"fake","remote_root":"$REMOTE_ROOT","workdir":"$REMOTE_ROOT/work"},"observed":{},"fact_mismatches":[]}\n'
elif [ "\$action" = "down" ]; then
    printf 'down\n'
else
    exit 64
fi
EOF
chmod +x "$DEMO_TMP/recipe.sh"

# ── locate porter ─────────────────────────────────────────────────────────
PORTER="$(cd "$(dirname "$0")/.." && pwd)/porter"

export PATH="$FAKEBIN:$PATH"

printf '=== porter run (connection will be dropped mid-exec) ===\n'

# Capture run_id; porter exits nonzero on refusal.
porter_rc=0
run_id="$(python3 "$PORTER" run \
    --runs-dir "$RUNS_DIR" \
    --target "recipe:$DEMO_TMP/recipe.sh" \
    -- sh -c 'printf "sending...\n"; PORTER_TEST_DROP')" \
    || porter_rc=$?

printf '\n=== porter show %s ===\n' "$run_id"
python3 "$PORTER" show --runs-dir "$RUNS_DIR" "$run_id"

printf '\n=== refusal evidence ===\n'
python3 "$PORTER" show --runs-dir "$RUNS_DIR" "$run_id" \
    | grep -E '"outcome"|"exit_code_observed"|"refusal_reason"' \
    | head -10

printf '\nPorter process exit: %s\n' "$porter_rc"

if [ "$porter_rc" -eq 0 ]; then
    printf 'ERROR: porter must exit nonzero on refusal\n' >&2
    exit 1
fi

exit "$porter_rc"

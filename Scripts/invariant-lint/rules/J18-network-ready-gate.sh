#!/bin/sh
# J18: agent-originated external network work is gated by NetworkReadySignal.
#
# Content Filter activation kills connections opened before the NetworkExtension
# stack settles, and they then stall for the full request timeout. The fix is a
# single boot-time gate, and this rule checks that every agent-originated start
# still goes through it.
#
# Enforced mechanically as five properties:
#   1. the gate seam exists and is the only thing that awaits the signal. An
#      open-coded wait is a second, untestable gate.
#   2. every gate region guards work the invariant's own enumeration names, and
#      that work demonstrably reaches an external-network primitive
#   3. every other call site of an inventoried entry is gated too
#   4. gated work that starts a URLSession but matches nothing the invariant
#      enumerates is reported as unrecognised, never passed
#   5. every release path the signal exposes still has a caller, or gated work
#      would hang for the lifetime of the agent
#
# The inventory is NOT a list in this script. It is discovered by walking out
# from the gate regions, and the vocabulary that decides what counts as gated
# work is parsed out of the invariant bullet in AGENTS.md, the document the
# team already maintains when this architecture changes. Rename a seam and the
# rule follows it; delete the enumeration and the rule says so instead of
# quietly checking nothing.
#
# EDITING THAT BULLET EDITS THIS LINT. Its parenthetical, "(initial update
# check, blocklist scheduler/force refresh)", is this rule's vocabulary, not
# prose. A call inside a gate region counts as gated work when its name shares
# at least two words with that parenthetical, and that threshold is the whole
# reason `startBlocklistScheduler` and `forceBlocklistUpdateResult` are
# recognised while `reloadBlocklist`, `flushCache` and `error`, in the same
# regions, are not. Narrow the wording and real work stops being
# recognised; widen it and bystanders get dragged in. After changing the bullet,
# run `J18_INVENTORY=1 Scripts/invariant-lint/run.sh J18` and confirm the
# discovered inventory still names every start you expect it to.
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J18 network-ready gate" "Agent-originated external network work"

AGENT_DIR="$REPO_ROOT/Sources/MacDNSAgent"
INV="$LINT_TMP.inventory"
trap 'rm -f "$LINT_TMP" "$LINT_ERR" "$INV"' EXIT HUP INT TERM

if [ ! -d "$AGENT_DIR" ]; then
    report "$AGENT_DIR" 0 "the agent target is missing; the invariant's subject moved"
    rule_end
fi

AGENT_SWIFT=$(swift_files "$AGENT_DIR")
assert_plain_paths "$AGENT_SWIFT"
if [ -z "$AGENT_SWIFT" ]; then
    report "$AGENT_DIR" 0 "no Swift source in the agent target; the rule checked nothing"
    rule_end
fi

# The enumeration of gated work lives in the invariant bullet, not here. A
# bullet that stops enumerating anything is a finding: the rule would otherwise
# still run and still report `ok` while recognising no work at all.
TOKENS=$(awk -v anchor="$RULE_ANCHOR" -f "$LINT_DIR/lib/J18-doc-inventory.awk" "$AGENTS_MD" 2>"$LINT_ERR") ||
    rule_error "documented-inventory scanner failed"
: >"$LINT_ERR"
if [ -z "$TOKENS" ]; then
    report "$AGENTS_MD" 0 \
        "the invariant bullet no longer enumerates which agent-originated network work is gated; J18 has no inventory to enforce"
    rule_end
fi

lint_awk -v tokens="$TOKENS" -v scope="$AGENT_DIR" -v inventory_out="$INV" \
    -f "$AWKLIB" -f "$LINT_DIR/lib/J18-network-gate.awk" $AGENT_SWIFT
report_stream "network-ready gate"

# The discovered table, on request. Written to a file rather than stderr because
# lint_awk reserves a scanner's stderr for crash diagnostics.
if [ -n "${J18_INVENTORY:-}" ] && [ -s "$INV" ]; then
    cat "$INV"
fi

rule_end

#!/bin/sh
# J19: override / forward-zone policy lives in memory in the Rust resolver, so
# `state.json` is only authoritative while something replays it. That something
# is `applyOverridesAndZonesToModule()`, on both paths that can make the module's
# copy stale: `startServices()` (the module is new and empty) and
# `saveFullConfig()` (the file just changed under a running module).
#
# Drop either replay and nothing fails loudly: the resolver keeps answering from
# whatever policy it still holds, and the divergence from state.json is only
# visible as a wrong answer.
#
# The save path hands the replay to the transaction as a closure instead of
# calling it, so the rule follows that indirection rather than demanding a
# literal call:
#   1. the replay itself still publishes a snapshot to the module
#   2. startServices() replays
#   3. some saveFullConfig* function binds the replay to a transaction parameter
#   4. that parameter is declared as a `-> Bool` step and is actually invoked
# The parameter name is read off the binding rather than hardcoded, so renaming
# it cannot quietly disarm checks 3 and 4.
#
# Deliberately NOT enforced:
#   - that every return path replays. `startServices()` returns early when the
#     resolver is already running and reconciliation is not needed; which paths
#     need a replay is a control-flow property, not a source one.
#   - the atomic-publication half of the same invariant (ArcSwap in policy.rs).
#     That is a Rust-side property with its own subject.
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J19 policy replay" "replays it on every"

AGENT="$REPO_ROOT/Sources/MacDNSAgent/MacDNSAgent.swift"
require_file "$AGENT" || rule_end

J19_BIND="$LINT_TMP.bind"
trap 'rm -f "$LINT_TMP" "$LINT_ERR" "$J19_BIND"' EXIT HUP INT TERM

REPLAY='applyOverridesAndZonesToModule'
BIND_RE="[A-Za-z_][A-Za-z0-9_]*[ ]*:[ ]*$REPLAY[ ]*[(]from:[ ]*[)]"

# 1. The replay still publishes into the module. Without this anchor the rule
#    would keep passing on a replay that had been hollowed out.
require_region_present "$AGENT" "func[ ]+$REPLAY[ ]*[(]" 'applyPolicySnapshot[ ]*[(]' \
    "the replay no longer publishes a policy snapshot to the resolver module"

# 2. Start replays: the module comes up empty, so state.json has to be replayed
#    into it before it answers.
require_region_present "$AGENT" 'func[ ]+startServices[ ]*[(]' "$REPLAY[ ]*[(]" \
    "startServices no longer replays state.json overrides and zones into the module"

# 3. Save binds the replay into the transaction. Any function in the
#    saveFullConfig family may hold it, since the split between the XPC entry
#    point and the locked transaction body is implementation detail.
require_any_region_present "$AGENT" 'func[ ]+saveFullConfig' "$BIND_RE" \
    "no saveFullConfig function binds the replay into the config transaction"

# 4. The bound step is declared and invoked. A binding nothing calls is a replay
#    that never runs.
lint_awk -v re="$BIND_RE" -f "$AWKLIB" -f "$GREP_CODE_AWK" "$AGENT"
cp "$LINT_TMP" "$J19_BIND"
lint_awk -F"$TAB" '
    NR == 1 && match($3, /[A-Za-z_][A-Za-z0-9_]*[ \t]*:[ \t]*applyOverridesAndZonesToModule/) {
        label = substr($3, RSTART, RLENGTH)
        sub(/[ \t]*:.*/, "", label)
        print label
    }
' "$J19_BIND"
LABEL=$(sed -n '1p' "$LINT_TMP")

if [ -z "$LABEL" ]; then
    report "$AGENT" 1 \
        "the replay is not bound to a transaction step; checks 3 and 4 have lost their subject"
else
    require_present "$AGENT" "$LABEL[ ]*:[ ]*[(][^)]*[)][ ]*->[ ]*Bool" \
        "the transaction no longer declares $LABEL as a step; the bound replay has no parameter to run as"
    require_present "$AGENT" "$LABEL[ ]*[(]" \
        "$LABEL is bound but never invoked; the save path would commit without replaying state.json"
fi

rule_end

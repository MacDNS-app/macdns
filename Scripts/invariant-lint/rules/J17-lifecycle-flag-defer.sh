#!/bin/sh
# J17: a lifecycle transition flag set to `true` must be cleared by a
# function-scoped `defer`. Without it, any early return or thrown error leaves
# the flag raised and every later start/stop is refused as "already in progress":
# the services are stuck until the agent is restarted.
#
# Scope is the agent target, which owns service lifecycle. The flags are
# discovered from their declarations (lib/J17-flag-decl.awk), never listed here,
# so a new guard is linted from the moment it is declared.
#
# A `defer` counts only at the function body's own top level. Nested inside a
# closure it fires when the closure returns, not when the function does. The
# reset itself may sit anywhere inside the defer body, which is what makes the
# agent's `defer { finishLifecycleTransition { flag = false } }` legal.
#
# Deliberately NOT enforced:
#   - the relative source position of the assignment and its defer. Swift
#     registers a defer when execution reaches it, so whether an early return
#     between the two leaks the flag is a control-flow property, not a
#     source-order one.
#   - App-side progress flags (`isLoadingLicense`, `isUpdatingBlocklist`). They
#     are cleared in async completion handlers by design and gate a spinner, not
#     a service transition.
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J17 lifecycle flag defer" "defer { flag = false }"

AGENT_DIR="$REPO_ROOT/Sources/MacDNSAgent"
if [ ! -d "$AGENT_DIR" ]; then
    report "$AGENT_DIR" 0 "the agent target is missing; the lifecycle flags moved"
    rule_end
fi

STATS="$LINT_TMP.stats"
trap 'rm -f "$LINT_TMP" "$LINT_ERR" "$STATS"' EXIT HUP INT TERM

SWIFT=$(swift_files "$AGENT_DIR")
assert_plain_paths "$SWIFT"
if [ -z "$SWIFT" ]; then
    report "$AGENT_DIR" 0 "no Swift sources in the agent target; the rule has lost its subject"
    rule_end
fi

# 1. Discover the flags.
lint_awk -f "$AWKLIB" -f "$LINT_DIR/lib/J17-flag-decl.awk" $SWIFT
FLAGS=$(cut -f3 <"$LINT_TMP" | sort -u | tr '\n' '|' | sed 's/|$//')
if [ -z "$FLAGS" ]; then
    report "$AGENT_DIR" 0 \
        "no lifecycle transition flag declared in the agent; the rule has lost its subject"
    rule_end
fi

# 2. Pair every `= true` with a function-scoped defer reset.
: >"$STATS"
lint_awk -v flags="$FLAGS" -v stats_out="$STATS" \
    -f "$AWKLIB" -f "$LINT_DIR/lib/J17-flag-defer.awk" $SWIFT
report_stream "lifecycle flag"

# 3. Non-vacuity: a run that paired nothing and found nothing checked nothing.
#    Flags exist but are never raised means the guards were rewritten into a
#    shape this rule no longer recognises.
ASSIGNMENTS=$(cut -d' ' -f1 <"$STATS")
PAIRS=$(cut -d' ' -f2 <"$STATS")
if [ -z "$ASSIGNMENTS" ]; then
    rule_error "the flag pairing scanner produced no summary"
fi
if [ "$ASSIGNMENTS" -eq 0 ] && [ "$VIOLATIONS" -eq 0 ]; then
    report "$AGENT_DIR" 0 \
        "flags [$FLAGS] are declared but never set true; the transition guards moved to a shape this rule does not recognise"
fi
if [ "$PAIRS" -eq 0 ] && [ "$VIOLATIONS" -eq 0 ]; then
    report "$AGENT_DIR" 0 \
        "no flag/defer pairing was verified; the rule would have passed vacuously"
fi

rule_end

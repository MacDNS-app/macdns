#!/bin/sh
# J20: the resolver dylib is opened once per agent lifetime and never released.
#
# The signing half of this invariant (`--options runtime`, matching team
# identity) is enforced by `verify_signing` in Sources/MacDNS/Makefile, which is
# the only place it CAN be enforced: it needs signed artifacts that only
# `make release` produces. This rule covers the half that check cannot reach,
# whose failure is not a bad build but a crash on the next `start()`, on a
# machine that already shipped.
#
# Enforced mechanically as four properties:
#   1. exactly one `dlopen` in the agent target
#   2. its result is stored in a `var` property that outlives the call, not in a
#      local that dies with it
#   3. that call is preceded by a `<handle> == nil` early exit, so calling the
#      loader twice loads the dylib once
#   4. no `dlclose` anywhere, and the handle is never assigned `nil`
#
# Property 4 is deliberately stated over the handle rather than over `stop()` by
# name: clearing the handle anywhere defeats property 3 just as thoroughly, and
# a rule keyed on a method name stops enforcing the moment that method is
# renamed. When the offending assignment does sit inside a `stop`-prefixed
# method, the message says so, because that is the case AGENTS.md calls out.
#
# Nothing here is a name list. The handle property is discovered by following
# what the `dlopen` result is stored into, so renaming it needs no lint change.
#
# Scope limits, stated plainly:
#   - `dlsym` is NOT counted. Resolving further FFI symbols from an already open
#     handle is the whole point of keeping it; new entrypoints are free to add
#     lookups and this rule stays green.
#   - only Sources/MacDNSAgent/** is scanned. A `dlopen` in the App or an
#     extension is a different concern and a different invariant.
#   - the handle-clearing scan is limited to the file that owns the handle,
#     because `handle = nil` is an ordinary statement elsewhere in a codebase.
#
# Run with J20_HANDLE=1 to print what the scanner discovered.
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J20 dylib handle lifetime" "loaded once per agent lifetime"

AGENT_DIR="$REPO_ROOT/Sources/MacDNSAgent"
DUMP="$LINT_TMP.handle"
trap 'rm -f "$LINT_TMP" "$LINT_ERR" "$DUMP"' EXIT HUP INT TERM

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

lint_awk -v scope="$AGENT_DIR" -v dump_out="$DUMP" \
    -f "$AWKLIB" -f "$LINT_DIR/lib/J20-dylib-handle.awk" $AGENT_SWIFT
report_stream "dylib handle"

# Written to a file rather than stderr because lint_awk reserves a scanner's
# stderr for crash diagnostics.
if [ -n "${J20_HANDLE:-}" ] && [ -s "$DUMP" ]; then
    cat "$DUMP"
fi

rule_end

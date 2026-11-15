#!/bin/sh
# J10: SCDynamicStore callbacks may only enqueue async reload work; calling
# SCDynamicStore* synchronously from the callback can deadlock or reenter configd.
#
# Every SCDynamicStore callback body (an inline closure argument of
# SCDynamicStoreCreate, or a typed SCDynamicStoreCallBack constant) must:
#   - contain at least one enqueue/signal statement
#   - contain nothing else at its own top level beyond the allowlist
#   - never call an SCDynamicStore* function synchronously
#
# Work nested inside `.async { }` / `Task { }` is not part of the callback and is
# not restricted. That is the hand-off the invariant demands.
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J10 scdynamicstore callback" "callbacks must only enqueue async reload work"

# Statements allowed at a callback's top level:
#   Unmanaged</fromOpaque/takeUnretainedValue  recovering `self` from the C info
#                                              pointer, unavoidable boilerplate
#   enqueue* / .async / .signal / Task {       the hand-off itself
ALLOW='enqueue|[.]async|[.]asyncAfter|Unmanaged<|fromOpaque|takeUnretainedValue|[.]signal[(]|Task[ ]*[{]'
REQUIRE='enqueue|[.]async|[.]signal[(]|Task[ ]*[{]'
DENY='SCDynamicStore[A-Za-z]*[(]|[.]sync[ ]*[{]|[.]sync[(]|sleep[(]|[.]wait[(]'
ESCAPE='[.]async|Task[ ]*[{]'
CALL='SCDynamicStoreCreate[ ]*[(]'
ASSIGN='SCDynamicStoreCallBack[ ]*='

for file in \
    "$REPO_ROOT/Sources/MacDNSAgent/Services/NetworkMonitor.swift" \
    "$REPO_ROOT/Sources/DNSProxyExtension/DNSProxyProvider.swift"; do
    require_file "$file" || continue
    callback_scan "$file" "SCDynamicStore callback" \
        -v call_re="$CALL" -v assign_re="$ASSIGN" \
        -v allow_re="$ALLOW" -v require_re="$REQUIRE" \
        -v deny_re="$DENY" -v escape_re="$ESCAPE"
done

# No other file may register an SCDynamicStore callback without being linted
# here: a new call site is a violation until it is added to the loop above.
SWIFT=$(swift_files "$REPO_ROOT/Sources")
assert_plain_paths "$SWIFT"
lint_awk -v re="$CALL|$ASSIGN" \
    -v skip='/NetworkMonitor[.]swift$|/DNSProxyProvider[.]swift$' \
    -f "$AWKLIB" -f "$GREP_CODE_AWK" $SWIFT
report_stream "SCDynamicStore callback registered in a file this rule does not lint"

rule_end

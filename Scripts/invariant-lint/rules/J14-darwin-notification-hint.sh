#!/bin/sh
# J14: Darwin notifications are unauthenticated wake-up hints only: they may
# enqueue health evaluation but never directly change bypass, readiness, or
# displayed state.
#
# Every CFNotificationCenterAddObserver callback body must:
#   - contain at least one signal/enqueue statement
#   - contain nothing else at its own top level beyond the allowlist
#   - never assign interception, readiness, or display state, and never drive
#     bypass or service lifecycle directly
#
# Work nested inside `.async { }` / `Task { }` is not part of the callback: it
# runs after the hint has been handed off, which is the required shape.
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J14 darwin notification hint" "Darwin notifications are unauthenticated wake-up hints only"

# Allowed at a callback's top level:
#   Unmanaged</fromOpaque/takeUnretainedValue  recovering the observer from the C
#                                              info pointer, unavoidable
#   signal*/enqueue/.async/Task {              the hand-off itself
ALLOW='Unmanaged<|fromOpaque|takeUnretainedValue|signal[A-Za-z]*[(]|[.]signal[(]|enqueue|[.]async|[.]asyncAfter|Task[ ]*[{]'
REQUIRE='signal[A-Za-z]*[(]|[.]signal[(]|enqueue|[.]async|Task[ ]*[{]'
# Forbidden: direct state mutation and direct control-plane action.
DENY='(bypass|isBypassed|bypassReason|interception|isIntercepting|providerState|protectionState|isProtectionActive|statusMessage|headline|iconName|servicesRunning|extensionActive|isReady|readiness)[A-Za-z]*[ ]*=[^=]|setBypass[(]|bypassEnable[(]|bypassDisable[(]|startServices[(]|stopServices[(]|stopProxy[(]|proxyEnable[(]|proxyDisable[(]'
ESCAPE='[.]async|Task[ ]*[{]'
CALL='CFNotificationCenterAddObserver[ ]*[(]'

for file in \
    "$REPO_ROOT/Sources/MacDNS/ViewModels/AppViewModel.swift" \
    "$REPO_ROOT/Sources/DNSProxyExtension/DNSProxyProvider.swift"; do
    require_file "$file" || continue
    callback_scan "$file" "Darwin notification callback" \
        -v call_re="$CALL" -v allow_re="$ALLOW" -v require_re="$REQUIRE" \
        -v deny_re="$DENY" -v escape_re="$ESCAPE"
done

# A Darwin observer registered anywhere else is unlinted, hence a violation until
# its file is added to the loop above.
SWIFT=$(swift_files "$REPO_ROOT/Sources")
assert_plain_paths "$SWIFT"
lint_awk -v re="$CALL" \
    -v skip='/AppViewModel[.]swift$|/DNSProxyProvider[.]swift$' \
    -f "$AWKLIB" -f "$GREP_CODE_AWK" $SWIFT
report_stream "Darwin observer registered in a file this rule does not lint"

rule_end

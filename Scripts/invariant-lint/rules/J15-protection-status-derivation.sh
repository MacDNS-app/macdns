#!/bin/sh
# J15: provider interception state reaches the App only inside the agent's
# runtime snapshot; when the provider cannot be queried the agent reports
# `unknown`. Never guess `intercepting` from `NEDNSProxyManager.isEnabled`.
#
# The user-visible consequence is that "Active" is a derived value. Enforced
# mechanically as five properties:
#   1. the "Active" wording exists only in ProtectionStatusPolicy
#   2. `providerState = .intercepting` is decided in exactly one place, from the
#      agent's reported interception state
#   3. no line derives interception from an `isEnabled` flag
#   4. the App's status message is assigned from the policy, not composed locally
#   5. positive anchors: the policy still derives .active from .intercepting
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J15 protection status derivation" "never guess"

POLICY="$REPO_ROOT/Sources/Shared/ProtectionStatusPolicy.swift"
DISPLAY="$REPO_ROOT/Sources/Shared/ProtectionDisplayState.swift"
PRESENTATION="$REPO_ROOT/Sources/MacDNS/ViewModels/RuntimeStatePresentationPolicy.swift"
VIEWMODEL="$REPO_ROOT/Sources/MacDNS/ViewModels/AppViewModel.swift"
require_file "$POLICY" || rule_end
require_file "$DISPLAY" || rule_end
require_file "$PRESENTATION" || rule_end
require_file "$VIEWMODEL" || rule_end

SWIFT=$(swift_files "$REPO_ROOT/Sources")
assert_plain_paths "$SWIFT"

# 1. Only the policy may spell the active state.
#
# Allowlist, one entry:
#   extensionActive  OverviewSection's system-extension activation label
#                    ("Active" for the installed sysext while the DNS Proxy is on),
#                    which is not protection status. Keyed on `extensionActive`,
#                    the flag and the HealthRowsPolicy case that render it.
lint_awk -v re='"Active"|"Protection Active"' \
    -v allow='extensionActive' \
    -v skip='/ProtectionStatusPolicy[.]swift$' \
    -f "$AWKLIB" -f "$GREP_CODE_AWK" $SWIFT
report_stream "protection status wording outside ProtectionStatusPolicy"

# 2. Interception is decided once, in the presentation policy.
lint_awk -v re='providerState[ ]*=[ ]*[.]intercepting' \
    -v skip='/RuntimeStatePresentationPolicy[.]swift$' \
    -f "$AWKLIB" -f "$GREP_CODE_AWK" $SWIFT
report_stream "interception decided outside RuntimeStatePresentationPolicy"

# 3. `isEnabled` describes user intent, never observed interception.
lint_awk -v re='isEnabled' -v also='intercept' \
    -f "$AWKLIB" -f "$GREP_CODE_AWK" $SWIFT
report_stream "interception derived from an isEnabled flag"

# 4/5. Positive anchors: the derivation chain must still be in place.
require_present "$PRESENTATION" 'proxyInterceptionState' \
    "the presentation policy no longer reads the agent's reported interception state"
require_present "$POLICY" 'case[ ]+[.]intercepting' \
    "the policy no longer branches on the provider's intercepting state"
# `.active` must be produced by the `.intercepting` branch, checked as "before
# the next case label", which is where the branch's body lives.
if ! lint_awk_test '
        /case[ ]+[.]intercepting/                                  { armed = 1 }
        armed && !/case[ ]+[.]intercepting/ && /case[ ]+[.]/        { armed = 0 }
        armed && /[.]active/                                       { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$POLICY"; then
    report "$POLICY" 1 "the policy no longer derives .active from the .intercepting branch"
fi
require_present "$DISPLAY" 'statusPolicy' \
    "ProtectionDisplayState no longer delegates to ProtectionStatusPolicy"
require_present "$VIEWMODEL" 'statusMessage[ ]*=[ ]*protectionDisplayState[.]statusPolicy[.]statusMessage' \
    "the App no longer takes its status message from the policy"

rule_end

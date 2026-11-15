#!/bin/sh
# J12: never re-add a libproc / proc_* endpoint validator to the proxy-control
# plane: the NE sandbox denies those calls, so the validator fails closed and the
# provider stays in permanent bypass.
#
# Scope is the proxy-control plane and the NSXPC endpoint plumbing around it.
# The flow-source process validators are deliberately OUT of scope by
# construction, because the invariant they implement is the opposite one:
#   Sources/DNSProxyExtension/DNSProxyProcessValidator.swift
#   Sources/ContentFilterExtension/ContentFilterProcessValidator.swift
#       Content Filter / DNS Proxy must allow MacDNS's own binaries by executable
#       path, resolved with proc_pidpath from the flow's audit token.
#   Sources/MacDNS/Services/DNSProxyProviderProcessInspector.swift
#       Runs inside the unsandboxed App, where libproc is available.
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J12 no libproc control plane" "Never re-add a libproc"

CONTROL_PLANE=$(
    find "$REPO_ROOT/Sources" -type f -name 'ProxyControl*.swift'
    find "$REPO_ROOT/Sources" -type f -name 'MacDNSXPCProtocol.swift'
    find "$REPO_ROOT/Sources" -type f -name 'CodeSignValidator.swift'
    find "$REPO_ROOT/Sources" -type f -name 'XPCClient.swift'
    find "$REPO_ROOT/Sources/MacDNSAgent" -type f -name 'EntryPoint.swift'
)
CONTROL_PLANE=$(printf '%s\n' "$CONTROL_PLANE" | sort -u)
assert_plain_paths "$CONTROL_PLANE"

# Positive anchor: the scope must still resolve to the control-plane sources.
COUNT=$(printf '%s\n' "$CONTROL_PLANE" | grep -c 'swift$')
if [ "$COUNT" -lt 6 ]; then
    report "$REPO_ROOT/AGENTS.md" 0 \
        "only $COUNT control-plane file(s) found; the rule's scope no longer matches the sources"
    rule_end
fi

# libproc, PID-based identity, and kernel process lookups are all banned here.
# `auditToken` itself is the sanctioned mechanism and is not matched.
code_scan "libproc / PID-based endpoint validation in the proxy-control plane" \
    '(^|[^A-Za-z0-9_])proc_[a-z_]+|libproc|kinfo_proc|KERN_PROC|audit_token_to_pid|processIdentifier|SecCodeCreateWithPID' \
    $CONTROL_PLANE

rule_end

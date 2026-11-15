#!/bin/sh
# J11: XPC security uses the audit token via CodeSignValidator; never bypass it,
# never use kSecCSStrictValidate.
#
# Enforced mechanically as four properties:
#   1. the validator identifies the peer from its audit token
#   2. kSecCSStrictValidate appears nowhere in code
#   3. every NSXPCListener delegate validates the peer's code signature
#   4. no listener accepts a connection unconditionally
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J11 xpc audit token" "XPC security uses audit token via"

VALIDATOR="$REPO_ROOT/Sources/MacDNSAgent/Utilities/CodeSignValidator.swift"
require_file "$VALIDATOR" || rule_end

SWIFT=$(swift_files "$REPO_ROOT/Sources")
assert_plain_paths "$SWIFT"

# 1. Peer identity comes from the audit token, not from a PID or a name.
require_present "$VALIDATOR" 'kSecGuestAttributeAudit' \
    "the validator no longer identifies the peer by audit token"
require_present "$VALIDATOR" 'SecCodeCopyGuestWithAttributes' \
    "the validator no longer resolves the peer's dynamic code object"
require_present "$VALIDATOR" 'xpc_connection_get_audit_token' \
    "the validator no longer reads the connection's audit token"

# 2. kSecCSStrictValidate is banned outright. Comments are stripped before
#    matching, so a comment that names it is not a violation.
code_scan "kSecCSStrictValidate breaks valid apps with dynamic libraries and is banned" \
    'kSecCSStrictValidate' $SWIFT

# 3/4. Every shouldAcceptNewConnection implementation must validate the peer.
#      Two accepted mechanisms: CodeSignValidator (agent listener) or the
#      NSXPCConnection code-signing requirement (proxy-control listener, which
#      runs inside the NE sandbox where CodeSignValidator's Security calls fail).
lint_awk -v re='func[ ]+.*shouldAcceptNewConnection|shouldAcceptNewConnection newConnection' \
    -f "$AWKLIB" -f "$GREP_CODE_AWK" $SWIFT
LISTENERS=$(cut -f1 <"$LINT_TMP" | sort -u)

if [ -z "$LISTENERS" ]; then
    report "$VALIDATOR" 1 "no NSXPCListener delegate found; this rule has lost its subject"
fi

for listener in $LISTENERS; do
    require_present "$listener" \
        'CodeSignValidator|setCodeSigningRequirement|setConnectionCodeSigningRequirement' \
        "an XPC listener delegate accepts connections without code-sign validation"
done

rule_end

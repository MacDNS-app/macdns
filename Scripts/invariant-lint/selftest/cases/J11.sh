# J11 — XPC security uses the audit token via CodeSignValidator; never bypass it,
# never use kSecCSStrictValidate.

VALIDATOR=Sources/MacDNSAgent/Utilities/CodeSignValidator.swift

begin "J11 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'XPC security uses audit token via'
expect J11 fail "no longer in AGENTS.md"

begin "J11 catches kSecCSStrictValidate in code"
add "$VALIDATOR" 'let flags = kSecCSStrictValidate'
expect J11 fail "kSecCSStrictValidate breaks valid apps"

# Comments are stripped before matching, so the note explaining why the flag is
# never used does not fail the rule that bans it.
begin "J11 does not flag kSecCSStrictValidate inside a comment"
add "$VALIDATOR" '// kSecCSStrictValidate is deliberately not used here'
expect J11 ok

begin "J11 catches identity taken from a PID instead of the audit token"
swap "$VALIDATOR" 'var token = xpc_connection_get_audit_token(connection)' \
    '        let pid = connection.processIdentifier'
expect J11 fail "no longer reads the connection's audit token"

begin "J11 catches a listener delegate that accepts without validation"
put Sources/MacDNSAgent/Services/SecondListener.swift \
    'func listener(_ l: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool { c.resume(); return true }'
expect J11 fail "accepts connections without code-sign validation"

begin "J11 fails when the validator stops using the audit token attribute"
drop "$VALIDATOR" 'kSecGuestAttributeAudit'
expect J11 fail "no longer identifies the peer by audit token"

# J17 — a lifecycle transition flag set to `true` must be cleared by a
# function-scoped `defer`, or the first error path leaves services stuck.

AGENT=Sources/MacDNSAgent/MacDNSAgent.swift
BOUNCE=Sources/MacDNSAgent/Services/ProxyBounceCoordinator.swift

# j17_bounce <defer-line> — a second agent file carrying its own transition
# guard, to prove the rule scopes itself to the agent target rather than to a
# list of files it already knows about. The caller supplies the line that resets
# the flag, which is the only difference between the green and red versions.
j17_bounce() {
    put "$BOUNCE" 'import Foundation'
    add "$BOUNCE" 'final class ProxyBounceCoordinator {'
    add "$BOUNCE" '    private let lock = NSLock()'
    add "$BOUNCE" '    private var isBouncingProxy = false'
    add "$BOUNCE" ''
    add "$BOUNCE" '    func bounce() -> Bool {'
    add "$BOUNCE" '        lock.withLock { isBouncingProxy = true }'
    add "$BOUNCE" "$1"
    add "$BOUNCE" '        guard reconnect() else { return false }'
    add "$BOUNCE" '        return true'
    add "$BOUNCE" '    }'
    add "$BOUNCE" ''
    add "$BOUNCE" '    private func reconnect() -> Bool { true }'
    add "$BOUNCE" '}'
}

begin "J17 is green on the compliant fixture"
expect J17 ok

begin "J17 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'defer { flag = false }'
expect J17 fail "no longer in AGENTS.md"

begin "J17 catches a start guard raised without a defer reset"
swap "$AGENT" 'finishLifecycleTransition { isStartingServices = false }' \
    '            finishLifecycleTransition { }'
expect J17 fail "isStartingServices"

begin "J17 does not accept a reset written only in a log string"
swap "$AGENT" 'finishLifecycleTransition { isStartingServices = false }' \
    '            AgentLogger.shared.debug("isStartingServices = false")'
expect J17 fail "isStartingServices"

begin "J17 ignores a true assignment written only in a log string"
j17_bounce '        AgentLogger.shared.debug("bouncing")'
swap "$BOUNCE" 'lock.withLock { isBouncingProxy = true }' \
    '        AgentLogger.shared.debug("isBouncingProxy = true")'
expect J17 ok

begin "J17 catches a stop guard raised without a defer reset"
drop "$AGENT" 'finishLifecycleTransition { isStoppingServices = false }'
expect J17 fail "isStoppingServices"

# The reset may sit anywhere inside the defer body, including inside a closure
# the defer hands to a lock helper — that is the shape the agent uses.
begin "J17 accepts a reset nested inside the defer body"
swap "$AGENT" 'lifecycleLock.withLock { isRestoringServices = false }' \
    '            finishLifecycleTransition { lifecycleLock.withLock { isRestoringServices = false } }'
expect J17 ok

begin "J17 accepts a new agent guard that defers its reset"
j17_bounce '        defer { lock.withLock { isBouncingProxy = false } }'
expect J17 ok

begin "J17 catches a new agent guard that never resets"
j17_bounce '        AgentLogger.shared.debug("bouncing")'
expect J17 fail "isBouncingProxy"

# A defer inside a closure fires when the closure returns, not when the function
# does, so it does not protect the early returns that follow it.
begin "J17 catches a reset deferred inside a closure instead of the function"
j17_bounce '        lock.withLock { defer { isBouncingProxy = false } }'
expect J17 fail "isBouncingProxy"

# Mode flags are excluded by shape, not by an exemption list: the same
# assignment becomes a finding as soon as the flag is named like a transition
# guard.
begin "J17 catches a renamed mode flag that now reads as a transition guard"
swap "$AGENT" 'private var isInForwardingMode = false' \
    '    private var isEnteringForwarding = false'
swap "$AGENT" 'isInForwardingMode = true' \
    '            isEnteringForwarding = true'
expect J17 fail "isEnteringForwarding"

begin "J17 catches a flag raised outside any function body"
put Sources/MacDNSAgent/Services/GlobalGate.swift 'var isSyncingLists = false'
add Sources/MacDNSAgent/Services/GlobalGate.swift \
    'let primed = { () -> Bool in isSyncingLists = true; return true }()'
expect J17 fail "outside any function body"

begin "J17 fails when the transition guards stop being raised"
drop "$AGENT" 'isStartingServices = true'
drop "$AGENT" 'isStoppingServices = true'
drop "$AGENT" 'isRestoringServices = true'
expect J17 fail "declared but never set true"

begin "J17 fails when no transition guard is declared at all"
drop "$AGENT" 'private var isStartingServices = false'
drop "$AGENT" 'private var isStoppingServices = false'
drop "$AGENT" 'private var isRestoringServices = false'
expect J17 fail "no lifecycle transition flag declared"

# The flag set is discovered by a scanner, so a crash there would leave the rule
# with an empty set — which must not read as "every flag is paired".
begin "J17 reports a crashed scanner as an error, never as a finding"
broken=$(clone_lint broken-awk-j17)
printf '\nfunction il_reserved(s, close) { return s }\n' >>"$broken/lib/awklib.awk"
expect_in "$broken" J17 error "scanner failed" "FAIL"

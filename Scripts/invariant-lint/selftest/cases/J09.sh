# J09 — handleNewFlow always returns true; the hot path keeps pthread_rwlock and
# stays clear of configd and Network.framework.

PROVIDER=Sources/DNSProxyExtension/DNSProxyProvider.swift

begin "J09 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'handleNewFlow'
expect J09 fail "no longer in AGENTS.md"

begin "J09 catches a false return from handleNewFlow"
swap "$PROVIDER" 'forwardOverSockets(flow, servers: state.snapshot())' '            return false'
expect J09 fail "handleNewFlow must always return true"

begin "J09 catches configd work on the flow hot path"
swap "$PROVIDER" 'let endpoint = udpFlow.localEndpoint as? NWHostEndpoint' \
    '        _ = SCDynamicStoreCopyValue(store, dnsKey)'
expect J09 fail "configd / Network.framework work on the flow hot path"

begin "J09 catches a lock-type change on the query hot path"
swap "$PROVIDER" 'private var servers: [String] = []' '    private let extra = NSLock()'
expect J09 fail "lock type changed on the query hot path"

begin "J09 catches the reader lock being dropped"
swap "$PROVIDER" 'pthread_rwlock_rdlock(&lock)' '        lock.lock()'
expect J09 fail "no longer takes a read lock"

begin "J09 catches Network.framework anywhere in the extension"
add Sources/DNSProxyExtension/ProxyControlListener.swift 'let monitor = NWPathMonitor()'
expect J09 fail "Network.framework symbol in the DNS Proxy"

# NWHostEndpoint is a NetworkExtension type, not Network.framework: J09's only
# allowlist entry, carved out of the NW* sweep rather than loosening it.
begin "J09 does not flag NWHostEndpoint"
add Sources/DNSProxyExtension/ProxyControlListener.swift 'let peer = flow.remoteEndpoint as? NWHostEndpoint'
expect J09 ok

begin "J09 fails when configd access leaves the dedicated worker"
drop "$PROVIDER" 'store = SCDynamicStoreCreate('
expect J09 fail "ConfigurationWorker no longer owns SCDynamicStore access"

# J10 — SCDynamicStore callbacks may only enqueue async reload work.

MONITOR=Sources/MacDNSAgent/Services/NetworkMonitor.swift
HANDOFF='monitor.queue.async { _ = SCDynamicStoreCopyValue(monitor.store, monitor.dnsKey) }'

begin "J10 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'callbacks must only enqueue async reload work'
expect J10 fail "no longer in AGENTS.md"

begin "J10 catches a synchronous configd call in the callback"
swap "$MONITOR" "$HANDOFF" '                _ = SCDynamicStoreCopyValue(monitor.store, monitor.dnsKey)'
expect J10 fail "forbidden in a callback body"

# Statements before and after a hand-off still run on the callback thread.
begin "J10 still catches a sync call written before a single-line hand-off"
swap "$MONITOR" "$HANDOFF" \
    '                _ = SCDynamicStoreCopyValue(monitor.store, monitor.dnsKey); monitor.queue.async { }'
expect J10 fail "forbidden in a callback body"

begin "J10 catches a sync call after a single-line hand-off"
swap "$MONITOR" "$HANDOFF" \
    '                monitor.queue.async { }; _ = SCDynamicStoreCopyValue(monitor.store, monitor.dnsKey)'
expect J10 fail "forbidden in a callback body"

begin "J10 catches a sync suffix after nested braces and a string brace"
swap "$MONITOR" "$HANDOFF" \
    '                monitor.queue.async { if ready { print("}") } }; _ = SCDynamicStoreCopyValue(monitor.store, monitor.dnsKey)'
expect J10 fail "forbidden in a callback body"

begin "J10 catches a sync suffix when a multiline hand-off closes"
swap "$MONITOR" "$HANDOFF" '                monitor.queue.async {'
swap "$MONITOR" '            },' \
    '                }; _ = SCDynamicStoreCopyValue(monitor.store, monitor.dnsKey) },'
expect J10 fail "forbidden in a callback body"

begin "J10 catches ordinary work after a single-line hand-off"
swap "$MONITOR" "$HANDOFF" '                monitor.queue.async { }; monitor.reload()'
expect J10 fail "statement is not an allowed signal/enqueue form"

begin "J10 accepts nested and string braces inside a hand-off"
swap "$MONITOR" "$HANDOFF" \
    '                monitor.queue.async { if ready { print("}"); _ = SCDynamicStoreCopyValue(monitor.store, monitor.dnsKey) } }'
expect J10 ok

# The other half of that fix: work handed off on one line is not the callback's
# code. The baseline covers `.async { }`; this covers `Task { }`.
begin "J10 exempts work handed off inside a single-line Task"
swap "$MONITOR" "$HANDOFF" \
    '                Task { _ = SCDynamicStoreCopyValue(monitor.store, monitor.dnsKey) }'
expect J10 ok

begin "J10 catches a callback that does work instead of handing it off"
swap "$MONITOR" "$HANDOFF" '                monitor.reload()'
expect J10 fail "callback body never hands work off"

begin "J10 catches a registration in a file the rule does not lint"
put Sources/MacDNSAgent/Services/OtherWatcher.swift \
    'let store = SCDynamicStoreCreate(nil, "x" as CFString, callback, &context)'
expect J10 fail "registered in a file this rule does not lint"

begin "J10 fails when its anchor no longer matches a linted file"
drop Sources/DNSProxyExtension/DNSProxyProvider.swift 'store = SCDynamicStoreCreate('
expect J10 fail "no callback body found"

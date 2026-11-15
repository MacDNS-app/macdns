# J12 — no libproc / proc_* endpoint validator in the proxy-control plane.

begin "J12 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'Never re-add a libproc'
expect J12 fail "no longer in AGENTS.md"

begin "J12 catches proc_pidpath in the control-plane listener"
add Sources/DNSProxyExtension/ProxyControlListener.swift \
    'let path = proc_pidpath(pid, &buffer, 4096)'
expect J12 fail "libproc / PID-based endpoint validation"

begin "J12 catches PID-based identity in the agent's control client"
add Sources/MacDNSAgent/Services/ProxyControlClient.swift \
    'let peer = connection.processIdentifier'
expect J12 fail "libproc / PID-based endpoint validation"

# The Content Filter must resolve the flow source's executable path with
# proc_pidpath, and the App inspector runs unsandboxed. Both are outside the
# rule's scope by construction, not by an exception in its pattern.
begin "J12 does not flag the Content Filter's flow-source validator"
add Sources/ContentFilterExtension/ContentFilterProcessValidator.swift \
    'let extra = proc_pidpath(pid, &buffer, 4096)'
expect J12 ok

begin "J12 does not flag the App-side process inspector"
add Sources/MacDNS/Services/DNSProxyProviderProcessInspector.swift \
    'let alsoFine = proc_pidpath(pid, &buffer, 4096)'
expect J12 ok

begin "J12 fails when its scope stops resolving to the control plane"
unlink Sources/DNSProxyExtension/ProxyControlListener.swift \
    Sources/DNSProxyExtension/ProxyControlSession.swift \
    Sources/MacDNSAgent/Services/ProxyControlClient.swift
expect J12 fail "the rule's scope no longer matches the sources"

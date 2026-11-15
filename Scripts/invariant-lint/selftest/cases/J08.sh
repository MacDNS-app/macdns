# J08 — the agent is a user LaunchAgent, not a root LaunchDaemon.

begin "J08 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'user LaunchAgent, not a root LaunchDaemon'
expect J08 fail "no longer in AGENTS.md"

begin "J08 catches root-daemon registration"
add Sources/MacDNS/Services/AgentInstaller.swift \
    'try SMAppService.daemon(plistName: "app.macdns.daemon.plist").register()'
expect J08 fail "root-daemon or privileged-helper surface"

begin "J08 catches a privileged-helper flow"
add Sources/MacDNS/Services/AgentInstaller.swift \
    'let status = AuthorizationCreate(nil, nil, [], &authRef)'
expect J08 fail "root-daemon or privileged-helper surface"

begin "J08 catches a root-daemon key in a bundled plist"
add Configuration/app.macdns.agent.plist '    <key>UserName</key>'
expect J08 fail "root-daemon key in a bundled property list"

begin "J08 catches a bind on the privileged DNS port"
add Sources/MacDNSAgent/Services/NetworkMonitor.swift \
    'addr.sin_port = htons(53)'
expect J08 fail "binds the privileged DNS port 53"

# The port pattern requires a port-shaped context, so a DNS server address that
# happens to contain 53 is not a bind.
begin "J08 does not mistake a DNS server IP literal for a bind"
add Sources/MacDNSAgent/Services/NetworkMonitor.swift \
    'let quad9 = "2620:119:53::53"'
expect J08 ok

begin "J08 fails when registration stops going through SMAppService.agent"
drop Sources/MacDNS/Services/AgentInstaller.swift 'SMAppService.agent('
expect J08 fail "no longer registered through SMAppService.agent"

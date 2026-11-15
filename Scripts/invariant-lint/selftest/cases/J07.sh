# J07 — state.json is the single source of truth for user config.

begin "J07 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'single source of truth for user config'
expect J07 fail "no longer in AGENTS.md"

begin "J07 catches a second config location"
put Sources/MacDNSAgent/Services/LegacyStore.swift \
    'let legacy = base.appendingPathComponent("state.json")'
expect J07 fail "config path built outside PathResolver"

begin "J07 catches a state-file write outside the lock"
add Sources/MacDNSAgent/Services/ConfigStore.swift \
    'func saveUnlocked(_ d: Data) throws { try d.write(to: PathResolver.stateFile) }'
expect J07 fail "state-file write outside StateFileLock"

begin "J07 catches a second App-side writer even when it takes the lock"
put Sources/MacDNS/Services/DirectConfigWriter.swift \
    'try StateFileLock.withExclusiveLock { try data.write(to: PathResolver.stateFile) }'
expect J07 fail "App-side state-file write outside RevisionAwareConfigFileStore"

begin "J07 catches a parallel persistence store"
add Sources/MacDNS/ViewModels/AppViewModel.swift \
    'func cacheServers(_ s: [String]) { UserDefaults.standard.set(s, forKey: "dnsServers") }'
expect J07 fail "parallel persistence store outside the allowlist"

# The allowlist is keyed on the enclosing function, so it exempts one call site
# rather than the API. The baseline proves the exemption works; this proves it is
# not a blanket pass for UserDefaults.
begin "J07 allowlist does not extend to a second function in the same file"
add Sources/MacDNS/ViewModels/AppViewModel.swift \
    'func rememberLastTab(_ t: Int) { UserDefaults.standard.set(t, forKey: "tab") }'
expect J07 fail "in rememberLastTab"

begin "J07 fails when PathResolver stops defining state.json"
drop Sources/Shared/PathResolver.swift 'appendingPathComponent("state.json")'
expect J07 fail "PathResolver no longer defines state.json"

begin "J07 permits the update prompt timestamp in its dedicated function"
put Sources/MacDNS/Services/UpdatePromptHistory.swift \
    'func persistedUpdatePromptHistory() { UserDefaults.standard.set(["2.0.0": Date()], forKey: "softwareUpdatePromptDates") }'
expect J07 ok

begin "J07 rejects a config store next to update prompt history"
put Sources/MacDNS/Services/UpdatePromptHistory.swift \
    'func cacheServers() { UserDefaults.standard.set(["1.1.1.1"], forKey: "dnsServers") }'
expect J07 fail "in cacheServers"

begin "J07 update prompt exception does not extend to other files"
put Sources/MacDNS/Services/OtherStore.swift \
    'func persistedUpdatePromptHistory() { UserDefaults.standard.set(true, forKey: "isEnabled") }'
expect J07 fail "in persistedUpdatePromptHistory"

# J19 — `applyOverridesAndZonesToModule()` replays state.json into the resolver
# on both paths that can make the module's in-memory copy stale: startServices()
# and saveFullConfig().

AGENT=Sources/MacDNSAgent/MacDNSAgent.swift

begin "J19 is green on the compliant fixture"
expect J19 ok

begin "J19 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'replays it on every'
expect J19 fail "no longer in AGENTS.md"

begin "J19 catches a start path that stops replaying"
swap "$AGENT" 'guard applyOverridesAndZonesToModule(from: startupConfig) else {' \
    '        guard loadFullConfigForMutation() != nil else {'
expect J19 fail "startServices no longer replays"

begin "J19 catches a save path that stops binding the replay"
swap "$AGENT" 'applyZonesAndOverrides: applyOverridesAndZonesToModule(from:),' \
    '            applyZonesAndOverrides: { _ in true },'
expect J19 fail "no saveFullConfig function binds the replay"

# The step name is read off the binding, so this is the case that proves the
# rule follows the indirection instead of trusting one hardcoded parameter name.
begin "J19 catches a bound replay that the transaction never runs"
swap "$AGENT" 'guard applyZonesAndOverrides(fullConfig) else {' \
    '        guard writeFile != nil else {'
expect J19 fail "applyZonesAndOverrides is bound but never invoked"

begin "J19 catches the transaction dropping the replay step from its signature"
swap "$AGENT" 'applyZonesAndOverrides: ([String: Any]) -> Bool,' \
    '        applyZonesAndOverrides: ([String: Any]) -> Void,'
expect J19 fail "no longer declares applyZonesAndOverrides as a step"

begin "J19 catches a replay that no longer reaches the resolver module"
swap "$AGENT" 'return ResolverModule.shared.applyPolicySnapshot(' \
    '        return true'
expect J19 fail "no longer publishes a policy snapshot"

begin "J19 fails when the replay is renamed out from under it"
swap "$AGENT" 'private func applyOverridesAndZonesToModule(from config: [String: Any]? = nil) -> Bool {' \
    '    private func replayPersistedPolicy(from config: [String: Any]? = nil) -> Bool {'
expect J19 fail "not found; the invariant's implementation moved"

begin "J19 fails when the lifecycle owner is gone"
unlink "$AGENT"
expect J19 fail "expected file is missing"

# Every J19 check is a positive requirement, so a crashed scanner would report
# each of them as missing. It has to be an internal error instead.
begin "J19 reports a crashed scanner as an error, never as a finding"
broken=$(clone_lint broken-awk-j19)
printf '\nfunction il_reserved(s, close) { return s }\n' >>"$broken/lib/awklib.awk"
expect_in "$broken" J19 error "scanner failed" "FAIL"

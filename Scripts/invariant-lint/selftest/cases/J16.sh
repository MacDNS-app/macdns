# J16 — the service lifecycle order:
#   start  ResolverModule.start() -> proxyEnable -> bypassDisable
#   stop   bypassEnable -> proxyDisable -> ResolverModule.stop()
#
# The order lives in two files: the agent orders the resolver against the
# readiness action list, and the policy orders the signals inside each list. Both
# halves get a red case, because breaking either one breaks the invariant while
# leaving the other looking correct.

AGENT=Sources/MacDNSAgent/MacDNSAgent.swift
POLICY=Sources/MacDNSAgent/Services/ProxyReadinessLifecyclePolicy.swift

begin "J16 is green on the compliant fixture"
expect J16 ok

begin "J16 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'Service start:'
expect J16 fail "no longer in AGENTS.md"

# --- the agent half: resolver vs. readiness --------------------------------

begin "J16 catches readiness published before the resolver is up"
swap "$AGENT" 'AgentLogger.shared.debug("Starting services")' \
    '        _ = applyProxyReadinessActions(ProxyReadinessLifecyclePolicy.startActions(keepProxyBypass: false))'
expect J16 fail "the start readiness actions (proxyEnable, bypassDisable) must come after ResolverModule.start()"

begin "J16 catches the resolver torn down before bypass is raised"
swap "$AGENT" 'AgentLogger.shared.debug("Stopping services")' \
    '        _ = ResolverModule.shared.stop(force: force)'
expect J16 fail "ResolverModule.stop() must come after the stop readiness actions"

begin "J16 catches a start path that never publishes readiness"
drop "$AGENT" 'ProxyReadinessLifecyclePolicy.startActions(keepProxyBypass: false)'
expect J16 fail "the start readiness actions (proxyEnable, bypassDisable) is missing"

# A signal posted straight from a lifecycle function is an ordering step this
# rule cannot place, so it is reported rather than passed.
begin "J16 catches a bypass signal posted inline in the start path"
swap "$AGENT" 'AgentLogger.shared.debug("Starting services")' \
    '        notifyBypassDisable()'
expect J16 fail "readiness signal posted inline in startServices"

begin "J16 catches a bypass request posted inline in the stop path"
swap "$AGENT" 'AgentLogger.shared.debug("Stopping services")' \
    '        _ = ResolverModule.shared.setProxyBypassRequested(true)'
expect J16 fail "readiness signal posted inline in stopAllServices"

begin "J16 fails when the start path is renamed out from under it"
swap "$AGENT" 'private func startServices() -> Bool {' \
    '    private func beginServices() -> Bool {'
expect J16 fail "not found; the invariant's implementation moved"

# --- the interpreter: the mapping the ordered lists rely on ----------------

begin "J16 catches the interpreter losing the bypassDisable signal"
swap_after "$AGENT" 'func applyProxyReadinessActions' 'notifyBypassDisable()' \
    '                    AgentLogger.shared.debug("no bypass signal")'
expect J16 fail "no longer posts bypassDisable"

begin "J16 catches the bypass probe no longer choosing from the list"
swap "$AGENT" 'if actions.contains(.setBypassRequested(true)) {' \
    '                if forceBypass {'
expect J16 fail "no longer chooses its signal from the list's bypass request"

# --- the policy half: signal order inside each list ------------------------

begin "J16 catches bypassDisable published before proxyEnable"
swap_after "$POLICY" 'static func startActions' '.wakeBypassProbe,' \
    '            .notifyProxyEnable,'
swap_after "$POLICY" 'static func startActions' '.notifyProxyEnable,' \
    '            .wakeBypassProbe,'
expect J16 fail "bypassDisable (the bypass probe) must come after proxyEnable"

# The stop list is an array literal with no braces to match; this is also the
# case that proves the bracket region walk works.
begin "J16 catches proxyDisable published before bypassEnable"
swap_after "$POLICY" 'static let stopActions' '.notifyProxyDisable,' \
    '        .wakeBypassProbe,'
swap_after "$POLICY" 'static let stopActions' '.wakeBypassProbe,' \
    '        .notifyProxyDisable,'
expect J16 fail "proxyDisable must come after bypassEnable (the bypass probe)"

# `.wakeBypassProbe` posts bypassEnable whenever its list also requests bypass,
# so a start list that requests bypass never lifts it — the start sequence would
# end in bypassEnable instead of bypassDisable.
begin "J16 catches a start list whose probe would raise bypass instead of lifting it"
swap_after "$POLICY" 'static func startActions' '.setBypassRequested(keepProxyBypass),' \
    '            .setBypassRequested(true),'
expect J16 fail "the start list requests bypass"

begin "J16 catches a stop list that stops requesting bypass"
swap_after "$POLICY" 'static let stopActions' '.setBypassRequested(true),' \
    '        .setBypassRequested(false),'
expect J16 fail "the bypass request is missing"

begin "J16 fails when the readiness policy file is gone"
unlink "$POLICY"
expect J16 fail "expected file is missing"

# Both halves of J16 read their regions through awk, so a crashed scanner must
# surface as an internal error rather than as findings assembled from its empty
# output — an ordering check on nothing would otherwise report every step as
# missing.
begin "J16 reports a crashed scanner as an error, never as a finding"
broken=$(clone_lint broken-awk-j16)
printf '\nfunction il_reserved(s, close) { return s }\n' >>"$broken/lib/awklib.awk"
expect_in "$broken" J16 error "region scanner failed" "FAIL"

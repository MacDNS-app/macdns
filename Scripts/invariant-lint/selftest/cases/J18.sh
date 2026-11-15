# J18 — agent-originated external network work is gated by NetworkReadySignal.
#
# The shared fixture carries no gate, no update checker and no resolver module,
# so it carries none of J18's subjects. Each case lays down a compliant agent
# target first: the signal and its gate seam, an update checker whose request
# start is a real URLSession call, a resolver module whose blocklist entrypoints
# go through `sym("dns_…")` bindings, and two callers — one using the shared
# gate, one using an injected gate handle. They live here rather than in the
# shared fixture so this case owns the shapes it asserts on.

SIGNAL=Sources/MacDNSAgent/Services/NetworkReadySignal.swift
UPDATER=Sources/MacDNSAgent/Services/UpdateChecker.swift
RESOLVER=Sources/MacDNSAgent/Services/ResolverModule.swift
BLOCKLIST=Sources/MacDNSAgent/Services/BlocklistManager.swift
BOOT=Sources/MacDNSAgent/AgentBoot.swift

# j18_write <rel> — writes a fixture file from a heredoc on stdin.
j18_write() {
    mkdir -p "$(dirname "$W/$1")"
    cat >"$W/$1"
}

# j18_append <rel> — appends a heredoc to an existing fixture file.
j18_append() {
    cat >>"$W/$1"
}

# j18_begin <case-name> — a fixture that satisfies J18 in full.
j18_begin() {
    begin "$1"

    j18_write "$SIGNAL" <<'SWIFT'
import Foundation

/// One-shot boot-time gate for deferring agent-originated external network
/// calls until the NetworkExtension stack is confirmed stable.
actor NetworkReadySignal {
    static let shared = NetworkReadySignal()

    private var isReady = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var timeoutTask: Task<Void, Never>?

    private init() {}

    func wait() async {
        if isReady { return }
        await withCheckedContinuation { cont in
            waiters.append(cont)
        }
    }

    func markReady(reason: String) {
        guard !isReady else { return }
        isReady = true
        for cont in waiters { cont.resume() }
        waiters.removeAll()
        timeoutTask?.cancel()
        timeoutTask = nil
    }

    func armTimeoutFallback(seconds: UInt64) {
        guard timeoutTask == nil, !isReady else { return }
        timeoutTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: seconds * 1_000_000_000)
            await self?.markReady(reason: "timeout")
        }
    }
}

/// Single seam every agent-originated external network start goes through.
struct NetworkReadyWorkGate: Sendable {
    static let shared = NetworkReadyWorkGate {
        await NetworkReadySignal.shared.wait()
    }

    private let waitUntilReady: @Sendable () async -> Void

    init(waitUntilReady: @escaping @Sendable () async -> Void) {
        self.waitUntilReady = waitUntilReady
    }

    func run(_ work: () async -> Void) async {
        await waitUntilReady()
        await work()
    }
}
SWIFT

    j18_write "$UPDATER" <<'SWIFT'
import Foundation

final class UpdateChecker {
    static let shared = UpdateChecker()

    func checkForUpdates(sendSystemNotification: Bool = true) async -> String? {
        guard let url = URL(string: "https://updates.invalid/appcast.xml") else { return nil }
        let request = URLRequest(url: url)
        guard let (payload, _) = try? await URLSession.shared.data(for: request) else { return nil }
        return String(data: payload, encoding: .utf8)
    }

    func checkForUpdatesWithBoundedRetry() async -> String? {
        await UpdateChecker.withBoundedRetry {
            await self.checkForUpdates(sendSystemNotification: true)
        }
    }

    static func withBoundedRetry(check: () async -> String?) async -> String? {
        await check()
    }
}
SWIFT

    j18_write "$RESOLVER" <<'SWIFT'
import Foundation

/// Stand-in for the agent's dlopen/dlsym bridge to libmacdns_resolver.dylib.
final class ResolverModule {
    static let shared = ResolverModule()

    typealias DnsIntFn = @convention(c) () -> Int32

    private var handle: UnsafeMutableRawPointer?
    private var fnStartBlocklistScheduler: DnsIntFn?
    private var fnForceBlocklistUpdate: DnsIntFn?
    private var fnReloadBlocklist: DnsIntFn?
    private var fnFlushCache: DnsIntFn?

    private func bind() {
        fnStartBlocklistScheduler = sym("dns_start_blocklist_scheduler")
        fnForceBlocklistUpdate = sym("dns_force_blocklist_update")
        fnReloadBlocklist = sym("dns_reload_blocklist")
        fnFlushCache = sym("dns_flush_cache")
    }

    func startBlocklistScheduler() -> Bool {
        guard let fn = fnStartBlocklistScheduler else { return false }
        return fn() == 1
    }

    func forceBlocklistUpdateResult() -> Bool {
        guard let fn = fnForceBlocklistUpdate else { return false }
        return fn() == 1
    }

    /// Legacy success/failure wrapper for callers that do not need change detail.
    func forceBlocklistUpdate() -> Bool {
        forceBlocklistUpdateResult()
    }

    func reloadBlocklist() -> Bool {
        guard let fn = fnReloadBlocklist else { return false }
        return fn() == 1
    }

    func flushCache() {
        _ = fnFlushCache?()
    }

    private func sym<T>(_ name: String) -> T? {
        guard let handle, let raw = dlsym(handle, name) else { return nil }
        return unsafeBitCast(raw, to: T.self)
    }
}
SWIFT

    j18_write "$BLOCKLIST" <<'SWIFT'
import Foundation

final class BlocklistManager {
    static let shared = BlocklistManager()

    private let resolver: ResolverModule
    private let networkReadyGate: NetworkReadyWorkGate

    init(resolver: ResolverModule = .shared, networkReadyGate: NetworkReadyWorkGate = .shared) {
        self.resolver = resolver
        self.networkReadyGate = networkReadyGate
    }

    func updateAllCategories(reload: Bool, completion: @escaping (Bool) -> Void) {
        Task {
            await self.networkReadyGate.run {
                DispatchQueue.global(qos: .background).async {
                    let ok = self.resolver.forceBlocklistUpdateResult()
                    if reload, ok {
                        _ = self.resolver.reloadBlocklist()
                        self.resolver.flushCache()
                    }
                    completion(ok)
                }
            }
        }
    }
}
SWIFT

    j18_write "$BOOT" <<'SWIFT'
import Foundation

final class AgentLogger {
    static let shared = AgentLogger()
    func error(_ message: String) {}
}

final class AgentBoot {
    private var initialUpdateTask: Task<Void, Never>?

    func start() {
        initialUpdateTask = Task {
            await NetworkReadyWorkGate.shared.run {
                _ = await UpdateChecker.shared.checkForUpdatesWithBoundedRetry()
            }
        }

        Task { await NetworkReadySignal.shared.armTimeoutFallback(seconds: 30) }
    }

    func startServices() {
        Task {
            await NetworkReadyWorkGate.shared.run {
                if !ResolverModule.shared.startBlocklistScheduler() {
                    AgentLogger.shared.error("scheduler start failed")
                }
            }
        }
        _ = ResolverModule.shared.reloadBlocklist()
        ResolverModule.shared.flushCache()
    }

    func onCaptivePortalNormal() {
        Task { await NetworkReadySignal.shared.markReady(reason: "captive-portal-normal") }
    }
}
SWIFT
}

# --- green -------------------------------------------------------------------

j18_begin "J18 is green on a compliant agent target"
expect J18 ok

# Non-network work inside a gate region must not be dragged into the inventory.
# `reloadBlocklist` and `flushCache` are FFI calls that touch nothing but LMDB
# and the cache, and both are legitimately called outside the gate.
j18_begin "J18 does not gate work that only shares one word with the enumeration"
j18_append "$BOOT" <<'SWIFT'

extension AgentBoot {
    func reapplyCategories() {
        _ = ResolverModule.shared.reloadBlocklist()
        ResolverModule.shared.flushCache()
    }
}
SWIFT
expect J18 ok

# The flip side of the chain case below: a delegating wrapper that nobody calls
# holds the obligation and discharges it, because dead code starts no request.
# Deliberate — the rule reports starts, not unreachable declarations.
j18_begin "J18 stays green for a delegating wrapper that nothing calls"
j18_append "$BOOT" <<'SWIFT'

extension AgentBoot {
    func forceRefreshNow() {
        _ = ResolverModule.shared.forceBlocklistUpdate()
    }
}
SWIFT
expect J18 ok

# The inventory is discovered, not listed, so renaming a seam does not need a
# lint change — as long as the new name still describes the documented work.
j18_begin "J18 follows a renamed seam without a lint change"
swap "$RESOLVER" 'func startBlocklistScheduler() -> Bool {' '    func beginBlocklistSchedulerRefresh() -> Bool {'
swap "$BOOT" 'ResolverModule.shared.startBlocklistScheduler()' '                if !ResolverModule.shared.beginBlocklistSchedulerRefresh() {'
expect J18 ok

# --- the invariant text ------------------------------------------------------

j18_begin "J18 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'Agent-originated external network work'
expect J18 fail "no longer in AGENTS.md"

# The enumeration in the bullet IS the inventory. A bullet that stops
# enumerating leaves the rule with nothing to recognise, and it says so rather
# than reporting a pass over an empty inventory.
j18_begin "J18 fails when the invariant stops enumerating the gated work"
swap AGENTS.md 'Agent-originated external network work' \
    '- Agent-originated external network work is gated by NetworkReadySignal until first captive-portal .normal or the 30s fallback. Do not start those URLSession/reqwest paths earlier; Content Filter activation can kill in-flight connections.'
expect J18 fail "no inventory to enforce"

# --- the gate seam -----------------------------------------------------------

j18_begin "J18 fails when the gate seam is gone"
drop "$SIGNAL" 'struct NetworkReadyWorkGate: Sendable {'
drop "$SIGNAL" 'await waitUntilReady()'
expect J18 fail "no gate seam found"

j18_begin "J18 catches an open-coded wait outside the gate"
j18_append "$BOOT" <<'SWIFT'

extension AgentBoot {
    func refreshLater() async {
        await NetworkReadySignal.shared.wait()
        _ = ResolverModule.shared.reloadBlocklist()
    }
}
SWIFT
expect J18 fail "open-coded NetworkReadySignal.wait()"

j18_begin "J18 catches an agent target that gates nothing at all"
j18_write "$BOOT" <<'SWIFT'
import Foundation

final class AgentLogger {
    static let shared = AgentLogger()
    func error(_ message: String) {}
}

final class AgentBoot {
    func start() {
        Task {
            _ = await UpdateChecker.shared.checkForUpdatesWithBoundedRetry()
        }
        Task { await NetworkReadySignal.shared.armTimeoutFallback(seconds: 30) }
    }

    func onCaptivePortalNormal() {
        Task { await NetworkReadySignal.shared.markReady(reason: "captive-portal-normal") }
    }
}
SWIFT
j18_write "$BLOCKLIST" <<'SWIFT'
import Foundation

final class BlocklistManager {
    static let shared = BlocklistManager()

    private let resolver: ResolverModule = .shared

    func updateAllCategories(completion: @escaping (Bool) -> Void) {
        completion(self.resolver.forceBlocklistUpdateResult())
    }
}
SWIFT
expect J18 fail "nothing defers agent-originated external network work"

# --- ungated call sites ------------------------------------------------------

j18_begin "J18 catches a second, ungated start of an inventoried seam"
j18_append "$BOOT" <<'SWIFT'

extension AgentBoot {
    func restartScheduler(after reason: String) {
        AgentLogger.shared.error("restarting scheduler after " + reason)
        _ = ResolverModule.shared.startBlocklistScheduler()
    }
}
SWIFT
expect J18 fail "ungated call to startBlocklistScheduler()"

j18_begin "J18 catches an ungated start behind an injected gate handle"
j18_append "$BLOCKLIST" <<'SWIFT'

extension BlocklistManager {
    func refreshNow(completion: @escaping (Bool) -> Void) {
        let ok = self.resolver.forceBlocklistUpdateResult()
        _ = self.resolver.reloadBlocklist()
        completion(ok)
    }
}
SWIFT
expect J18 fail "ungated call to forceBlocklistUpdateResult()"

# The delegating-wrapper exemption MOVES the obligation, it does not remove it:
# the wrapper joins the inventory, so calling the wrapper ungated is a finding.
j18_begin "J18 moves the obligation onto a delegating wrapper rather than dropping it"
j18_append "$BOOT" <<'SWIFT'

extension AgentBoot {
    func refreshNow() {
        AgentLogger.shared.error("forcing a blocklist refresh")
        _ = ResolverModule.shared.forceBlocklistUpdate()
    }
}
SWIFT
expect J18 fail "ungated call to forceBlocklistUpdate()"

# ... and the transfer chains rather than terminating: wrapping the wrapper
# hands the obligation one hop further out, it never discharges it.
j18_begin "J18 follows the obligation through a chain of delegating wrappers"
j18_append "$BOOT" <<'SWIFT'

extension AgentBoot {
    func forceRefreshNow() {
        _ = ResolverModule.shared.forceBlocklistUpdate()
    }

    func onUserRequestedRefresh() {
        AgentLogger.shared.error("user requested a refresh")
        self.forceRefreshNow()
    }
}
SWIFT
expect J18 fail "ungated call to forceRefreshNow()"

# --- the gate keeps its subject ----------------------------------------------

j18_begin "J18 catches a gate emptied of the work it was protecting"
swap "$BOOT" '_ = await UpdateChecker.shared.checkForUpdatesWithBoundedRetry()' \
    '                AgentLogger.shared.error("nothing to defer")'
expect J18 fail "guards no external network start"

# Unrecognised shapes are reported as unrecognised. A URLSession start is
# unambiguous external network work; if it matches nothing the invariant
# enumerates, the document and the code have diverged and a human decides which
# one is wrong.
j18_begin "J18 reports gated network work the invariant does not enumerate"
j18_append "$UPDATER" <<'SWIFT'

extension UpdateChecker {
    func pingTelemetryHost() async {
        guard let url = URL(string: "https://telemetry.invalid/beacon") else { return }
        _ = try? await URLSession.shared.data(from: url)
    }
}
SWIFT
swap "$BOOT" '_ = await UpdateChecker.shared.checkForUpdatesWithBoundedRetry()' \
    '                await UpdateChecker.shared.pingTelemetryHost()'
expect J18 fail "names no work item from the invariant's enumeration"

# --- release paths -----------------------------------------------------------

j18_begin "J18 catches a release path that is no longer wired"
drop "$BOOT" 'armTimeoutFallback(seconds: 30)'
expect J18 fail "armTimeoutFallback() has no caller outside the signal"

# --- engine ------------------------------------------------------------------
#
# Both scanners run through lint_awk, so a crashed scanner must surface as an
# internal error rather than as findings invented from its empty output.
j18_begin "J18 reports a crashed scanner as an error, never as a finding"
broken=$(clone_lint broken-awk-j18)
printf '\nfunction il_reserved(s, close) { return s }\n' >>"$broken/lib/awklib.awk"
expect_in "$broken" J18 error "scanner failed" "FAIL"

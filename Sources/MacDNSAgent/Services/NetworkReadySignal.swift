// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// One-shot boot-time gate that defers agent-originated external network calls
/// until the NetworkExtension stack (DNS Proxy and Content Filter) is stable.
/// Released by the first captive-portal probe result of `.normal`, which
/// proves the stack settled, or by a 30 s timeout fallback. Inferred-state
/// releases such as "services failed to start" are deliberately not used: a
/// release during a service transition can still race a late in-flight
/// URLSession against Content Filter activation. Once released, every current
/// and future `wait()` caller returns immediately, and later network
/// transitions do not re-gate.
actor NetworkReadySignal {
    static let shared = NetworkReadySignal()

    private var isReady = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var timeoutTask: Task<Void, Never>?

    private init() {}

    /// Never throws and never cancels individual waiters.
    func wait() async {
        if isReady { return }
        await withCheckedContinuation { cont in
            waiters.append(cont)
        }
    }

    /// Idempotent. Logs the release reason for post-mortem correlation with
    /// other agent events.
    func markReady(reason: String) {
        guard !isReady else { return }
        isReady = true
        let count = waiters.count
        AgentLogger.shared.info(
            "network-ready released (\(reason)) — unblocking \(count) deferred task\(count == 1 ? "" : "s")")
        for cont in waiters { cont.resume() }
        waiters.removeAll()
        timeoutTask?.cancel()
        timeoutTask = nil
    }

    /// Releases the signal after `seconds` so it always releases, also on a
    /// "services off" boot (no captive-portal probe ever runs) and when the
    /// probe endpoint is blocked on an otherwise healthy network. Only the
    /// first arm takes effect.
    func armTimeoutFallback(seconds: UInt64) {
        guard timeoutTask == nil, !isReady else { return }
        timeoutTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: seconds * 1_000_000_000)
            guard !Task.isCancelled else { return }
            await self?.markReady(reason: "timeout \(seconds)s")
        }
    }
}

/// Single seam every agent-originated external network start goes through, so
/// the deferral is one injectable decision instead of open-coded `wait()` calls
/// scattered across services. Production uses `shared`, which waits on
/// `NetworkReadySignal`. Tests inject a gate they release by hand.
struct NetworkReadyWorkGate: Sendable {
    static let shared = NetworkReadyWorkGate {
        await NetworkReadySignal.shared.wait()
    }

    private let waitUntilReady: @Sendable () async -> Void

    init(waitUntilReady: @escaping @Sendable () async -> Void) {
        self.waitUntilReady = waitUntilReady
    }

    /// Runs `work` only after the gate released and returns its result, so a
    /// caller that must answer a request (manual update check over XPC) stays
    /// gated without losing the value. Never start a URLSession or reqwest path
    /// outside this helper. Content Filter activation kills connections opened
    /// before the NetworkExtension stack settles, and they then stall for the
    /// full request timeout.
    func run<T>(_ work: () async -> T) async -> T {
        await waitUntilReady()
        return await work()
    }
}

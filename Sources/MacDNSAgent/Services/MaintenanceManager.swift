// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

/// Result of one maintenance tick. Surfaced so the manager can log it and
/// tests can drive the runner without the resolver dylib.
enum MaintenanceTickOutcome: Equatable {
    case skippedResolverStopped
    /// A tick arrived while the previous snapshot was still running and was
    /// folded into it.
    case coalesced
    case snapshot(ResolverModule.CacheSnapshotResult)
}

/// Runs the hourly cache snapshot off the main queue, one at a time.
///
/// The snapshot FFI blocks its caller across iteration, serialization, gzip,
/// write and fsync of a cache that can hold 200 MB, so running it on the main
/// queue stalls every control path the agent drives from there. Ticks that
/// arrive while one is still running are coalesced into it, because a second
/// full snapshot right behind the first would write the same entries and only
/// extend the stall.
///
/// This guard releases when the FFI call returns, which after the resolver's own
/// deadline is well before the abandoned write actually ends. The resolver keeps
/// a second, longer-lived single flight for exactly that window and answers a
/// tick arriving inside it with `.busy`.
final class MaintenanceTickRunner: @unchecked Sendable {

    private let lock = NSLock()
    private var inFlight = false

    private let enqueue: (@escaping () -> Void) -> Void
    private let isResolverRunning: () -> Bool
    private let snapshot: () -> ResolverModule.CacheSnapshotResult

    init(
        enqueue: @escaping (@escaping () -> Void) -> Void,
        isResolverRunning: @escaping () -> Bool,
        snapshot: @escaping () -> ResolverModule.CacheSnapshotResult
    ) {
        self.enqueue = enqueue
        self.isResolverRunning = isResolverRunning
        self.snapshot = snapshot
    }

    /// Called from the timer callback on the main queue. The coalescing
    /// decision is made synchronously here so a backlog can never build up
    /// behind an in-flight snapshot.
    func tick(completion: ((MaintenanceTickOutcome) -> Void)? = nil) {
        lock.lock()
        if inFlight {
            lock.unlock()
            completion?(.coalesced)
            return
        }
        inFlight = true
        lock.unlock()

        enqueue { [weak self] in
            guard let self else { return }
            completion?(self.run())
        }
    }

    /// `defer` releases the in-flight guard unconditionally. A stuck flag would
    /// silence every later tick for the rest of the agent's lifetime.
    private func run() -> MaintenanceTickOutcome {
        defer { lock.withLock { inFlight = false } }
        guard isResolverRunning() else { return .skippedResolverStopped }
        return .snapshot(snapshot())
    }
}

class MaintenanceManager {
    static let shared = MaintenanceManager()

    private var timer: Timer?
    private let updateInterval: TimeInterval = 1 * 60 * 60

    /// Dedicated serial queue for the blocking snapshot. Utility QoS: warm
    /// cache persistence is never latency-sensitive.
    private let snapshotQueue = DispatchQueue(
        label: "app.macdns.agent.maintenance", qos: .utility)

    private lazy var runner = MaintenanceTickRunner(
        enqueue: { [snapshotQueue] work in snapshotQueue.async(execute: work) },
        isResolverRunning: { ResolverModule.shared.isRunning() },
        snapshot: { ResolverModule.shared.snapshotCache() }
    )

    func start() {
        AgentLogger.shared.info("Starting maintenance manager (1-hour cache snapshot cycle)")

        DispatchQueue.main.async { [self] in
            self.timer = Timer.scheduledTimer(withTimeInterval: self.updateInterval, repeats: true) { [weak self] _ in
                self?.runner.tick { Self.log($0) }
            }
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }

    private static func log(_ outcome: MaintenanceTickOutcome) {
        switch outcome {
        case .skippedResolverStopped:
            AgentLogger.shared.debug("Maintenance tick skipped - resolver not running")
        case .coalesced:
            AgentLogger.shared.warning("Maintenance tick coalesced - previous cache snapshot still running")
        case .snapshot(.wrote(let entries)):
            AgentLogger.shared.debug("Maintenance tick - cache snapshot persisted \(entries) entries")
        case .snapshot(.timedOut):
            AgentLogger.shared.warning("Maintenance tick - cache snapshot exceeded its deadline")
        case .snapshot(.busy):
            // Expected when a previous write outlived its FFI deadline. The
            // resolver folds this tick into the running writer instead of
            // letting two writers race the final rename.
            AgentLogger.shared.info(
                "Maintenance tick - resolver already writing a cache snapshot; tick coalesced")
        case .snapshot(.failed):
            AgentLogger.shared.warning("Maintenance tick - cache snapshot failed")
        }
    }
}

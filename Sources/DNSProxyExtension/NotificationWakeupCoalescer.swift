// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Collapses a burst of unauthenticated Darwin wake-ups into a bounded amount
/// of queued work.
///
/// Coalescing happens at the front door: the decision to enqueue is made
/// synchronously under a lock, so a flood cannot build a queue backlog while
/// earlier blocks are still waiting to run. Signals arriving while work is
/// already scheduled collapse into that scheduled run.
final class NotificationWakeupCoalescer: @unchecked Sendable {

    private let lock = NSLock()
    private var generation: UInt64 = 0
    private var scheduled = false
    private var cancelled = false

    private let enqueue: (@escaping () -> Void) -> Void
    private let handler: () -> Void

    init(
        enqueue: @escaping (@escaping () -> Void) -> Void,
        handler: @escaping () -> Void = {}
    ) {
        self.enqueue = enqueue
        self.handler = handler
    }

    /// Runs scheduled but not yet executed. Test-facing diagnostic. Production
    /// code only calls `signal()` and `cancel()`.
    var pendingDepth: Int {
        lock.lock()
        defer { lock.unlock() }
        return scheduled ? 1 : 0
    }

    /// Called directly from the Darwin notification callback. Does no work
    /// beyond flag manipulation so the callback stays cheap.
    func signal() {
        lock.lock()
        if cancelled || scheduled {
            lock.unlock()
            return
        }
        scheduled = true
        let scheduledGeneration = generation
        lock.unlock()

        enqueue { [weak self] in
            self?.drain(generation: scheduledGeneration)
        }
    }

    func cancel() {
        lock.lock()
        generation &+= 1
        cancelled = true
        scheduled = false
        lock.unlock()
    }

    func reset() {
        lock.lock()
        generation &+= 1
        cancelled = false
        scheduled = false
        lock.unlock()
    }

    private func drain(generation scheduledGeneration: UInt64) {
        lock.lock()
        guard scheduledGeneration == generation else {
            lock.unlock()
            return
        }
        let shouldRun = !cancelled && scheduled
        scheduled = false
        lock.unlock()

        guard shouldRun else { return }
        handler()
    }
}

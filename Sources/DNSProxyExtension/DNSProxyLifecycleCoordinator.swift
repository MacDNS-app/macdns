// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Tracks provider lifecycle so asynchronous socket callbacks cannot publish
/// state or create resources after teardown has begun.
///
/// Every connect, read, write, and timer callback captures a generation when it
/// is scheduled and checks `isCurrent` before acting. `beginStop` invalidates
/// the running generation before any resource is torn down, so callbacks in
/// flight during shutdown become inert rather than racing the teardown.
final class DNSProxyLifecycleCoordinator: @unchecked Sendable {

    enum Phase: Equatable {
        case stopped
        case starting
        case running
        case stopping
    }

    private let condition = NSCondition()
    private var currentPhase: Phase = .stopped
    private var generation: UInt64 = 0
    private var activeOperations = 0

    var phase: Phase {
        condition.lock()
        defer { condition.unlock() }
        return currentPhase
    }

    /// Begins a start transition and returns the generation this session owns.
    @discardableResult
    func beginStart() -> UInt64 {
        condition.lock()
        defer { condition.unlock() }
        generation &+= 1
        currentPhase = .starting
        return generation
    }

    func finishStart() {
        condition.lock()
        defer { condition.unlock() }
        guard currentPhase == .starting else { return }
        currentPhase = .running
    }

    /// Invalidates the running generation. Returns false when a stop is already
    /// in progress, so the completion handler runs exactly once.
    @discardableResult
    func beginStop() -> Bool {
        condition.lock()
        defer { condition.unlock() }
        guard currentPhase != .stopping, currentPhase != .stopped else {
            return false
        }
        generation &+= 1
        currentPhase = .stopping
        while activeOperations > 0 {
            condition.wait()
        }
        return true
    }

    /// Completes the stop and returns the token that authorizes self-termination
    /// for exactly this stop.
    @discardableResult
    func finishStop() -> UInt64 {
        condition.lock()
        defer { condition.unlock() }
        currentPhase = .stopped
        return generation
    }

    /// Whether the deferred process exit for `token` may still run. `beginStart`
    /// claims a newer generation and moves the phase off `.stopped`, so a restart
    /// arriving inside the exit delay is not killed by the previous stop. With no
    /// restart the exit proceeds, because launchd only rebuilds the proxy-control
    /// Mach endpoint once this process actually exits.
    func mayTerminate(_ token: UInt64) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        return currentPhase == .stopped && generation == token
    }

    func generationForNewFlow() -> UInt64? {
        condition.lock()
        defer { condition.unlock() }
        guard currentPhase == .running else { return nil }
        return generation
    }

    @discardableResult
    func performIfCurrent(
        _ capturedGeneration: UInt64,
        operation: () -> Void
    ) -> Bool {
        condition.lock()
        guard currentPhase == .running, generation == capturedGeneration else {
            condition.unlock()
            return false
        }
        activeOperations += 1
        condition.unlock()

        defer {
            condition.lock()
            activeOperations -= 1
            if activeOperations == 0 {
                condition.broadcast()
            }
            condition.unlock()
        }
        operation()
        return true
    }

    /// Whether work captured at `capturedGeneration` may still act.
    func isCurrent(_ capturedGeneration: UInt64) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        return currentPhase == .running && generation == capturedGeneration
    }
}

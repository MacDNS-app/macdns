// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

@MainActor
final class ContentFilterPreferenceMutationCoordinatorTests: XCTestCase {
    func testCancelThenDisableWaitsForTheInFlightMutation() async throws {
        let coordinator = ContentFilterPreferenceMutationCoordinator()
        let gate = ControlledPreferenceMutationGate()
        var activeOperations = 0
        var maximumActiveOperations = 0
        var enabled = false

        let firstEnable = Task { @MainActor in
            try await coordinator.perform(respectCancellation: true) {
                activeOperations += 1
                maximumActiveOperations = max(maximumActiveOperations, activeOperations)
                defer { activeOperations -= 1 }
                await gate.wait()
                enabled = true
            }
        }
        let enableStarted = await waitUntil { gate.isWaiting }
        XCTAssertTrue(enableStarted)

        firstEnable.cancel()
        let disable = Task { @MainActor in
            try await coordinator.perform {
                activeOperations += 1
                maximumActiveOperations = max(maximumActiveOperations, activeOperations)
                defer { activeOperations -= 1 }
                enabled = false
            }
        }
        let disableQueued = await waitUntil { coordinator.pendingOperationCount == 1 }
        XCTAssertTrue(disableQueued)

        gate.release()
        _ = await firstEnable.result
        try await disable.value

        XCTAssertFalse(enabled)
        XCTAssertEqual(maximumActiveOperations, 1)
    }

    func testCancelDisableThenReenablePreservesRequestOrder() async throws {
        let coordinator = ContentFilterPreferenceMutationCoordinator()
        let gate = ControlledPreferenceMutationGate()
        var activeOperations = 0
        var maximumActiveOperations = 0
        var appliedStates: [Bool] = []

        let firstEnable = Task { @MainActor in
            try await coordinator.perform(respectCancellation: true) {
                activeOperations += 1
                maximumActiveOperations = max(maximumActiveOperations, activeOperations)
                defer { activeOperations -= 1 }
                await gate.wait()
                appliedStates.append(true)
            }
        }
        let enableStarted = await waitUntil { gate.isWaiting }
        XCTAssertTrue(enableStarted)

        firstEnable.cancel()
        let disable = Task { @MainActor in
            try await coordinator.perform {
                activeOperations += 1
                maximumActiveOperations = max(maximumActiveOperations, activeOperations)
                defer { activeOperations -= 1 }
                appliedStates.append(false)
            }
        }
        let disableQueued = await waitUntil { coordinator.pendingOperationCount == 1 }
        XCTAssertTrue(disableQueued)

        let reenable = Task { @MainActor in
            try await coordinator.perform(respectCancellation: true) {
                activeOperations += 1
                maximumActiveOperations = max(maximumActiveOperations, activeOperations)
                defer { activeOperations -= 1 }
                appliedStates.append(true)
            }
        }
        let reenableQueued = await waitUntil { coordinator.pendingOperationCount == 2 }
        XCTAssertTrue(reenableQueued)

        gate.release()
        _ = await firstEnable.result
        try await disable.value
        try await reenable.value

        XCTAssertEqual(appliedStates, [true, false, true])
        XCTAssertEqual(maximumActiveOperations, 1)
    }

    func testCancelledWaiterDoesNotMutatePreferences() async throws {
        let coordinator = ContentFilterPreferenceMutationCoordinator()
        let gate = ControlledPreferenceMutationGate()
        var operations: [String] = []

        let first = Task { @MainActor in
            try await coordinator.perform {
                await gate.wait()
                operations.append("first")
            }
        }
        let firstStarted = await waitUntil { gate.isWaiting }
        XCTAssertTrue(firstStarted)

        let cancelled = Task { @MainActor in
            try await coordinator.perform(respectCancellation: true) {
                operations.append("cancelled")
            }
        }
        let cancelledWaiterQueued = await waitUntil { coordinator.pendingOperationCount == 1 }
        XCTAssertTrue(cancelledWaiterQueued)
        cancelled.cancel()

        let last = Task { @MainActor in
            try await coordinator.perform {
                operations.append("last")
            }
        }
        let lastQueued = await waitUntil { coordinator.pendingOperationCount == 2 }
        XCTAssertTrue(lastQueued)

        gate.release()
        try await first.value
        do {
            try await cancelled.value
            XCTFail("cancelled waiter must not mutate preferences")
        } catch is CancellationError {
            // Expected.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        try await last.value

        XCTAssertEqual(operations, ["first", "last"])
    }

    func testCancelledEnableCanRunNonCancellableCleanup() async {
        let coordinator = ContentFilterPreferenceMutationCoordinator()
        let gate = ControlledPreferenceMutationGate()
        var enabled = false

        let task = Task { @MainActor in
            do {
                try await coordinator.perform(respectCancellation: true) {
                    await gate.wait()
                    enabled = true
                }
                try Task.checkCancellation()
            } catch is CancellationError {
                do {
                    try await coordinator.perform {
                        enabled = false
                    }
                } catch {
                    XCTFail("cleanup failed: \(error)")
                }
            } catch {
                XCTFail("unexpected error: \(error)")
            }
        }
        let enableStarted = await waitUntil { gate.isWaiting }
        XCTAssertTrue(enableStarted)

        task.cancel()
        gate.release()
        await task.value

        XCTAssertFalse(enabled)
    }

    private func waitUntil(
        _ condition: @escaping @MainActor () -> Bool,
        attempts: Int = 1_000
    ) async -> Bool {
        for _ in 0..<attempts {
            if condition() { return true }
            try? await Task.sleep(nanoseconds: 1_000_000)
        }
        return condition()
    }
}

@MainActor
private final class ControlledPreferenceMutationGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var released = false

    private(set) var isWaiting = false

    func wait() async {
        isWaiting = true
        guard !released else { return }

        await withCheckedContinuation { continuation in
            if released {
                continuation.resume()
            } else {
                self.continuation = continuation
            }
        }
    }

    func release() {
        released = true
        continuation?.resume()
        continuation = nil
    }
}

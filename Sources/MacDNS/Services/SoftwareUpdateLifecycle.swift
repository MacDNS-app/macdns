// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

/// Quiesces traffic and waits for launchd to terminate the bundled Agent before replacement.
@MainActor
final class SoftwareUpdateLifecycle {
    enum StopStep: CaseIterable {
        case disableDNSProxy
        case disableContentFilter
        case unregisterAgent
    }

    enum State {
        case idle
        case preparing
        case prepared
        case failed
        case restoring
    }

    enum Owner {
        case updateCycle
        case applicationTermination
    }

    private(set) var state: State = .idle
    private let stop: (StopStep) async -> Bool
    private let restore: () async -> Void
    private var preparation: Task<Bool, Never>?
    private var restoration: Task<Void, Never>?
    private var generation: UInt64 = 0
    private var preparationOwner: Owner?

    var attemptID: UInt64 { generation }

    init(stop: @escaping (StopStep) async -> Bool, restore: @escaping () async -> Void) {
        self.stop = stop
        self.restore = restore
    }

    var mayRelaunch: Bool { state == .idle || state == .prepared }

    func prepare(for owner: Owner = .updateCycle) async -> Bool {
        if state == .prepared { return true }
        if let preparation { return await preparation.value && state == .prepared }
        guard state == .idle else { return false }

        preparationOwner = owner
        state = .preparing
        let capturedGeneration = generation
        let task = Task { @MainActor in
            var ready = true
            for step in StopStep.allCases {
                guard !Task.isCancelled, await stop(step) else {
                    ready = false
                    break
                }
            }
            guard capturedGeneration == generation else { return false }
            ready = ready && !Task.isCancelled
            state = ready ? .prepared : .failed
            return ready
        }
        preparation = task
        let ready = await task.value
        guard capturedGeneration == generation else { return false }
        preparation = nil
        return ready
    }

    func finishUpdateCycle(for attemptID: UInt64) async {
        guard attemptID == generation, preparationOwner == .updateCycle else { return }
        await finishCycle()
    }

    /// A surviving App must resume its previous services after an aborted install.
    func finishCycle() async {
        if let restoration {
            await restoration.value
            return
        }
        guard state != .idle else { return }
        generation &+= 1
        state = .restoring
        let pendingPreparation = preparation
        pendingPreparation?.cancel()
        let task = Task { @MainActor in
            _ = await pendingPreparation?.value
            await restore()
        }
        restoration = task
        await task.value
        preparation = nil
        restoration = nil
        preparationOwner = nil
        state = .idle
    }
}

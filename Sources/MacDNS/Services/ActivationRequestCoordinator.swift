// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import SystemExtensions

@MainActor
final class ActivationRequestCoordinator {
    private let timeoutNanoseconds: UInt64
    private let timeoutError: @MainActor () -> Error
    private let submit: @MainActor (OSSystemExtensionRequest) -> Void

    private var continuations: [UUID: CheckedContinuation<Void, Error>] = [:]
    private var timeoutTasks: [UUID: Task<Void, Never>] = [:]
    private var requestGeneration: UInt64 = 0
    private var activeGeneration: UInt64?
    private var requestGenerations: [ObjectIdentifier: UInt64] = [:]
    private var requestWatchdog: Task<Void, Never>?
    private var awaitingApprovalGeneration: UInt64?

    /// The active request reached the user approval stage. It stays alive in
    /// macOS until the user answers, so it is neither expired nor reported idle.
    var isAwaitingApproval: Bool {
        awaitingApprovalGeneration != nil && awaitingApprovalGeneration == activeGeneration
    }

    init(
        timeoutNanoseconds: UInt64,
        timeoutError: @escaping @MainActor () -> Error,
        submit: @escaping @MainActor (OSSystemExtensionRequest) -> Void = {
            OSSystemExtensionManager.shared.submitRequest($0)
        }
    ) {
        self.timeoutNanoseconds = timeoutNanoseconds
        self.timeoutError = timeoutError
        self.submit = submit
    }

    func waitForCompletion(
        submitRequest: (@MainActor () -> Void)? = nil,
        onIdle: @escaping @MainActor () -> Void
    ) async throws {
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                continuations[id] = continuation
                timeoutTasks[id] = Task { @MainActor in
                    try? await Task.sleep(nanoseconds: timeoutNanoseconds)
                    guard let continuation = continuations.removeValue(forKey: id) else { return }
                    timeoutTasks[id] = nil
                    notifyIdleIfNeeded(onIdle)
                    continuation.resume(throwing: timeoutError())
                }
                submitRequest?()
            }
        } onCancel: {
            Task { @MainActor in
                self.cancelContinuation(id, onIdle: onIdle)
            }
        }
    }

    func cancelContinuation(_ id: UUID, onIdle: @MainActor () -> Void) {
        timeoutTasks.removeValue(forKey: id)?.cancel()
        guard let continuation = continuations.removeValue(forKey: id) else { return }
        notifyIdleIfNeeded(onIdle)
        continuation.resume(throwing: CancellationError())
    }

    /// Submits an activation request. `onTimeout` arms a generation-correlated
    /// watchdog: a submission that never reaches a terminal delegate callback
    /// or the approval stage (a request the system silently drops) would
    /// otherwise leave the caller's in-progress state set forever and the
    /// submission's generation active, so a late callback still applies.
    /// `markAwaitingApproval` disarms it. `onTimeout` is required so an
    /// unguarded submission cannot be expressed.
    func submitRequest(
        _ request: OSSystemExtensionRequest,
        onTimeout: @escaping @MainActor () -> Void
    ) {
        requestGeneration &+= 1
        let generation = requestGeneration
        activeGeneration = generation
        requestGenerations[ObjectIdentifier(request)] = generation
        armRequestWatchdog(for: generation, onTimeout: onTimeout)
        submit(request)
    }

    func shouldHandleCallback(for request: OSSystemExtensionRequest) -> Bool {
        let generation = requestGenerations.removeValue(forKey: ObjectIdentifier(request))
        let policy = ActivationCallbackCorrelationPolicy(
            callbackGeneration: generation,
            activeGeneration: activeGeneration
        )
        guard policy.shouldApplyCallback else { return false }

        activeGeneration = nil
        awaitingApprovalGeneration = nil
        cancelRequestWatchdog()
        return true
    }

    func markAwaitingApproval(_ request: OSSystemExtensionRequest) {
        guard let generation = requestGenerations[ObjectIdentifier(request)],
            generation == activeGeneration
        else { return }

        awaitingApprovalGeneration = generation
        cancelRequestWatchdog()
    }

    func shouldApplyStatusUpdate(for request: OSSystemExtensionRequest) -> Bool {
        let generation = requestGenerations[ObjectIdentifier(request)]
        let policy = ActivationCallbackCorrelationPolicy(
            callbackGeneration: generation,
            activeGeneration: activeGeneration
        )
        return policy.shouldApplyCallback
    }

    @discardableResult
    func finish(_ result: Result<Void, Error>) -> Bool {
        let currentContinuations = continuations
        continuations = [:]
        timeoutTasks.values.forEach { $0.cancel() }
        timeoutTasks = [:]

        for continuation in currentContinuations.values {
            switch result {
            case .success:
                continuation.resume()
            case .failure(let error):
                continuation.resume(throwing: error)
            }
        }

        return !currentContinuations.isEmpty
    }

    private func armRequestWatchdog(for generation: UInt64, onTimeout: @escaping @MainActor () -> Void) {
        cancelRequestWatchdog()

        requestWatchdog = Task { @MainActor [weak self, timeoutNanoseconds] in
            try? await Task.sleep(nanoseconds: timeoutNanoseconds)
            guard !Task.isCancelled, let self else { return }
            guard self.expireRequest(generation: generation) else { return }
            onTimeout()
        }
    }

    private func cancelRequestWatchdog() {
        requestWatchdog?.cancel()
        requestWatchdog = nil
    }

    /// Invalidates a submission that never answered, so any late callback for it
    /// is ignored. Returns false when the generation already completed or was
    /// superseded by a newer submission.
    private func expireRequest(generation: UInt64) -> Bool {
        guard activeGeneration == generation else { return false }
        activeGeneration = nil
        awaitingApprovalGeneration = nil
        requestGenerations = requestGenerations.filter { $0.value != generation }
        requestWatchdog = nil
        return true
    }

    private func notifyIdleIfNeeded(_ onIdle: @MainActor () -> Void) {
        guard !isAwaitingApproval else { return }
        let policy = ActivationRequestProgressPolicy(pendingContinuations: continuations.count)
        if policy.shouldClearInProgressAfterWaiterRemoval {
            onIdle()
        }
    }
}

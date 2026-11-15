// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

/// Reconciles update wake-ups against the Agent cache, retaining failed delivery.
@MainActor
final class UpdateInfoLoader {
    private let retryDelays: [TimeInterval]
    private let load: () async -> UpdateInfo?
    private let didLoad: (UpdateInfo) -> Void
    private let present: (UpdateInfo) async -> Bool
    private var task: Task<Void, Never>?
    private var needsPresentation = false
    private var generation = 0

    var isIdle: Bool { task == nil }

    init(
        retryDelays: [TimeInterval] = [1, 5, 30, 60],
        load: @escaping () async -> UpdateInfo?,
        didLoad: @escaping (UpdateInfo) -> Void,
        present: @escaping (UpdateInfo) async -> Bool
    ) {
        self.retryDelays = retryDelays
        self.load = load
        self.didLoad = didLoad
        self.present = present
    }

    func refresh(presentIfAvailable: Bool) {
        generation += 1
        needsPresentation = needsPresentation || presentIfAvailable
        guard task == nil else { return }
        task = Task { [weak self] in
            guard let self else { return }
            var attemptedGeneration = generation
            defer {
                task = nil
                if !Task.isCancelled, attemptedGeneration != generation {
                    refresh(presentIfAvailable: needsPresentation)
                }
            }

            for delay in [0] + retryDelays {
                do {
                    if delay > 0 { try await Task.sleep(for: .seconds(delay)) }
                    try Task.checkCancellation()
                } catch {
                    return
                }
                let requestedGeneration = generation
                attemptedGeneration = requestedGeneration
                guard let info = await load() else { continue }
                guard !Task.isCancelled else { return }
                guard requestedGeneration == generation else { continue }
                didLoad(info)
                guard needsPresentation else { return }

                let delivered: Bool
                if info.isUpdateAvailable {
                    delivered = await present(info)
                } else {
                    delivered = true
                }
                guard !Task.isCancelled else { return }
                if delivered, requestedGeneration == generation {
                    needsPresentation = false
                    return
                }
            }
        }
    }

    func retryPendingPresentation() {
        guard needsPresentation, task == nil else { return }
        refresh(presentIfAvailable: true)
    }

    func cancel() {
        needsPresentation = false
        task?.cancel()
    }
}

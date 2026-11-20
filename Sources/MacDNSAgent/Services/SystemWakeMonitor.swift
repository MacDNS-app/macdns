// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import Foundation

protocol SystemWakeMonitorDelegate: AnyObject {
    func systemDidWake(callbackLifecycleGeneration: UInt64)
}

private final class WakeCallbackGeneration: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64?

    func load() -> UInt64? {
        lock.withLock { value }
    }

    func store(_ value: UInt64?) {
        lock.withLock { self.value = value }
    }
}

final class SystemWakeMonitor {
    static let shared = SystemWakeMonitor()

    weak var delegate: SystemWakeMonitorDelegate?

    private let notificationCenter: NotificationCenter
    private let debounceDelay: TimeInterval
    private let queue = DispatchQueue(label: "app.macdns.system-wake")
    private var observer: NSObjectProtocol?
    private var pendingWake: DispatchWorkItem?
    private var callbackLifecycleGeneration: UInt64?
    private let callbackGeneration = WakeCallbackGeneration()
    private var isStarted = false

    init(
        notificationCenter: NotificationCenter = NSWorkspace.shared.notificationCenter,
        debounceDelay: TimeInterval = 2.0
    ) {
        self.notificationCenter = notificationCenter
        self.debounceDelay = debounceDelay
    }

    func start(callbackLifecycleGeneration: UInt64) {
        dispatchPrecondition(condition: .notOnQueue(queue))
        queue.sync {
            if isStarted {
                pendingWake?.cancel()
                pendingWake = nil
                self.callbackLifecycleGeneration = callbackLifecycleGeneration
                callbackGeneration.store(callbackLifecycleGeneration)
                return
            }

            self.callbackLifecycleGeneration = callbackLifecycleGeneration
            callbackGeneration.store(callbackLifecycleGeneration)
            isStarted = true
            observer = notificationCenter.addObserver(
                forName: NSWorkspace.didWakeNotification,
                object: nil,
                queue: nil
            ) { [weak self] _ in
                guard let self else { return }
                guard let generation = self.callbackGeneration.load() else { return }
                self.enqueueWake(capturedGeneration: generation)
            }
        }
    }

    func stop() {
        dispatchPrecondition(condition: .notOnQueue(queue))
        queue.sync {
            pendingWake?.cancel()
            pendingWake = nil
            if let observer {
                notificationCenter.removeObserver(observer)
            }
            self.observer = nil
            callbackLifecycleGeneration = nil
            callbackGeneration.store(nil)
            isStarted = false
        }
    }

    private func enqueueWake(capturedGeneration: UInt64) {
        queue.async { [weak self] in
            guard let self, self.isStarted else { return }
            guard self.callbackLifecycleGeneration == capturedGeneration else { return }
            self.pendingWake?.cancel()

            let workItem = DispatchWorkItem { [weak self] in
                guard let self, self.isStarted else { return }
                guard self.callbackLifecycleGeneration == capturedGeneration else { return }
                DispatchQueue.main.async { [weak self] in
                    self?.deliverWake(
                        callbackLifecycleGeneration: capturedGeneration
                    )
                }
            }
            self.pendingWake = workItem
            self.queue.asyncAfter(
                deadline: .now() + self.debounceDelay,
                execute: workItem
            )
        }
    }

    private func deliverWake(callbackLifecycleGeneration: UInt64) {
        let isCurrent = queue.sync {
            isStarted
                && self.callbackLifecycleGeneration
                    == callbackLifecycleGeneration
        }
        guard isCurrent else { return }
        delegate?.systemDidWake(
            callbackLifecycleGeneration: callbackLifecycleGeneration
        )
    }
}

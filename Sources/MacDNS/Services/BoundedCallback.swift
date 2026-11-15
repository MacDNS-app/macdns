// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

final class BoundedCallback<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: ((Value) -> Void)?
    private var lateReply: ((Value) -> Void)?
    private var timedOut = false

    init(completion: @escaping (Value) -> Void, onLateReply: ((Value) -> Void)? = nil) {
        self.completion = completion
        self.lateReply = onLateReply
    }

    func finish(_ value: Value) {
        lock.lock()
        let callback = completion
        completion = nil
        let lateCallback = timedOut ? lateReply : nil
        lateReply = nil
        lock.unlock()
        callback?(value)
        lateCallback?(value)
    }

    private func expire(_ value: Value) {
        lock.lock()
        let callback = completion
        if callback != nil {
            timedOut = true
            completion = nil
        }
        lock.unlock()
        callback?(value)
    }

    static func run(
        seconds: TimeInterval,
        timeoutValue: Value,
        schedule: (TimeInterval, @escaping () -> Void) -> Void = { seconds, action in
            DispatchQueue.global().asyncAfter(deadline: .now() + seconds, execute: action)
        },
        completion: @escaping (Value) -> Void,
        onLateReply: ((Value) -> Void)? = nil,
        operation: (@escaping (Value) -> Void) -> Void
    ) {
        let callback = BoundedCallback(completion: completion, onLateReply: onLateReply)
        schedule(seconds) { callback.expire(timeoutValue) }
        operation { callback.finish($0) }
    }
}

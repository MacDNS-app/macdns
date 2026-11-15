// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation

/// Owns the close of one socket descriptor that several dispatch sources may
/// still be watching. The descriptor is closed exactly once, only after a close
/// was requested and every registered source has cancelled, and `onClosed`
/// runs exactly once right after that close. Budget slots are released from
/// `onClosed`, so admission tracks descriptors the process actually holds.
final class ProxyDescriptorLifecycle: @unchecked Sendable {
    private let fd: Int32
    private let closeDescriptor: (Int32) -> Void
    private let onClosed: () -> Void
    private let lock = NSLock()
    private var sourceCount = 0
    private var closeRequested = false
    private var closed = false

    init(
        fd: Int32,
        closeDescriptor: @escaping (Int32) -> Void = { _ = Darwin.close($0) },
        onClosed: @escaping () -> Void
    ) {
        self.fd = fd
        self.closeDescriptor = closeDescriptor
        self.onClosed = onClosed
    }

    func addSource() {
        lock.lock()
        sourceCount += 1
        lock.unlock()
    }

    func sourceCancelled() {
        lock.lock()
        sourceCount -= 1
        let shouldClose = takeCloseIfReadyLocked()
        lock.unlock()
        if shouldClose { performClose() }
    }

    func requestClose() {
        lock.lock()
        closeRequested = true
        let shouldClose = takeCloseIfReadyLocked()
        lock.unlock()
        if shouldClose { performClose() }
    }

    private func takeCloseIfReadyLocked() -> Bool {
        guard closeRequested, sourceCount == 0, !closed else { return false }
        closed = true
        return true
    }

    private func performClose() {
        closeDescriptor(fd)
        onClosed()
    }
}

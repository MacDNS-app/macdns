// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Idle deadline for one proxied connection, renewed only by I/O progress.
///
/// A peer that opens a DNS-over-TCP flow and then goes silent must expire
/// instead of holding a file descriptor, its dispatch sources, and its buffers
/// for the life of the process. Timer ticks, `EAGAIN`, and suspended sources are
/// not progress: only bytes that actually moved renew the deadline.
struct ProxyIdleDeadline {
    private let timeoutNanoseconds: UInt64
    private var lastProgressNanoseconds: UInt64

    init(timeout: TimeInterval, startedAt uptimeNanoseconds: UInt64) {
        self.timeoutNanoseconds = UInt64(max(timeout, 0) * 1_000_000_000)
        self.lastProgressNanoseconds = uptimeNanoseconds
    }

    mutating func noteProgress(at uptimeNanoseconds: UInt64) {
        lastProgressNanoseconds = uptimeNanoseconds
    }

    func isExpired(at uptimeNanoseconds: UInt64) -> Bool {
        guard uptimeNanoseconds > lastProgressNanoseconds else { return false }
        return uptimeNanoseconds - lastProgressNanoseconds >= timeoutNanoseconds
    }
}

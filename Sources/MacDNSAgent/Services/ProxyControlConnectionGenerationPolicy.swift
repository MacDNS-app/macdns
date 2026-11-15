// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

/// Ownership of the proxy-control link, expressed as monotonic generations.
///
/// Exactly one generation is current at a time: a connection owns the one
/// minted when it is created, and the retry that replaces a dropped connection
/// owns the next. XPC handlers, bootstrap replies, and scheduled retries carry
/// the generation they were created in and may act only while it is still
/// current.
///
/// Without that check a delayed callback from a replaced connection clears the
/// HMAC session installed for its replacement, and a retry scheduled before
/// `disconnect()` reconnects after the service stopped. Pure so the sequences
/// are testable without XPC.
struct ProxyControlConnectionGenerationPolicy {
    /// Never handed out, so no outstanding generation matches the initial or a
    /// retired-only state.
    private(set) var current: UInt64 = 0

    /// Mints the generation for a new connection or a pending retry, retiring
    /// whatever owned the link before it.
    mutating func begin() -> UInt64 {
        current &+= 1
        return current
    }

    /// True while `generation` still owns the link.
    func isCurrent(_ generation: UInt64) -> Bool {
        generation == current
    }

    /// Retires every generation handed out so far without minting a new one, so
    /// their pending callbacks and retries become no-ops.
    mutating func retireAll() {
        current &+= 1
    }
}

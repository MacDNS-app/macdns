// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Bounded admission budget for one proxy resource family: DNS-over-TCP proxies
/// or UDP passthrough exchanges.
///
/// Saturation is a deliberate, counted drop of the excess work. Without a bound,
/// a burst of silent flows exhausts the extension's file descriptors, dispatch
/// sources, and memory, which takes every DNS flow down instead of only the ones
/// past the budget.
final class ProxyResourceBudget: @unchecked Sendable {

    /// Descriptors left aside for the resolver socket pool, the control-plane
    /// listener, XPC, and logging.
    static let reservedFileDescriptors = 64

    /// Applied before sizing, so an unlimited `RLIMIT_NOFILE` cannot turn into an
    /// unbounded budget.
    private static let fileDescriptorCeiling: UInt64 = 65_536

    // Passthrough exchanges are the higher-volume, short-lived family, so they
    // get the larger share.
    private static let tcpProxyShare = 0.25
    private static let tcpProxyMinimum = 64
    private static let tcpProxyMaximum = 512
    private static let udpExchangeShare = 0.5
    private static let udpExchangeMinimum = 256

    /// Soft `RLIMIT_NOFILE` the extension asks for before sizing. launchd starts
    /// it at 256, which leaves UDP passthrough at 128 slots and lets one outage
    /// burst saturate it. At this limit both minimums fit with room to spare.
    static let targetFileDescriptorLimit: UInt64 = 512
    private static let udpExchangeMaximum = 2048

    let capacity: Int

    private let lock = NSLock()
    private let saturationLogIntervalNanoseconds: UInt64
    private var inUseCount = 0
    private var rejectedCount: UInt64 = 0
    private var hasLoggedSaturation = false
    private var lastSaturationLogNanoseconds: UInt64 = 0

    init(capacity: Int, saturationLogInterval: TimeInterval = 30) {
        self.capacity = max(capacity, 0)
        self.saturationLogIntervalNanoseconds = UInt64(max(saturationLogInterval, 0) * 1_000_000_000)
    }

    /// The process descriptor allowance the budgets are sized against.
    static func processFileDescriptorLimit() -> UInt64 {
        var limits = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &limits) == 0 else { return 256 }
        return limits.rlim_cur
    }

    /// The soft limit to request, or `nil` when the current one is already at
    /// or above what the hard limit allows. Never lowers the limit.
    static func raisedSoftLimit(current: UInt64, hard: UInt64) -> UInt64? {
        let target = min(targetFileDescriptorLimit, hard)
        return target > current ? target : nil
    }

    /// Raises the soft descriptor limit toward `targetFileDescriptorLimit` and
    /// returns the limit actually in effect. Must run before the budgets are
    /// sized. A refused `setrlimit` leaves the old limit, and the allocation
    /// then shrinks to fit it, so failure costs capacity but never descriptors.
    static func raiseFileDescriptorLimit() -> UInt64 {
        var limits = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &limits) == 0 else { return 256 }
        if let raised = raisedSoftLimit(current: limits.rlim_cur, hard: limits.rlim_max) {
            var requested = limits
            requested.rlim_cur = raised
            _ = setrlimit(RLIMIT_NOFILE, &requested)
        }
        return processFileDescriptorLimit()
    }

    /// The slice of the descriptor allowance one family may claim. Sizing from
    /// the real limit keeps the budget generous where the process can afford it
    /// without ever letting one family consume the whole extension.
    static func capacity(
        fileDescriptorLimit: UInt64,
        share: Double,
        minimum: Int,
        maximum: Int
    ) -> Int {
        let usable = usableFileDescriptors(limit: fileDescriptorLimit)
        let scaled = Int(Double(usable) * share)
        return max(min(scaled, maximum, usable), min(minimum, usable))
    }

    /// Sizes both families from one allowance. Each keeps its own share and
    /// floor, but when the floors together exceed what the process can hold,
    /// the usable allowance is split by share instead, so the two budgets never
    /// admit more descriptors than the extension has.
    static func allocate(fileDescriptorLimit: UInt64) -> ProxyBudgetAllocation {
        let tcpProxies = capacity(
            fileDescriptorLimit: fileDescriptorLimit,
            share: tcpProxyShare, minimum: tcpProxyMinimum, maximum: tcpProxyMaximum)
        let udpExchanges = capacity(
            fileDescriptorLimit: fileDescriptorLimit,
            share: udpExchangeShare, minimum: udpExchangeMinimum, maximum: udpExchangeMaximum)
        let usable = usableFileDescriptors(limit: fileDescriptorLimit)
        guard tcpProxies + udpExchanges > usable else {
            return ProxyBudgetAllocation(tcpProxies: tcpProxies, udpExchanges: udpExchanges)
        }

        guard usable >= 2 else {
            return ProxyBudgetAllocation(tcpProxies: 0, udpExchanges: usable)
        }
        let tcpFraction = tcpProxyShare / (tcpProxyShare + udpExchangeShare)
        let scarceTCPProxies = max(Int(Double(usable) * tcpFraction), 1)
        let scarceUDPExchanges = usable - scarceTCPProxies
        return ProxyBudgetAllocation(tcpProxies: scarceTCPProxies, udpExchanges: scarceUDPExchanges)
    }

    private static func usableFileDescriptors(limit: UInt64) -> Int {
        let bounded = Int(min(limit, fileDescriptorCeiling))
        return max(bounded - reservedFileDescriptors, 0)
    }

    var inUse: Int {
        lock.lock()
        defer { lock.unlock() }
        return inUseCount
    }

    /// Total admissions refused since start. Exposed so saturation is observable
    /// instead of showing up only as unexplained DNS failures.
    var rejected: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return rejectedCount
    }

    func acquire() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard inUseCount < capacity else {
            rejectedCount &+= 1
            return false
        }
        inUseCount += 1
        return true
    }

    /// Reserves one unit *before* the resource it accounts for is allocated, or
    /// returns `nil` at saturation.
    ///
    /// Admission has to precede the allocation. A connect attempt holds a file
    /// descriptor, a dispatch source, and a timeout work item for its whole
    /// connect window, so a budget taken only once the connection is established
    /// bounds the established proxies and none of the in-progress ones, and the
    /// burst that exhausts the extension never reaches the check.
    func acquireSlot() -> ProxyBudgetSlot? {
        guard acquire() else { return nil }
        return ProxyBudgetSlot(budget: self)
    }

    func release() {
        lock.lock()
        defer { lock.unlock() }
        guard inUseCount > 0 else { return }
        inUseCount -= 1
    }

    /// Rate-limits the saturation log: a flood that saturates the budget must not
    /// also flood the log with one line per refused flow.
    func shouldLogSaturation(uptimeNanoseconds: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if hasLoggedSaturation,
            uptimeNanoseconds &- lastSaturationLogNanoseconds < saturationLogIntervalNanoseconds
        {
            return false
        }
        hasLoggedSaturation = true
        lastSaturationLogNanoseconds = uptimeNanoseconds
        return true
    }
}

/// Admission capacities for both proxy resource families, carved from the same
/// process descriptor allowance.
struct ProxyBudgetAllocation: Equatable {
    let tcpProxies: Int
    let udpExchanges: Int
}

/// Ownership of one admitted unit of a `ProxyResourceBudget`.
///
/// The slot travels with the resource it accounts for, so connect failure,
/// connect timeout, socket error, orderly close, and the idle sweep all end on
/// the same `release()`. Releasing twice would let the family admit more work
/// than the descriptor allowance it was sized against. Leaking a slot shrinks
/// the budget until it refuses every flow, which is worse than having no budget
/// at all. The first release counts and the rest are ignored.
final class ProxyBudgetSlot: @unchecked Sendable {
    private let budget: ProxyResourceBudget
    private let lock = NSLock()
    private var isReleased = false

    fileprivate init(budget: ProxyResourceBudget) {
        self.budget = budget
    }

    func release() {
        lock.lock()
        let alreadyReleased = isReleased
        isReleased = true
        lock.unlock()
        guard !alreadyReleased else { return }
        budget.release()
    }
}

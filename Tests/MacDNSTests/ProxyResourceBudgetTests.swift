// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import DNSProxyExtension

final class ProxyResourceBudgetTests: XCTestCase {

    // MARK: - Sizing

    func testCapacityIsAShareOfTheDescriptorAllowanceLeftAfterTheReserve() {
        let capacity = ProxyResourceBudget.capacity(
            fileDescriptorLimit: 1064, share: 0.25, minimum: 64, maximum: 512)

        XCTAssertEqual(capacity, 250)
    }

    func testCapacityNeverExceedsItsMaximum() {
        let capacity = ProxyResourceBudget.capacity(
            fileDescriptorLimit: 40_000, share: 0.5, minimum: 128, maximum: 2048)

        XCTAssertEqual(capacity, 2048)
    }

    func testCapacityIsRaisedToTheMinimumOnASmallAllowance() {
        let capacity = ProxyResourceBudget.capacity(
            fileDescriptorLimit: 320, share: 0.25, minimum: 64, maximum: 512)

        XCTAssertEqual(capacity, 64)
    }

    func testCapacityNeverExceedsTheUsableAllowance() {
        let capacity = ProxyResourceBudget.capacity(
            fileDescriptorLimit: 80, share: 0.5, minimum: 128, maximum: 2048)

        XCTAssertEqual(capacity, 16, "a minimum above the real allowance would guarantee EMFILE")
    }

    func testAnUnlimitedDescriptorAllowanceStaysBounded() {
        let capacity = ProxyResourceBudget.capacity(
            fileDescriptorLimit: UInt64.max, share: 1.0, minimum: 1, maximum: Int.max)

        XCTAssertEqual(capacity, 65_536 - ProxyResourceBudget.reservedFileDescriptors)
    }

    // MARK: - Allocation across families

    func testAllocationAtTheDefaultAllowanceKeepsBothMinimums() {
        let allocation = ProxyResourceBudget.allocate(fileDescriptorLimit: 256)

        XCTAssertEqual(allocation, ProxyBudgetAllocation(tcpProxies: 64, udpExchanges: 128))
    }

    func testAllocationAtTheRaisedAllowanceGivesUDPExchangesTheirMinimum() {
        let allocation = ProxyResourceBudget.allocate(
            fileDescriptorLimit: ProxyResourceBudget.targetFileDescriptorLimit)

        XCTAssertEqual(allocation, ProxyBudgetAllocation(tcpProxies: 112, udpExchanges: 256))
    }

    // MARK: - Descriptor limit

    func testSoftLimitIsRaisedToTheTargetWhenTheHardLimitAllows() {
        XCTAssertEqual(
            ProxyResourceBudget.raisedSoftLimit(current: 256, hard: .max),
            ProxyResourceBudget.targetFileDescriptorLimit)
    }

    func testSoftLimitIsRaisedOnlyUpToTheHardLimit() {
        XCTAssertEqual(ProxyResourceBudget.raisedSoftLimit(current: 256, hard: 300), 300)
    }

    func testSoftLimitIsNeverLowered() {
        XCTAssertNil(ProxyResourceBudget.raisedSoftLimit(current: 4096, hard: .max))
        XCTAssertNil(ProxyResourceBudget.raisedSoftLimit(current: 256, hard: 256))
    }

    func testAllocationAtALargeAllowanceReachesBothMaximums() {
        let allocation = ProxyResourceBudget.allocate(fileDescriptorLimit: 65_536)

        XCTAssertEqual(allocation, ProxyBudgetAllocation(tcpProxies: 512, udpExchanges: 2048))
    }

    func testAllocationSplitsAScarceAllowanceByShareInsteadOfStackingMinimums() {
        let allocation = ProxyResourceBudget.allocate(fileDescriptorLimit: 128)

        XCTAssertEqual(allocation, ProxyBudgetAllocation(tcpProxies: 21, udpExchanges: 43))
        XCTAssertLessThanOrEqual(
            allocation.tcpProxies + allocation.udpExchanges,
            128 - ProxyResourceBudget.reservedFileDescriptors)
    }

    func testAllocationAdmitsNothingWhenTheReserveConsumesTheLimit() {
        XCTAssertEqual(
            ProxyResourceBudget.allocate(fileDescriptorLimit: 0),
            ProxyBudgetAllocation(tcpProxies: 0, udpExchanges: 0))
        XCTAssertEqual(
            ProxyResourceBudget.allocate(fileDescriptorLimit: 64),
            ProxyBudgetAllocation(tcpProxies: 0, udpExchanges: 0))
    }

    func testAllocationNeverSplitsOneAvailableDescriptorIntoTwoAdmissions() {
        let allocation = ProxyResourceBudget.allocate(fileDescriptorLimit: 65)

        XCTAssertEqual(allocation, ProxyBudgetAllocation(tcpProxies: 0, udpExchanges: 1))
        XCTAssertEqual(allocation.tcpProxies + allocation.udpExchanges, 1)
    }

    // MARK: - Admission

    func testZeroCapacityRefusesEveryAdmission() {
        let budget = ProxyResourceBudget(capacity: 0)

        XCTAssertFalse(budget.acquire())
        XCTAssertNil(budget.acquireSlot())
        XCTAssertEqual(budget.inUse, 0)
        XCTAssertEqual(budget.rejected, 2)
    }

    func testAdmissionStopsAtCapacityAndCountsEveryRefusal() {
        let budget = ProxyResourceBudget(capacity: 2)

        XCTAssertTrue(budget.acquire())
        XCTAssertTrue(budget.acquire())
        XCTAssertFalse(budget.acquire())
        XCTAssertFalse(budget.acquire())

        XCTAssertEqual(budget.inUse, 2)
        XCTAssertEqual(budget.rejected, 2)
    }

    func testReleasingASlotReadmitsWork() {
        let budget = ProxyResourceBudget(capacity: 1)
        XCTAssertTrue(budget.acquire())
        XCTAssertFalse(budget.acquire())

        budget.release()

        XCTAssertEqual(budget.inUse, 0)
        XCTAssertTrue(budget.acquire())
        XCTAssertEqual(budget.rejected, 1)
    }

    func testReleasingMoreThanWasAcquiredCannotInflateTheBudget() {
        let budget = ProxyResourceBudget(capacity: 1)
        XCTAssertTrue(budget.acquire())

        budget.release()
        budget.release()
        budget.release()

        XCTAssertEqual(budget.inUse, 0)
        XCTAssertTrue(budget.acquire())
        XCTAssertFalse(budget.acquire())
    }

    func testConcurrentAdmissionNeverOversubscribesTheBudget() {
        let budget = ProxyResourceBudget(capacity: 64)
        let admitted = AdmissionCounter()

        DispatchQueue.concurrentPerform(iterations: 512) { _ in
            if budget.acquire() { admitted.increment() }
        }

        XCTAssertEqual(admitted.value, 64)
        XCTAssertEqual(budget.inUse, 64)
        XCTAssertEqual(budget.rejected, 512 - 64)
    }

    // MARK: - Slot ownership

    func testASaturatedBudgetHandsOutNoSlot() {
        let budget = ProxyResourceBudget(capacity: 1)
        let admitted = budget.acquireSlot()

        let refused = budget.acquireSlot()

        XCTAssertNotNil(admitted)
        XCTAssertNil(
            refused,
            "a refused flow must learn it is refused before it allocates a socket, a dispatch source, or a work item"
        )
        XCTAssertEqual(budget.inUse, 1)
        XCTAssertEqual(budget.rejected, 1)
    }

    func testASlotReleasedTwiceCountsOnce() throws {
        let budget = ProxyResourceBudget(capacity: 1)
        let slot = try XCTUnwrap(budget.acquireSlot())

        slot.release()
        slot.release()
        slot.release()

        XCTAssertEqual(budget.inUse, 0)
        XCTAssertNotNil(budget.acquireSlot())
        XCTAssertNil(budget.acquireSlot(), "a double release must not admit more work than the budget allows")
    }

    func testRepeatedAcquireAndDuplicateReleaseCyclesPreserveCapacity() throws {
        let budget = ProxyResourceBudget(capacity: 1)

        for _ in 0..<500 {
            for releaseAttempts in [1, 2] {
                let slot = try XCTUnwrap(
                    budget.acquireSlot(),
                    "every released slot must be available for the next acquisition")
                XCTAssertNil(budget.acquireSlot(), "one acquisition must exhaust the capacity")
                for _ in 0..<releaseAttempts {
                    slot.release()
                }
                XCTAssertEqual(budget.inUse, 0)
            }
        }

        XCTAssertEqual(budget.inUse, 0)
        XCTAssertEqual(budget.rejected, 1_000)
    }

    func testConcurrentReleasesOfTheSameSlotCountOnce() throws {
        let budget = ProxyResourceBudget(capacity: 2)
        let slot = try XCTUnwrap(budget.acquireSlot())

        DispatchQueue.concurrentPerform(iterations: 256) { _ in
            slot.release()
        }

        XCTAssertEqual(budget.inUse, 0, "a connect timeout racing its completion must return one slot, not many")
    }

    // MARK: - Saturation logging

    func testSaturationLogIsRateLimited() {
        let budget = ProxyResourceBudget(capacity: 1, saturationLogInterval: 1)
        let start: UInt64 = 1_000_000_000

        XCTAssertTrue(budget.shouldLogSaturation(uptimeNanoseconds: start))
        XCTAssertFalse(budget.shouldLogSaturation(uptimeNanoseconds: start))
        XCTAssertFalse(budget.shouldLogSaturation(uptimeNanoseconds: start + 999_999_999))
        XCTAssertTrue(budget.shouldLogSaturation(uptimeNanoseconds: start + 1_000_000_000))
    }

    func testTheFirstSaturationIsAlwaysLogged() {
        let budget = ProxyResourceBudget(capacity: 1, saturationLogInterval: 30)

        XCTAssertTrue(budget.shouldLogSaturation(uptimeNanoseconds: 0))
        XCTAssertFalse(budget.shouldLogSaturation(uptimeNanoseconds: 0))
    }
}

/// Lock-guarded counter for the concurrency assertion.
private final class AdmissionCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    func increment() {
        lock.lock()
        count += 1
        lock.unlock()
    }
}

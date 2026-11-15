// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import MacDNSAgent

/// Lock-protected owner of the link generation, mirroring how
/// `ProxyControlClient` holds it: every connection, drop, and retry decision is
/// taken under one lock.
private final class LinkGenerations: @unchecked Sendable {
    private let lock = NSLock()
    private var generations = ProxyControlConnectionGenerationPolicy()

    func begin() -> UInt64 {
        lock.withLock { generations.begin() }
    }

    func retireAll() {
        lock.withLock { generations.retireAll() }
    }

    func isCurrent(_ generation: UInt64) -> Bool {
        lock.withLock { generations.isCurrent(generation) }
    }
}

private final class AcceptedCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    func increment() {
        lock.withLock { count += 1 }
    }

    var value: Int {
        lock.withLock { count }
    }
}

/// Replays the sequences `ProxyControlClient` performs on its link generation:
/// `connect()` mints one, a drop retires it and mints the retry that replaces
/// it, and `disconnect()` retires everything outstanding.
///
/// With only a single stored connection and a bare `reconnectScheduled` flag, a
/// late callback from a replaced link clears the HMAC session of its successor
/// and a retry scheduled before `disconnect()` still reconnects. Both rules are
/// asserted here.
final class ProxyControlConnectionGenerationPolicyTests: XCTestCase {
    func testLateCallbackFromAReplacedConnectionIsNotCurrent() {
        var generations = ProxyControlConnectionGenerationPolicy()
        let connectionA = generations.begin()
        let retryAfterA = generations.begin()
        let connectionB = generations.begin()

        XCTAssertFalse(
            generations.isCurrent(connectionA),
            "a delayed callback from the replaced connection must not drop its successor")
        XCTAssertFalse(generations.isCurrent(retryAfterA))
        XCTAssertTrue(generations.isCurrent(connectionB))
    }

    func testSecondCallbackFromTheSameConnectionIsIgnored() {
        var generations = ProxyControlConnectionGenerationPolicy()
        let connection = generations.begin()
        XCTAssertTrue(generations.isCurrent(connection))

        // The interruption drops the link and mints the pending retry. The
        // invalidation that follows carries the same, now retired, generation.
        _ = generations.begin()

        XCTAssertFalse(generations.isCurrent(connection))
    }

    func testDisconnectRetiresAScheduledRetry() {
        var generations = ProxyControlConnectionGenerationPolicy()
        let connection = generations.begin()
        let retry = generations.begin()

        generations.retireAll()

        XCTAssertFalse(
            generations.isCurrent(retry),
            "a retry scheduled before disconnect() must not reconnect afterwards")
        XCTAssertFalse(generations.isCurrent(connection))
    }

    func testReconnectAfterDisconnectOwnsTheLinkAndTheOldRetryStaysRetired() {
        var generations = ProxyControlConnectionGenerationPolicy()
        _ = generations.begin()
        let retry = generations.begin()
        generations.retireAll()

        let reconnect = generations.begin()

        XCTAssertTrue(generations.isCurrent(reconnect))
        XCTAssertFalse(generations.isCurrent(retry))
    }

    func testGenerationsAreNeverReused() {
        var generations = ProxyControlConnectionGenerationPolicy()
        var handedOut: Set<UInt64> = []

        for step in 0..<256 {
            let generation = generations.begin()
            XCTAssertTrue(
                handedOut.insert(generation).inserted,
                "a reused generation would revive a retired callback")
            if step.isMultiple(of: 3) { generations.retireAll() }
        }

        XCTAssertFalse(handedOut.contains(0))
    }

    func testStaleGenerationsNeverPassUnderConcurrentUse() {
        let generations = LinkGenerations()
        let accepted = AcceptedCounter()
        let workers = DispatchQueue(label: "generations", attributes: .concurrent)
        let group = DispatchGroup()

        for _ in 0..<8 {
            group.enter()
            workers.async {
                for _ in 0..<500 {
                    // Take a generation, let a newer attempt replace it, then
                    // check the retired token the way a late callback does.
                    let mine = generations.begin()
                    _ = generations.begin()
                    if generations.isCurrent(mine) { accepted.increment() }
                }
                group.leave()
            }
        }

        XCTAssertEqual(group.wait(timeout: .now() + 30), .success)
        XCTAssertEqual(accepted.value, 0)
    }
}

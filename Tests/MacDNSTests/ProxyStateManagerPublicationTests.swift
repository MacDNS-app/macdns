// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import DNSProxyExtension

/// The flow paths read the destination set and the bypass flag as one pair and
/// forward to the original destination whenever the destination does not match.
/// Publishing an empty set while interception is still claimed therefore leaks
/// unfiltered queries, so the transition has to stop interception atomically.
final class ProxyStateManagerPublicationTests: XCTestCase {
    private func intercepting(_ ips: Set<String>) -> ProxyStateManager {
        let manager = ProxyStateManager()
        _ = manager.publishDNSIPs(ips)
        manager.setBypassMode(false)
        return manager
    }

    func testLosingEveryDestinationForcesBypassAtPublicationTime() {
        let manager = intercepting(["1.1.1.1", "8.8.8.8"])

        XCTAssertTrue(manager.publishDNSIPs([]))

        let (ips, bypass) = manager.read()
        XCTAssertTrue(ips.isEmpty)
        XCTAssertTrue(bypass, "an empty destination set must not leave interception claimed")
    }

    func testPublishingDestinationsDoesNotLeaveBypassOnItsOwn() {
        let manager = intercepting(["1.1.1.1"])

        XCTAssertFalse(manager.publishDNSIPs(["9.9.9.9"]))
        XCTAssertFalse(manager.read().bypassMode)

        _ = manager.publishDNSIPs([])
        XCTAssertFalse(
            manager.publishDNSIPs(["9.9.9.9"]),
            "only an authenticated challenge may leave bypass")
        XCTAssertTrue(manager.read().bypassMode)
    }

    func testRepeatedEmptyPublicationReportsTheTransitionOnlyOnce() {
        let manager = intercepting(["1.1.1.1"])

        XCTAssertTrue(manager.publishDNSIPs([]))
        XCTAssertFalse(manager.publishDNSIPs([]))
    }

    func testReplacingDestinationsInvalidatesACapturedRoutingRevision() {
        let manager = intercepting(["1.1.1.1"])
        let captured = manager.routingSnapshot()

        _ = manager.publishDNSIPs(["9.9.9.9"])

        XCTAssertFalse(manager.isCurrentRoutingRevision(captured.revision))
        XCTAssertFalse(manager.bypassMode)
    }

    func testBypassRoundTripCannotMakeAnOldRoutingRevisionCurrentAgain() {
        let manager = intercepting(["1.1.1.1"])
        let captured = manager.routingSnapshot()

        manager.setBypassMode(true)
        manager.setBypassMode(false)

        XCTAssertFalse(manager.isCurrentRoutingRevision(captured.revision))
    }

    func testIdempotentRoutingPublicationsKeepTheCurrentRevision() {
        let manager = intercepting(["1.1.1.1"])
        let captured = manager.routingSnapshot()

        _ = manager.publishDNSIPs(["1.1.1.1"])
        manager.setBypassMode(false)

        XCTAssertTrue(manager.isCurrentRoutingRevision(captured.revision))
    }

    /// Readers run on the DNS hot path and take the pair under one lock. No
    /// reader may ever observe an empty destination set together with an active
    /// interception, however the publication is interleaved with them.
    func testReadersNeverObserveAnEmptySetWhileIntercepting() {
        let manager = ProxyStateManager()
        let deadline = Date().addingTimeInterval(1)
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "publication", attributes: .concurrent)
        let violated = ViolationFlag()

        for _ in 0..<4 {
            group.enter()
            queue.async {
                while Date() < deadline {
                    let (ips, bypass) = manager.read()
                    if ips.isEmpty && !bypass { violated.raise() }
                }
                group.leave()
            }
        }

        group.enter()
        queue.async {
            while Date() < deadline {
                _ = manager.publishDNSIPs(["1.1.1.1", "8.8.8.8"])
                manager.setBypassMode(false)
                _ = manager.publishDNSIPs([])
            }
            group.leave()
        }

        XCTAssertEqual(group.wait(timeout: .now() + 30), .success)
        XCTAssertFalse(
            violated.value,
            "a reader saw an empty destination set while interception was still claimed")
    }
}

private final class ViolationFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var raised = false

    func raise() {
        lock.withLock { raised = true }
    }

    var value: Bool {
        lock.withLock { raised }
    }
}

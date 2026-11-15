// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent
@testable import Shared

/// XPC serializes calls to an exported object, so a license handler that blocks
/// its calling thread removes the whole App control channel until it returns.
/// These tests pin that `LicenseXPCDispatch` returns before the license work
/// finishes and still delivers the reply exactly once.
final class LicenseXPCNonBlockingTests: XCTestCase {

    private final class Flag: @unchecked Sendable {
        private let lock = NSLock()
        private var raised = false

        func raise() {
            lock.lock()
            raised = true
            lock.unlock()
        }

        var isRaised: Bool {
            lock.lock()
            defer { lock.unlock() }
            return raised
        }
    }

    private static func blockingInfo() -> LicenseInfo {
        LicenseInfo(
            from: LicenseState(licenseId: "license-1", status: .valid),
            isServiceAllowed: true
        )
    }

    func testEnsureValidLicenseReturnsBeforeValidationCompletes() {
        let release = DispatchSemaphore(value: 0)
        let replied = Flag()
        let dispatch = LicenseXPCDispatch(
            validate: {
                await withCheckedContinuation { continuation in
                    DispatchQueue.global().async {
                        release.wait()
                        continuation.resume()
                    }
                }
                return true
            },
            info: { Self.blockingInfo() }
        )
        let reply = expectation(description: "validation reply")

        dispatch.ensureValidLicense { allowed in
            XCTAssertTrue(allowed)
            replied.raise()
            reply.fulfill()
        }

        XCTAssertFalse(
            replied.isRaised,
            "The XPC handler must return before license validation finishes"
        )
        release.signal()
        wait(for: [reply], timeout: 5)
    }

    func testLicenseInfoReturnsBeforeTheLookupCompletes() {
        let release = DispatchSemaphore(value: 0)
        let replied = Flag()
        let dispatch = LicenseXPCDispatch(
            validate: { true },
            info: {
                await withCheckedContinuation { continuation in
                    DispatchQueue.global().async {
                        release.wait()
                        continuation.resume()
                    }
                }
                return Self.blockingInfo()
            }
        )
        let reply = expectation(description: "info reply")

        dispatch.licenseInfo { info in
            XCTAssertEqual(info.status, .valid)
            replied.raise()
            reply.fulfill()
        }

        XCTAssertFalse(
            replied.isRaised,
            "The XPC handler must return before the license lookup finishes"
        )
        release.signal()
        wait(for: [reply], timeout: 5)
    }

    func testSlowValidationDoesNotStallLaterHandlerCalls() {
        let release = DispatchSemaphore(value: 0)
        let dispatch = LicenseXPCDispatch(
            validate: {
                await withCheckedContinuation { continuation in
                    DispatchQueue.global().async {
                        release.wait()
                        continuation.resume()
                    }
                }
                return true
            },
            info: { Self.blockingInfo() }
        )
        let slowReply = expectation(description: "slow validation reply")
        let fastReply = expectation(description: "info reply while validating")

        dispatch.ensureValidLicense { _ in slowReply.fulfill() }
        dispatch.licenseInfo { _ in fastReply.fulfill() }

        wait(for: [fastReply], timeout: 5)
        release.signal()
        wait(for: [slowReply], timeout: 5)
    }

    func testReplyIsDeliveredExactlyOnce() {
        let dispatch = LicenseXPCDispatch(
            validate: { false },
            info: { Self.blockingInfo() }
        )
        let reply = expectation(description: "single validation reply")
        reply.expectedFulfillmentCount = 1
        reply.assertForOverFulfill = true

        dispatch.ensureValidLicense { allowed in
            XCTAssertFalse(allowed)
            reply.fulfill()
        }

        wait(for: [reply], timeout: 5)
    }
}

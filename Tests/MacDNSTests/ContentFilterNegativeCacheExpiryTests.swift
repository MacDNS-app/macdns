// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation
import SharedExtensionKit
import XCTest

@testable import ContentFilterExtension

final class ContentFilterNegativeCacheExpiryTests: XCTestCase {
    func testFailureExpiresAtOneSecondAndRequiresFullValidation() {
        var now: TimeInterval = 100
        var signatureValid = false
        var team = "TEAM123"
        var probes = 0
        let path = "/Applications/MacDNS.app/Contents/MacOS/MacDNSAgent"
        let validator = ContentFilterProcessValidator(
            expectedTeamIdentifier: "TEAM123", now: { now }, resolvePath: { _ in path },
            probeSignature: { path, role, _ in
                probes += 1
                return ContentFilterProcessSnapshot(
                    canonicalPath: path, signingIdentifier: role.signingIdentifier,
                    teamIdentifier: team, signatureValid: signatureValid)
            })
        var token = audit_token_t()
        token.val.5 = 42
        token.val.7 = 1
        let data = withUnsafeBytes(of: token) { Data($0) }
        XCTAssertFalse(validator.evaluate(auditToken: data).trusted)
        signatureValid = true
        team = "OTHER"
        now = 100.999
        XCTAssertFalse(validator.evaluate(auditToken: data).trusted)
        XCTAssertEqual(probes, 1)
        now = 101
        XCTAssertFalse(validator.evaluate(auditToken: data).trusted)
        XCTAssertEqual(probes, 2)
        team = "TEAM123"
        now = 102
        XCTAssertTrue(validator.evaluate(auditToken: data).trusted)
        XCTAssertEqual(probes, 3)
        signatureValid = false
        now = 1_000
        XCTAssertTrue(validator.evaluate(auditToken: data).trusted)
        XCTAssertEqual(probes, 3)
    }

    func testDefaultCacheRetainsNegativeResultsWithoutExpiry() {
        var now: TimeInterval = 1
        let cache = MacDNSValidationCache<Int>(maxEntries: 1, now: { now })
        cache.insert(false, for: 1)
        now = 10_000
        XCTAssertEqual(cache.value(for: 1), false)
    }

    func testExpiredEntryDoesNotConsumeCapacityOrDuplicateInsertionOrder() {
        var now: TimeInterval = 1
        let cache = MacDNSValidationCache<Int>(maxEntries: 2, negativeTTL: 1, now: { now })
        cache.insert(false, for: 1)
        cache.insert(true, for: 2)
        now = 2
        XCTAssertNil(cache.value(for: 1))
        XCTAssertEqual(cache.count, 1)
        cache.insert(true, for: 1)
        cache.insert(true, for: 3)
        XCTAssertNil(cache.value(for: 2))
        XCTAssertEqual(cache.value(for: 1), true)
        XCTAssertEqual(cache.value(for: 3), true)
        XCTAssertEqual(cache.count, 2)
    }
}

// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation
import XCTest

@testable import ContentFilterExtension
import SharedExtensionKit

final class ContentFilterProcessValidatorCacheTests: XCTestCase {
    private let teamIdentifier = "TEAM123"
    private let agentPath = "/Applications/MacDNS.app/Contents/MacOS/MacDNSAgent"

    func testAuditTokenIdentityReadsPidAndPidGeneration() {
        let identity = ContentFilterAuditTokenIdentity(
            auditToken: auditToken(pid: 4321, pidVersion: 9)
        )

        XCTAssertEqual(identity?.pid, 4321)
        XCTAssertEqual(identity?.pidVersion, 9)
    }

    func testAuditTokenIdentityRejectsWrongSizedToken() {
        XCTAssertNil(
            ContentFilterAuditTokenIdentity(auditToken: Data([0x01, 0x02, 0x03]))
        )
    }

    func testRepeatedFlowFromSameProcessReusesCachedVerdict() {
        let probe = SignatureProbeSpy()
        let validator = makeValidator(probe: probe, paths: [42: agentPath])
        let token = auditToken(pid: 42, pidVersion: 1)

        XCTAssertTrue(validator.evaluate(auditToken: token).trusted)
        XCTAssertTrue(validator.evaluate(auditToken: token).trusted)

        XCTAssertEqual(probe.callCount, 1)
    }

    func testReusedPidWithNewGenerationDoesNotInheritVerdict() {
        let probe = SignatureProbeSpy()
        let validator = makeValidator(probe: probe, paths: [42: agentPath])

        XCTAssertTrue(
            validator.evaluate(auditToken: auditToken(pid: 42, pidVersion: 1)).trusted
        )

        probe.signatureValid = false
        let reusedPid = validator.evaluate(
            auditToken: auditToken(pid: 42, pidVersion: 2)
        )

        XCTAssertFalse(reusedPid.trusted)
        XCTAssertEqual(probe.callCount, 2)
    }

    func testReusedPidRunningADifferentBinaryDoesNotInheritVerdict() {
        let probe = SignatureProbeSpy()
        let validator = makeValidator(probe: probe, paths: [42: agentPath])
        XCTAssertTrue(
            validator.evaluate(auditToken: auditToken(pid: 42, pidVersion: 1)).trusted
        )

        let impostorValidator = makeValidator(
            probe: probe,
            paths: [42: "/tmp/MacDNSAgent"]
        )
        let impostor = impostorValidator.evaluate(
            auditToken: auditToken(pid: 42, pidVersion: 1)
        )

        XCTAssertFalse(impostor.trusted)
        XCTAssertEqual(impostor.canonicalPath, "/tmp/MacDNSAgent")
    }

    func testEvictionAtCapacityForcesRevalidation() {
        let probe = SignatureProbeSpy()
        let validator = makeValidator(
            probe: probe,
            capacity: 1,
            paths: [42: agentPath, 43: agentPath]
        )

        XCTAssertTrue(
            validator.evaluate(auditToken: auditToken(pid: 42, pidVersion: 1)).trusted
        )
        XCTAssertTrue(
            validator.evaluate(auditToken: auditToken(pid: 43, pidVersion: 1)).trusted
        )
        XCTAssertEqual(probe.callCount, 2)

        XCTAssertTrue(
            validator.evaluate(auditToken: auditToken(pid: 42, pidVersion: 1)).trusted
        )

        XCTAssertEqual(probe.callCount, 3)
    }

    func testNonMacDNSPathIsRejectedWithoutSignatureProbe() {
        let probe = SignatureProbeSpy()
        let validator = makeValidator(
            probe: probe,
            paths: [42: "/Applications/Safari.app/Contents/MacOS/Safari"]
        )

        let evaluation = validator.evaluate(
            auditToken: auditToken(pid: 42, pidVersion: 1)
        )

        XCTAssertFalse(evaluation.trusted)
        XCTAssertEqual(
            evaluation.canonicalPath,
            "/Applications/Safari.app/Contents/MacOS/Safari"
        )
        XCTAssertEqual(probe.callCount, 0)
    }

    func testUnresolvableSourceReportsNoPath() {
        let probe = SignatureProbeSpy()
        let validator = makeValidator(probe: probe, paths: [:])

        let missingToken = validator.evaluate(auditToken: nil)
        let unresolvedPath = validator.evaluate(
            auditToken: auditToken(pid: 42, pidVersion: 1)
        )

        XCTAssertNil(missingToken.canonicalPath)
        XCTAssertFalse(missingToken.trusted)
        XCTAssertNil(unresolvedPath.canonicalPath)
        XCTAssertFalse(unresolvedPath.trusted)
        XCTAssertEqual(probe.callCount, 0)
    }

    func testCacheKeySeparatesPidGenerationPathAndRole() {
        let cache = ContentFilterValidationCache(maxEntries: 4)
        let base = cacheKey()
        let newGeneration = cacheKey(pidVersion: 2)
        let otherPath = cacheKey(canonicalPath: "/tmp/MacDNSAgent")
        let otherRole = cacheKey(role: .dnsProxy)

        cache.insert(true, for: base)
        cache.insert(false, for: newGeneration)
        cache.insert(false, for: otherPath)
        cache.insert(false, for: otherRole)

        XCTAssertEqual(cache.value(for: base), true)
        XCTAssertEqual(cache.value(for: newGeneration), false)
        XCTAssertEqual(cache.value(for: otherPath), false)
        XCTAssertEqual(cache.value(for: otherRole), false)
    }

    func testCacheEvictsOldestEntryAtDeterministicCapacity() {
        let cache = ContentFilterValidationCache(maxEntries: 2)
        let first = cacheKey(pid: 1)
        let second = cacheKey(pid: 2)
        let third = cacheKey(pid: 3)

        cache.insert(true, for: first)
        cache.insert(false, for: second)
        cache.insert(true, for: third)

        XCTAssertNil(cache.value(for: first))
        XCTAssertEqual(cache.value(for: second), false)
        XCTAssertEqual(cache.value(for: third), true)
        XCTAssertEqual(cache.count, 2)
    }

    func testCacheWithZeroCapacityNeverStoresVerdicts() {
        let cache = ContentFilterValidationCache(maxEntries: 0)
        cache.insert(true, for: cacheKey())

        XCTAssertNil(cache.value(for: cacheKey()))
        XCTAssertEqual(cache.count, 0)
    }

    // MARK: - Helpers

    private final class SignatureProbeSpy {
        var signatureValid = true
        private(set) var callCount = 0

        func probe(
            canonicalPath: String,
            role: MacDNSProcessRole,
            expectedTeamIdentifier: String
        ) -> ContentFilterProcessSnapshot {
            callCount += 1
            return ContentFilterProcessSnapshot(
                canonicalPath: canonicalPath,
                signingIdentifier: role.signingIdentifier,
                teamIdentifier: expectedTeamIdentifier,
                signatureValid: signatureValid
            )
        }
    }

    private func makeValidator(
        probe: SignatureProbeSpy,
        capacity: Int = 64,
        paths: [Int32: String]
    ) -> ContentFilterProcessValidator {
        ContentFilterProcessValidator(
            expectedTeamIdentifier: teamIdentifier,
            cacheCapacity: capacity,
            resolvePath: { token in
                guard let identity = ContentFilterAuditTokenIdentity(auditToken: token)
                else { return nil }
                return paths[identity.pid]
            },
            probeSignature: probe.probe
        )
    }

    private func auditToken(pid: Int32, pidVersion: Int32) -> Data {
        var token = audit_token_t()
        token.val.5 = UInt32(bitPattern: pid)
        token.val.7 = UInt32(bitPattern: pidVersion)
        return withUnsafeBytes(of: token) { Data($0) }
    }

    private func cacheKey(
        pid: Int32 = 42,
        pidVersion: Int32 = 1,
        canonicalPath: String = "/Applications/MacDNS.app/Contents/MacOS/MacDNSAgent",
        role: MacDNSProcessRole = .agent
    ) -> ContentFilterProcessCacheKey {
        ContentFilterProcessCacheKey(
            pid: pid,
            pidVersion: pidVersion,
            canonicalPath: canonicalPath,
            role: role
        )
    }
}

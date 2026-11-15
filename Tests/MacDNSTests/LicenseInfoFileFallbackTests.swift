// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS
@testable import Shared

final class LicenseInfoFileFallbackTests: XCTestCase {
    private var directory: URL!
    private var licensePath: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("license-fallback-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        licensePath = directory.appendingPathComponent("license.json")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
        try super.tearDownWithError()
    }

    func testEnabledAgentFailureRetainsAuthoritativeInfoWithoutReadingFile() {
        var fallbackRead = false
        let authoritative = licenseInfo(status: .valid, isServiceAllowed: true)

        let resolved = LicenseInfoLoadFailurePolicy.resolve(
            lastAuthoritativeInfo: authoritative,
            canUseFileFallback: false
        ) {
            fallbackRead = true
            return self.licenseInfo(status: .expired, isServiceAllowed: false)
        }

        XCTAssertFalse(fallbackRead)
        XCTAssertEqual(resolved?.status, .valid)
        XCTAssertEqual(resolved?.isServiceAllowed, true)
    }

    func testEnabledAgentFailureWithoutAuthoritativeInfoFailsClosed() {
        let resolved = LicenseInfoLoadFailurePolicy.resolve(
            lastAuthoritativeInfo: nil,
            canUseFileFallback: false
        ) {
            XCTFail("File fallback must not run while the Agent can execute")
            return nil
        }

        XCTAssertEqual(resolved?.status, .unknown)
        XCTAssertEqual(resolved?.isServiceAllowed, false)
    }

    func testRefreshFailureWithoutAuthoritativeInfoFailsClosed() {
        let resolved = LicenseInfoLoadFailurePolicy.resolveRefresh(
            refreshed: nil,
            lastAuthoritativeInfo: nil,
            canUseFileFallback: false
        ) {
            XCTFail("File fallback must not run while the Agent can execute")
            return nil
        }

        XCTAssertNotNil(resolved)
        XCTAssertEqual(resolved?.status, .unknown)
        XCTAssertEqual(resolved?.isServiceAllowed, false)
    }

    func testRefreshFailureRetainsLastAuthoritativeInfo() {
        let resolved = LicenseInfoLoadFailurePolicy.resolveRefresh(
            refreshed: nil,
            lastAuthoritativeInfo: licenseInfo(status: .valid, isServiceAllowed: true),
            canUseFileFallback: false
        ) {
            XCTFail("File fallback must not run while the Agent can execute")
            return nil
        }

        XCTAssertEqual(resolved?.status, .valid)
        XCTAssertEqual(resolved?.isServiceAllowed, true)
    }

    func testSuccessfulRefreshIsUsedVerbatim() {
        let resolved = LicenseInfoLoadFailurePolicy.resolveRefresh(
            refreshed: licenseInfo(status: .expired, isServiceAllowed: false),
            lastAuthoritativeInfo: licenseInfo(status: .valid, isServiceAllowed: true),
            canUseFileFallback: false
        ) {
            XCTFail("File fallback must not run for a successful refresh")
            return nil
        }

        XCTAssertEqual(resolved?.status, .expired)
        XCTAssertEqual(resolved?.isServiceAllowed, false)
    }

    func testPermittedFallbackUsesValidLicenseFile() throws {
        try writeLicense(status: .valid)

        let outcome = LicenseInfoFileFallback(path: licensePath).load()

        XCTAssertEqual(outcome.info?.status, .valid)
        XCTAssertEqual(outcome.info?.isServiceAllowed, true)
        XCTAssertNil(outcome.failureDescription)
    }

    func testValidFailClosedSidecarBlocksService() throws {
        try writeLicense(status: .valid)
        try Data(#"{"reason":"networkGraceExpired","engagedAt":0}"#.utf8)
            .write(to: licensePath.appendingPathExtension("fail-closed"))

        let outcome = LicenseInfoFileFallback(path: licensePath).load()

        XCTAssertEqual(outcome.info?.status, .valid)
        XCTAssertEqual(outcome.info?.isServiceAllowed, false)
    }

    func testInvalidFailClosedSidecarBlocksService() throws {
        try writeLicense(status: .valid)
        try Data("{ not json".utf8)
            .write(to: licensePath.appendingPathExtension("fail-closed"))

        let outcome = LicenseInfoFileFallback(path: licensePath).load()

        XCTAssertEqual(outcome.info?.isServiceAllowed, false)
        XCTAssertNotNil(outcome.failureDescription)
    }

    func testFailClosedSidecarIOFailureBlocksService() throws {
        try writeLicense(status: .valid)
        try FileManager.default.createDirectory(
            at: licensePath.appendingPathExtension("fail-closed"),
            withIntermediateDirectories: true
        )

        let outcome = LicenseInfoFileFallback(path: licensePath).load()

        XCTAssertEqual(outcome.info?.isServiceAllowed, false)
        XCTAssertNotNil(outcome.failureDescription)
    }

    func testValidAdmissionJournalBlocksService() throws {
        try writeLicense(status: .valid)
        try Data(#"{"armedAt":0}"#.utf8)
            .write(to: licensePath.appendingPathExtension("admission-journal"))

        let outcome = LicenseInfoFileFallback(path: licensePath).load()

        XCTAssertEqual(outcome.info?.status, .valid)
        XCTAssertEqual(outcome.info?.isServiceAllowed, false)
    }

    func testInvalidAdmissionJournalBlocksService() throws {
        try writeLicense(status: .valid)
        try Data("{ not json".utf8)
            .write(to: licensePath.appendingPathExtension("admission-journal"))

        let outcome = LicenseInfoFileFallback(path: licensePath).load()

        XCTAssertEqual(outcome.info?.isServiceAllowed, false)
        XCTAssertNotNil(outcome.failureDescription)
    }

    func testAdmissionJournalIOFailureBlocksService() throws {
        try writeLicense(status: .valid)
        try FileManager.default.createDirectory(
            at: licensePath.appendingPathExtension("admission-journal"),
            withIntermediateDirectories: true
        )

        let outcome = LicenseInfoFileFallback(path: licensePath).load()

        XCTAssertEqual(outcome.info?.isServiceAllowed, false)
        XCTAssertNotNil(outcome.failureDescription)
    }

    func testAbsentSupportDirectoryReportsNoLicenseInsteadOfFailingClosed() {
        let freshInstallPath = directory
            .appendingPathComponent("not-created-yet")
            .appendingPathComponent("license.json")

        let outcome = LicenseInfoFileFallback(path: freshInstallPath).load()

        XCTAssertNil(outcome.info)
        XCTAssertNil(outcome.failureDescription)
    }

    func testInvalidLicenseFileFailsClosed() throws {
        try Data("{ not json".utf8).write(to: licensePath)

        let outcome = LicenseInfoFileFallback(path: licensePath).load()

        XCTAssertEqual(outcome.info?.status, .unknown)
        XCTAssertEqual(outcome.info?.isServiceAllowed, false)
        XCTAssertNotNil(outcome.failureDescription)
    }

    private func writeLicense(status: LicenseStatus) throws {
        let state = LicenseState(
            licenseKey: status == .valid ? "paid-key" : nil,
            licenseId: "license-1",
            status: status,
            expiresAt: Date().addingTimeInterval(3_600)
        )
        try JSONCoding.encoder.encode(state).write(to: licensePath)
    }

    private func licenseInfo(
        status: LicenseStatus,
        isServiceAllowed: Bool
    ) -> LicenseInfo {
        LicenseInfo(
            from: LicenseState(
                licenseKey: status == .valid ? "paid-key" : nil,
                licenseId: "license-1",
                status: status,
                expiresAt: status == .valid
                    ? Date().addingTimeInterval(3_600)
                    : Date().addingTimeInterval(-3_600)
            ),
            isServiceAllowed: isServiceAllowed
        )
    }
}

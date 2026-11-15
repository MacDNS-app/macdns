// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent
@testable import Shared

final class LicenseStateFileStoreTests: XCTestCase {

    private var directory: URL!
    private var licensePath: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("license-store-tests-\(UUID().uuidString)")
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

    func testMissingFileReportsMissing() {
        let store = LicenseStateFileStore(path: licensePath)

        guard case .missing = store.load() else {
            return XCTFail("Expected missing result")
        }
    }

    func testValidFileReportsLoadedState() throws {
        let expiry = Date().addingTimeInterval(3600)
        let state = LicenseState(
            licenseId: "trial-1",
            status: .trial,
            expiresAt: expiry
        )
        let store = LicenseStateFileStore(path: licensePath)
        XCTAssertTrue(store.save(state))

        guard case .loaded(let loaded) = store.load() else {
            return XCTFail("Expected loaded result")
        }
        XCTAssertEqual(loaded.licenseId, "trial-1")
        XCTAssertEqual(loaded.status, .trial)
        XCTAssertEqual(
            loaded.expiresAt?.timeIntervalSince1970 ?? 0,
            expiry.timeIntervalSince1970,
            accuracy: 1
        )
    }

    func testCorruptFileReportsInvalidNotEmptyState() throws {
        try Data("{ not json".utf8).write(to: licensePath)
        let store = LicenseStateFileStore(path: licensePath)

        guard case .invalid = store.load() else {
            return XCTFail("Expected invalid result for corrupt file")
        }
    }

    func testTruncatedJSONReportsInvalid() throws {
        try Data("{}".utf8).write(to: licensePath)
        let store = LicenseStateFileStore(path: licensePath)

        guard case .invalid = store.load() else {
            return XCTFail("Expected invalid result for state without status")
        }
    }

    func testUnreadableFileReportsIOFailure() throws {
        try FileManager.default.createDirectory(
            at: licensePath,
            withIntermediateDirectories: true
        )
        let store = LicenseStateFileStore(path: licensePath)

        guard case .ioFailure = store.load() else {
            return XCTFail("Expected io failure when path is not a regular file")
        }
    }

    func testSaveFailureIsReported() {
        let unwritable =
            directory
            .appendingPathComponent("missing-dir")
            .appendingPathComponent("license.json")
        let store = LicenseStateFileStore(path: unwritable)

        XCTAssertFalse(store.save(LicenseState()))
    }

    func testFailClosedStateRoundTripsAndClears() {
        let store = LicenseStateFileStore(path: licensePath)
        let engagedAt = Date(timeIntervalSince1970: 1_700_000_000)
        let state = LicenseFailClosedState(
            reason: .networkGraceExpired,
            engagedAt: engagedAt
        )

        XCTAssertTrue(store.saveFailClosedState(state))

        guard case .loaded(let loaded) = store.loadFailClosedState() else {
            return XCTFail("Expected persisted fail-closed state")
        }
        XCTAssertEqual(loaded, state)
        XCTAssertTrue(store.clearFailClosedState())
        guard case .missing = store.loadFailClosedState() else {
            return XCTFail("Expected cleared fail-closed state")
        }
    }

    func testCorruptFailClosedFileReportsInvalid() throws {
        let store = LicenseStateFileStore(path: licensePath)
        try Data("{ not json".utf8).write(to: store.failClosedPath)

        guard case .invalid = store.loadFailClosedState() else {
            return XCTFail("Expected invalid fail-closed state")
        }
    }

    func testFailClosedDirectoryReportsIOFailure() throws {
        let store = LicenseStateFileStore(path: licensePath)
        try FileManager.default.createDirectory(
            at: store.failClosedPath,
            withIntermediateDirectories: true
        )

        guard case .ioFailure = store.loadFailClosedState() else {
            return XCTFail("Expected fail-closed I/O failure")
        }
        XCTAssertFalse(store.clearFailClosedState())
    }

    func testEveryPersistedLicenseFileIsOwnerOnly() throws {
        let store = LicenseStateFileStore(path: licensePath)

        XCTAssertTrue(
            store.save(LicenseState(licenseId: "trial-1", status: .trial))
        )
        XCTAssertTrue(
            store.saveFailClosedState(
                LicenseFailClosedState(
                    reason: .networkGraceExpired,
                    engagedAt: Date()
                )
            )
        )
        XCTAssertTrue(
            store.saveAdmissionJournal(
                LicenseAdmissionJournalEntry(armedAt: Date())
            )
        )
        XCTAssertTrue(
            store.saveTrustedTimeMark(
                LicenseTrustedTimeMark(serverTime: Date())
            )
        )

        let files = [
            licensePath!,
            store.failClosedPath,
            store.admissionJournalPath,
            store.trustedTimePath,
        ]
        for file in files {
            XCTAssertEqual(
                try Self.permissions(of: file),
                0o600,
                "\(file.lastPathComponent) must not be readable by other users"
            )
        }
    }

    func testSaveTightensPermissionsOfAWorldReadableFile() throws {
        try Data("{}".utf8).write(to: licensePath)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: Int16(0o644))],
            ofItemAtPath: licensePath.path
        )
        let store = LicenseStateFileStore(path: licensePath)

        XCTAssertTrue(
            store.save(LicenseState(licenseId: "trial-1", status: .trial))
        )

        XCTAssertEqual(try Self.permissions(of: licensePath), 0o600)
    }

    private static func permissions(of file: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(
            atPath: file.path
        )
        let mode = try XCTUnwrap(attributes[.posixPermissions] as? NSNumber)
        return mode.intValue & 0o777
    }

    func testOldLicenseStateDecodesWithoutMachineReactivationField() throws {
        let data = Data(
            #"{"licenseKey":"paid-key","licenseId":"license-1","machineId":"machine-1","status":"valid"}"#.utf8
        )

        let state = try JSONCoding.decoder.decode(LicenseState.self, from: data)

        XCTAssertNil(state.machineReactivationPending)
    }
}

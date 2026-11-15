// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNSAgent

final class StateDocumentWriterTests: XCTestCase {
    private let stateFile = URL(fileURLWithPath: "/unused/state.json")
    private let projectionError = NSError(
        domain: "StateDocumentWriterTests", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "projection failed"]
    )
    private let restorationError = NSError(
        domain: "StateDocumentWriterTests", code: 2,
        userInfo: [NSLocalizedDescriptionKey: "restoration failed"]
    )

    func testFailedRestorationReportsBothFailures() throws {
        let oldData = try documentData(revision: 4)
        var writes = 0

        XCTAssertThrowsError(
            try StateDocumentWriter.write(
                ["configRevision": 5], to: stateFile,
                writeData: { _, _ in
                    writes += 1
                    if writes == 2 { throw self.restorationError }
                },
                readData: { _ in oldData },
                refreshProjection: { _ in throw self.projectionError }
            )
        ) { error in
            XCTAssertTrue(error.localizedDescription.contains("projection failed"))
            XCTAssertTrue(error.localizedDescription.contains("restoration failed"))
        }
        XCTAssertEqual(writes, 2)
    }

    func testFailedRestorationReturnsTheRevisionActuallyPersisted() throws {
        var persisted = try documentData(revision: 4)
        var writes = 0
        let response = transaction {
            try StateDocumentWriter.write(
                $0, to: self.stateFile,
                writeData: { data, _ in
                    writes += 1
                    if writes == 2 { throw self.restorationError }
                    persisted = data
                },
                readData: { _ in persisted },
                refreshProjection: { _ in throw self.projectionError }
            )
        }

        XCTAssertEqual(response.status, .rejected)
        XCTAssertEqual(response.rejectionReason, .persistenceFailure)
        XCTAssertEqual(response.authoritativeRevision, 5)
        XCTAssertEqual(try JSONSerialization.jsonObject(with: persisted) as? [String: Int], ["configRevision": 5])
    }

    func testFailedRestorationDoesNotGuessAnUnreadableRevision() throws {
        let oldData = try documentData(revision: 4)
        var reads = 0
        var writes = 0
        let response = transaction {
            try StateDocumentWriter.write(
                $0, to: self.stateFile,
                writeData: { _, _ in
                    writes += 1
                    if writes == 2 { throw self.restorationError }
                },
                readData: { _ in
                    reads += 1
                    return reads == 1 ? oldData : nil
                },
                refreshProjection: { _ in throw self.projectionError }
            )
        }

        XCTAssertEqual(response.status, .rejected)
        XCTAssertNil(response.authoritativeRevision)
    }

    func testUnreadablePreviousDocumentDoesNotStartAWriteOrRemoval() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        var writes = 0
        var removals = 0
        var projections = 0

        XCTAssertThrowsError(
            try StateDocumentWriter.write(
                ["configRevision": 5], to: directory,
                writeData: { _, _ in writes += 1 },
                removeFile: { _ in removals += 1 },
                refreshProjection: { _ in
                    projections += 1
                    throw self.projectionError
                }
            )
        )

        XCTAssertEqual(writes, 0)
        XCTAssertEqual(removals, 0)
        XCTAssertEqual(projections, 0)
    }

    func testSuccessfulRestorationPreservesTheOriginalProjectionError() throws {
        let oldData = try documentData(revision: 4)
        var persisted = oldData
        var writes = 0

        XCTAssertThrowsError(
            try StateDocumentWriter.write(
                ["configRevision": 5], to: stateFile,
                writeData: { data, _ in
                    writes += 1
                    persisted = data
                },
                readData: { _ in oldData },
                refreshProjection: { _ in throw self.projectionError }
            )
        ) { error in
            XCTAssertEqual(error as NSError, self.projectionError)
        }

        XCTAssertEqual(writes, 2)
        XCTAssertEqual(persisted, oldData)
    }

    func testMissingDocumentIsRemovedAfterProjectionFailure() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("state.json")

        XCTAssertThrowsError(
            try StateDocumentWriter.write(
                ["configRevision": 1], to: file,
                refreshProjection: { _ in throw self.projectionError }
            )
        ) { error in
            XCTAssertEqual(error as NSError, self.projectionError)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }

    func testFailedRemovalReportsNewPersistedRevision() throws {
        var persisted: Data?
        XCTAssertThrowsError(
            try StateDocumentWriter.write(
                ["configRevision": 5], to: stateFile,
                writeData: { data, _ in persisted = data },
                readData: { _ in persisted },
                removeFile: { _ in throw self.restorationError },
                refreshProjection: { _ in throw self.projectionError }
            )
        ) { error in
            let failure = error as? StateDocumentWriter.RestorationFailure
            XCTAssertEqual(failure?.persistedRevision, 5)
            XCTAssertTrue(error.localizedDescription.contains("restoration failed"))
        }
    }

    func testFailedRestorationDoesNotGuessMalformedOrInvalidRevision() throws {
        for readback in [
            Data("invalid json".utf8),
            Data("[]".utf8),
            Data("{\"configRevision\":true}".utf8),
            Data("{\"configRevision\":-1}".utf8),
            Data("{\"configRevision\":\"5\"}".utf8),
        ] {
            var reads = 0
            var writes = 0
            XCTAssertThrowsError(
                try StateDocumentWriter.write(
                    ["configRevision": 5], to: stateFile,
                    writeData: { _, _ in
                        writes += 1
                        if writes == 2 { throw self.restorationError }
                    },
                    readData: { _ in
                        reads += 1
                        return reads == 1 ? try self.documentData(revision: 4) : readback
                    },
                    refreshProjection: { _ in throw self.projectionError }
                )
            ) { error in
                guard let failure = error as? StateDocumentWriter.RestorationFailure else {
                    return XCTFail("Expected both persistence failures")
                }
                XCTAssertNil(failure.persistedRevision)
            }
        }
    }

    func testFailedRestorationToleratesReadbackError() throws {
        var reads = 0
        var writes = 0
        XCTAssertThrowsError(
            try StateDocumentWriter.write(
                ["configRevision": 5], to: stateFile,
                writeData: { _, _ in
                    writes += 1
                    if writes == 2 { throw self.restorationError }
                },
                readData: { _ in
                    reads += 1
                    if reads == 2 { throw CocoaError(.fileReadNoPermission) }
                    return try self.documentData(revision: 4)
                },
                refreshProjection: { _ in throw self.projectionError }
            )
        ) { error in
            guard let failure = error as? StateDocumentWriter.RestorationFailure else {
                return XCTFail("Expected both persistence failures")
            }
            XCTAssertNil(failure.persistedRevision)
        }
    }

    private func documentData(revision: Int) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["configRevision": revision])
    }

    private func transaction(
        writeFile: ([String: Any]) throws -> Void
    ) -> FullConfigSaveResponse {
        MacDNSAgent.performFullConfigTransaction(
            classification: .accept(nextRevision: 5),
            persistedRevision: 4,
            oldConfig: ["configRevision": 4],
            fullConfig: ["configRevision": 4],
            prepareAccepted: { _ in
                .ready(
                    MacDNSAgent.FullConfigTransactionContext(
                        resolverRunning: true,
                        backendBounceRequired: false,
                        applyOptions: {
                            XCTFail("Persistence failure must not change the running resolver")
                            return .applied
                        },
                        performBackendBounce: { _ in
                            XCTFail("Persistence failure must not bounce DNS")
                            return false
                        },
                        applyHistory: {
                            XCTFail("Persistence failure must not change lookup history")
                            return false
                        },
                        rollback: { _ in
                            XCTFail("Persistence failure must not stop DNS through rollback recovery")
                            return false
                        },
                        didCommit: { XCTFail("A failed persistence transaction cannot commit") }
                    )
                )
            },
            writeFile: writeFile,
            syncAllowlist: { _ in
                XCTFail("A failed persistence transaction cannot apply allowlist state")
                return false
            },
            applyZonesAndOverrides: { _ in
                XCTFail("A failed persistence transaction cannot apply DNS policy")
                return false
            },
            reloadBlocklist: {
                XCTFail("A failed persistence transaction cannot reload the blocklist")
                return false
            }
        )
    }
}

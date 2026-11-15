// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import XCTest

@testable import Shared

/// `StateFileLock` must key both its in-process lock and its recursion depth by
/// the individual lock-file path. Nesting two distinct state files has to take
/// both `flock`s, and unrelated files must not serialize against each other. A
/// full-config transaction blocking license I/O delays fail-closed licensing.
final class StateFileLockPolicyTests: XCTestCase {

    private var directory: URL!
    private var stateFile: URL!
    private var licenseFile: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("state-file-lock-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        stateFile = directory.appendingPathComponent("state.json")
        licenseFile = directory.appendingPathComponent("license.json")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
        try super.tearDownWithError()
    }

    func testNestedDistinctFilesHoldBothFileLocks() throws {
        try StateFileLock.withExclusiveLock(stateFile: stateFile) {
            try StateFileLock.withExclusiveLock(stateFile: licenseFile) {
                XCTAssertFalse(
                    canAcquireFileLock(for: stateFile),
                    "outer state.json flock must stay held"
                )
                XCTAssertFalse(
                    canAcquireFileLock(for: licenseFile),
                    "nested license.json flock must be acquired, not skipped"
                )
            }
        }
    }

    func testSamePathRecursionReentersWithoutDeadlock() throws {
        let value = try StateFileLock.withExclusiveLock(stateFile: stateFile) {
            try StateFileLock.withExclusiveLock(stateFile: stateFile) {
                canAcquireFileLock(for: stateFile) ? "unlocked" : "locked"
            }
        }
        XCTAssertEqual(value, "locked")
        XCTAssertTrue(
            canAcquireFileLock(for: stateFile),
            "both nesting levels must release the flock"
        )
    }

    func testDistinctFilesDoNotSerializeAgainstEachOther() throws {
        let otherEntered = DispatchSemaphore(value: 0)
        var overlapped = false

        try StateFileLock.withExclusiveLock(stateFile: stateFile) {
            let licenseFile = self.licenseFile!
            DispatchQueue.global().async {
                _ = try? StateFileLock.withExclusiveLock(stateFile: licenseFile) {
                    otherEntered.signal()
                }
            }
            overlapped = otherEntered.wait(timeout: .now() + 5) == .success
        }

        XCTAssertTrue(
            overlapped,
            "license.json lock must not wait on an unrelated state.json transaction"
        )
    }

    func testSameFileOperationsStaySerialized() throws {
        let otherEntered = DispatchSemaphore(value: 0)

        try StateFileLock.withExclusiveLock(stateFile: stateFile) {
            let stateFile = self.stateFile!
            DispatchQueue.global().async {
                _ = try? StateFileLock.withExclusiveLock(stateFile: stateFile) {
                    otherEntered.signal()
                }
            }
            XCTAssertEqual(
                otherEntered.wait(timeout: .now() + 0.5),
                .timedOut,
                "a second holder must not enter while the file lock is held"
            )
        }

        XCTAssertEqual(otherEntered.wait(timeout: .now() + 5), .success)
    }

    /// Opens a second description of the lock file and probes it without
    /// blocking. `flock` conflicts across descriptions even inside one process,
    /// so `false` proves `withExclusiveLock` really holds the file lock.
    private func canAcquireFileLock(for stateFile: URL) -> Bool {
        let lockFile = stateFile.appendingPathExtension("lock")
        let descriptor = lockFile.path.withCString {
            Darwin.open($0, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        }
        guard descriptor >= 0 else {
            XCTFail("failed to open \(lockFile.path)")
            return false
        }
        defer { Darwin.close(descriptor) }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else { return false }
        flock(descriptor, LOCK_UN)
        return true
    }
}

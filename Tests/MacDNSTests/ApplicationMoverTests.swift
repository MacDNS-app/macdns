// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import XCTest

@testable import MacDNS

final class ApplicationMoverTests: XCTestCase {
    private static let quarantine = "com.apple.quarantine"
    private var root: URL!
    private var applications: URL!
    private var source: URL!
    private var readOnlyDirectory: URL?

    private final class Recycled: @unchecked Sendable {
        private let lock = NSLock()
        private var urls: [URL] = []

        func record(_ url: URL) {
            lock.lock()
            defer { lock.unlock() }
            urls.append(url)
        }

        var all: [URL] {
            lock.lock()
            defer { lock.unlock() }
            return urls
        }
    }

    override func setUpWithError() throws {
        let fileManager = FileManager.default
        root = fileManager.temporaryDirectory
            .appendingPathComponent("ApplicationMoverTests-\(UUID().uuidString)")
        applications = root.appendingPathComponent("Applications")
        let downloads = root.appendingPathComponent("Downloads")
        try fileManager.createDirectory(at: applications, withIntermediateDirectories: true)
        source = downloads.appendingPathComponent("MacDNS.app")
        let macOS = source.appendingPathComponent("Contents/MacOS")
        try fileManager.createDirectory(at: macOS, withIntermediateDirectories: true)
        try Data("plist".utf8).write(to: source.appendingPathComponent("Contents/Info.plist"))
        try Data("binary".utf8).write(to: macOS.appendingPathComponent("MacDNS"))
        let versions = source.appendingPathComponent("Contents/Frameworks/Fake.framework/Versions")
        try fileManager.createDirectory(
            at: versions.appendingPathComponent("A"), withIntermediateDirectories: true)
        try Data("lib".utf8).write(to: versions.appendingPathComponent("A/Fake"))
        try fileManager.createSymbolicLink(
            atPath: versions.appendingPathComponent("Current").path, withDestinationPath: "A")
        for item in Self.items(in: source) {
            XCTAssertEqual(
                setxattr(item.path, Self.quarantine, "0083;0;Safari;", 14, 0, XATTR_NOFOLLOW), 0, item.path)
            XCTAssertTrue(hasQuarantine(item), item.path)
        }
    }

    override func tearDownWithError() throws {
        if let readOnlyDirectory {
            chmod(readOnlyDirectory.path, 0o755)
        }
        try? FileManager.default.removeItem(at: root)
    }

    /// The bundle root plus every file, directory and symlink beneath it.
    private static func items(in bundle: URL) -> [URL] {
        let enumerator = FileManager.default.enumerator(at: bundle, includingPropertiesForKeys: nil)
        return [bundle] + (enumerator?.allObjects as? [URL] ?? [])
    }

    private func hasQuarantine(_ url: URL) -> Bool {
        getxattr(url.path, Self.quarantine, nil, 0, 0, XATTR_NOFOLLOW) >= 0
    }

    private func makeMover(
        applicationsDirectory: URL? = nil,
        recycled: Recycled = Recycled()
    ) -> ApplicationMover {
        ApplicationMover(
            applicationsDirectory: applicationsDirectory ?? applications,
            recycle: { recycled.record($0) }
        )
    }

    func testCopiesTheBundleAndKeepsTheSource() async throws {
        let copy = try await makeMover().install(source)

        XCTAssertEqual(copy.path, applications.appendingPathComponent("MacDNS.app").path)
        XCTAssertEqual(
            try String(contentsOf: copy.appendingPathComponent("Contents/Info.plist"), encoding: .utf8), "plist")
        XCTAssertEqual(
            try String(contentsOf: copy.appendingPathComponent("Contents/MacOS/MacDNS"), encoding: .utf8), "binary")
        XCTAssertTrue(FileManager.default.fileExists(atPath: source.appendingPathComponent("Contents/Info.plist").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: source.appendingPathComponent("Contents/MacOS/MacDNS").path))
    }

    func testCopyHasNoQuarantineAttribute() async throws {
        let sourceItems = Self.items(in: source)
        XCTAssertEqual(sourceItems.count, 11)
        XCTAssertTrue(sourceItems.allSatisfy(hasQuarantine))

        let copy = try await makeMover().install(source)

        let copiedItems = Self.items(in: copy)
        XCTAssertEqual(copiedItems.count, 11)
        for item in copiedItems {
            XCTAssertFalse(hasQuarantine(item), item.path)
        }
        XCTAssertTrue(sourceItems.allSatisfy(hasQuarantine), "source must keep its attributes")
    }

    func testSymlinkInsideTheBundleIsCopiedAsSymlink() async throws {
        let copy = try await makeMover().install(source)

        let link = copy.appendingPathComponent("Contents/Frameworks/Fake.framework/Versions/Current").path
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: link), "A")
    }

    func testInstallingTheBundleOntoItselfThrowsWithoutRecyclingOrCopying() async throws {
        let installed = applications.appendingPathComponent("MacDNS.app")
        try FileManager.default.copyItem(at: source, to: installed)
        let recycled = Recycled()

        do {
            _ = try await makeMover(recycled: recycled).install(installed)
            XCTFail("expected copyFailed")
        } catch let error as ApplicationMoveError {
            guard case .copyFailed = error else { return XCTFail("unexpected \(error)") }
        }
        XCTAssertEqual(recycled.all, [])
        XCTAssertTrue(FileManager.default.fileExists(atPath: installed.appendingPathComponent("Contents/Info.plist").path))
    }

    func testExistingCopyIsRecycledThenReplaced() async throws {
        let existing = applications.appendingPathComponent("MacDNS.app")
        try FileManager.default.createDirectory(at: existing, withIntermediateDirectories: true)
        try Data().write(to: existing.appendingPathComponent("marker"))
        let recycled = Recycled()
        let mover = ApplicationMover(
            applicationsDirectory: applications,
            recycle: { url in
                recycled.record(url)
                try FileManager.default.removeItem(at: url)
            })

        let copy = try await mover.install(source)

        XCTAssertEqual(recycled.all.map(\.path), [existing.path])
        XCTAssertFalse(FileManager.default.fileExists(atPath: copy.appendingPathComponent("marker").path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: copy.appendingPathComponent("Contents/Info.plist").path))
    }

    /// A second download lands as "MacDNS 2.app". It must still replace the
    /// one install the system extension and the Agent registration point at.
    func testRenamedDownloadReplacesMacDNSApp() async throws {
        let renamed = source.deletingLastPathComponent().appendingPathComponent("MacDNS 2.app")
        try FileManager.default.moveItem(at: source, to: renamed)
        let existing = applications.appendingPathComponent("MacDNS.app")
        try FileManager.default.createDirectory(at: existing, withIntermediateDirectories: true)
        try Data().write(to: existing.appendingPathComponent("marker"))
        let recycled = Recycled()
        let mover = ApplicationMover(
            applicationsDirectory: applications,
            recycle: { url in
                recycled.record(url)
                try FileManager.default.removeItem(at: url)
            })

        let copy = try await mover.install(renamed)

        XCTAssertEqual(copy.path, existing.path)
        XCTAssertEqual(recycled.all.map(\.path), [existing.path])
        XCTAssertTrue(FileManager.default.fileExists(atPath: copy.appendingPathComponent("Contents/Info.plist").path))
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: applications.appendingPathComponent("MacDNS 2.app").path))
    }

    func testRecycleFailureThrowsCopyFailedAndKeepsExistingCopy() async throws {
        let existing = applications.appendingPathComponent("MacDNS.app")
        try FileManager.default.createDirectory(at: existing, withIntermediateDirectories: true)
        try Data().write(to: existing.appendingPathComponent("marker"))
        struct RecycleError: LocalizedError { var errorDescription: String? { "trash unavailable" } }
        let mover = ApplicationMover(applicationsDirectory: applications, recycle: { _ in throw RecycleError() })

        do {
            _ = try await mover.install(source)
            XCTFail("expected copyFailed")
        } catch let error as ApplicationMoveError {
            XCTAssertEqual(error, .copyFailed("trash unavailable"))
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: existing.appendingPathComponent("marker").path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: existing.appendingPathComponent("Contents").path))
    }

    func testUnwritableDestinationThrowsCopyFailed() async throws {
        let locked = root.appendingPathComponent("Locked")
        try FileManager.default.createDirectory(at: locked, withIntermediateDirectories: true)
        XCTAssertEqual(chmod(locked.path, 0o555), 0)
        readOnlyDirectory = locked

        do {
            _ = try await makeMover(applicationsDirectory: locked).install(source)
            XCTFail("expected copyFailed")
        } catch let error as ApplicationMoveError {
            guard case .copyFailed = error else { return XCTFail("unexpected \(error)") }
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: locked.appendingPathComponent("MacDNS.app").path))
    }
}

// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import ContentFilterExtension

final class ContentFilterProcessValidatorTests: XCTestCase {
    private let teamIdentifier = "TEAM123"

    func testAcceptsCanonicalRolePathsWithMatchingIdentity() {
        XCTAssertTrue(
            isTrusted(
                path: "/Applications/MacDNS.app/Contents/MacOS/MacDNSAgent",
                signingIdentifier: "app.macdns.agent"
            )
        )
        XCTAssertTrue(
            isTrusted(
                path:
                    "/Library/SystemExtensions/UUID/app.macdns.dnsproxy.systemextension/Contents/MacOS/app.macdns.dnsproxy",
                signingIdentifier: "app.macdns.dnsproxy"
            )
        )
        XCTAssertTrue(
            isTrusted(
                path:
                    "/Library/SystemExtensions/UUID/app.macdns.contentfilter.systemextension/Contents/MacOS/app.macdns.contentfilter",
                signingIdentifier: "app.macdns.contentfilter"
            )
        )
    }

    func testRejectsPathWithoutCanonicalRoleLayout() {
        XCTAssertFalse(
            isTrusted(
                path: "/Users/test/Fake/MacDNS.app/Contents/Helpers/MacDNSAgent",
                signingIdentifier: "app.macdns.agent"
            )
        )
        XCTAssertFalse(
            isTrusted(
                path: "/tmp/MacDNSAgent",
                signingIdentifier: "app.macdns.agent"
            )
        )
        XCTAssertFalse(
            isTrusted(
                path: "/tmp/MacDNS.app/Contents/MacOS/MacDNSAgent-copy",
                signingIdentifier: "app.macdns.agent"
            )
        )
    }

    func testRejectsIdentifierThatDoesNotMatchPathRole() {
        XCTAssertFalse(
            isTrusted(
                path: "/Applications/MacDNS.app/Contents/MacOS/MacDNSAgent",
                signingIdentifier: "app.macdns.dnsproxy"
            )
        )
    }

    func testRejectsUnexpectedTeamIdentifier() {
        XCTAssertFalse(
            isTrusted(
                path: "/Applications/MacDNS.app/Contents/MacOS/MacDNSAgent",
                signingIdentifier: "app.macdns.agent",
                actualTeamIdentifier: "OTHER"
            )
        )
    }

    func testRejectsInvalidStaticSignature() {
        XCTAssertFalse(
            isTrusted(
                path: "/Applications/MacDNS.app/Contents/MacOS/MacDNSAgent",
                signingIdentifier: "app.macdns.agent",
                signatureValid: false
            )
        )
    }

    func testCanonicalPathResolvesSymlinkBeforeRoleMatching() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let executable =
            root
            .appendingPathComponent("MacDNS.app/Contents/MacOS/MacDNSAgent")
        try FileManager.default.createDirectory(
            at: executable.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data().write(to: executable)
        let symlink = root.appendingPathComponent("agent-link")
        try FileManager.default.createSymbolicLink(
            at: symlink,
            withDestinationURL: executable
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let canonical = ContentFilterProcessValidator.canonicalPath(
            symlink.path
        )

        XCTAssertEqual(canonical, executable.standardizedFileURL.path)
        XCTAssertEqual(
            ContentFilterProcessValidator.role(forCanonicalPath: canonical),
            .agent
        )
    }

    private func isTrusted(
        path: String,
        signingIdentifier: String,
        actualTeamIdentifier: String = "TEAM123",
        signatureValid: Bool = true
    ) -> Bool {
        ContentFilterProcessValidator.isTrusted(
            snapshot: ContentFilterProcessSnapshot(
                canonicalPath: path,
                signingIdentifier: signingIdentifier,
                teamIdentifier: actualTeamIdentifier,
                signatureValid: signatureValid
            ),
            expectedTeamIdentifier: teamIdentifier
        )
    }
}

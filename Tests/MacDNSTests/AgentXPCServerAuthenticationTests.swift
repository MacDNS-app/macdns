// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Security
import Shared
import XCTest

@testable import MacDNS

/// The App sends the license key to `app.macdns.agent`, so the Agent has to be
/// authenticated before the connection is resumed. Otherwise any process running
/// as the same user can register that Mach service name and harvest the key.
/// `XPCClient` cannot be exercised against a live Mach service in a test process,
/// so the requirement and the moment it is installed are pinned here.
final class AgentXPCServerAuthenticationTests: XCTestCase {

    func testRequirementPinsIdentifierAnchorAndTeam() {
        XCTAssertEqual(
            XPCClient.agentCodeRequirement,
            "identifier \"app.macdns.agent\" and anchor apple generic and "
                + "certificate leaf[subject.OU] = \"MY427949GW\""
        )
    }

    /// One Team ID literal for the whole product. A second copy could drift from
    /// the identity the build signs with (`check_source_signing_inputs` only ties
    /// the proxy-control constants to `TEAM_ID`) and lock the App out of its Agent.
    func testRequirementReusesTheAgentIdentityPinnedForProxyControl() {
        XCTAssertEqual(XPCClient.agentCodeRequirement, proxyControlAgentRequirement)
    }

    /// `setCodeSigningRequirement` raises an Objective-C exception on a malformed
    /// string, which would crash the App instead of rejecting an impostor.
    func testRequirementParsesAsASecRequirement() {
        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString(
            XPCClient.agentCodeRequirement as CFString,
            SecCSFlags(),
            &requirement
        )

        XCTAssertEqual(status, errSecSuccess)
        XCTAssertNotNil(requirement)
    }

    /// A requirement installed after `resume()` leaves a window in which the App
    /// can already message an unauthenticated peer.
    func testTheRequirementIsInstalledBeforeTheConnectionResumes() throws {
        let source = try source("Sources/MacDNS/Services/XPCClient.swift")
        let pinned = try XCTUnwrap(
            source.range(of: "setCodeSigningRequirement(Self.agentCodeRequirement)"),
            "the agent connection is created without a code-signing requirement"
        )
        let resumed = try XCTUnwrap(
            source.range(of: "newConnection.resume()"),
            "getConnection no longer resumes the agent connection"
        )

        XCTAssertLessThan(
            pinned.lowerBound,
            resumed.lowerBound,
            "the requirement must be installed before the connection is resumed"
        )
    }

    /// A rejected Agent and an absent Agent are indistinguishable from the client
    /// side, so the pinned requirement has to reach the log at least once and,
    /// since invalidation fires on every failed attempt, at most once per session.
    func testRejectedConnectionsAreDiagnosable() throws {
        let source = try source("Sources/MacDNS/Services/XPCClient.swift")

        XCTAssertTrue(
            source.contains("logFirstConnectionInvalidation()"),
            "connection invalidation must report why the agent channel is unusable"
        )
        XCTAssertTrue(
            source.contains("didLogConnectionInvalidation = true"),
            "the invalidation report must be latched so retries cannot flood the log"
        )
    }

    private func source(
        _ relativePath: String,
        from filePath: String = #filePath
    ) throws -> String {
        var directory = URL(fileURLWithPath: filePath).deletingLastPathComponent()
        while directory.path != "/" {
            let candidate = directory.appendingPathComponent(relativePath)
            if FileManager.default.fileExists(atPath: candidate.path) {
                return try String(contentsOf: candidate, encoding: .utf8)
            }
            directory = directory.deletingLastPathComponent()
        }
        throw XCTSkip("\(relativePath) not found above the test source path")
    }
}

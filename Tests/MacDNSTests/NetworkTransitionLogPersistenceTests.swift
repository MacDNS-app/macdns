// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

/// The unified log does not persist `.info`, so a network transition logged at
/// that level is gone by the time anyone runs `log show`. These lines are the
/// only record of which DNS path the agent chose, so they must use `.notice`.
final class NetworkTransitionLogPersistenceTests: XCTestCase {
    func testDetectorOutcomeTransitionsPersist() throws {
        let detector = try source("Sources/MacDNSAgent/Services/CaptivePortalDetector.swift")

        for message in [
            "Captive connectivity transition http=",
            "Captive portal detected, polling every",
        ] {
            XCTAssertEqual(try level(of: message, in: detector), "notice", message)
        }
    }

    func testDetectorTransitionRecordsNetworkDNSEvidence() throws {
        let detector = try source("Sources/MacDNSAgent/Services/CaptivePortalDetector.swift")
        let line = try XCTUnwrap(
            detector.components(separatedBy: "\n").first {
                $0.contains("Captive connectivity transition http=")
            }
        )

        XCTAssertTrue(line.contains("network-dns=\\(networkDNS.rawValue)"))
    }

    func testAgentForwardingAndBypassTransitionsPersist() throws {
        let agent = try source("Sources/MacDNSAgent/MacDNSAgent.swift")

        for message in [
            "Network status changed: connected=",
            "Forwarding mode disabled due to network change",
            "Network compatibility mode enabled with DHCP DNS",
            "Portal cleared; restored scoped network compatibility forwarding",
            "Direct DoH health restored; network compatibility forwarding disabled",
            "Captive portal bypass enabled",
            "Captive portal bypass disabled - DNS back to local backend",
            "Captive-portal bypass approval dropped",
            "Captive-portal full bypass approved by the user",
        ] {
            XCTAssertEqual(try level(of: message, in: agent), "notice", message)
        }
    }

    /// The `AgentLogger` method that emits `message`, read from the closest
    /// call before the literal.
    private func level(of message: String, in contents: String) throws -> String {
        let literal = try XCTUnwrap(
            contents.range(of: "\"\(message)"),
            "missing log message: \(message)"
        )
        let call = try XCTUnwrap(
            contents.range(
                of: "AgentLogger.shared.",
                options: .backwards,
                range: contents.startIndex..<literal.lowerBound
            )
        )
        let remainder = contents[call.upperBound..<literal.lowerBound]
        return String(remainder.prefix { $0.isLetter })
    }

    private var repositoryRoot: URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<3 {
            url.deleteLastPathComponent()
        }
        return url
    }

    private func source(_ relativePath: String) throws -> String {
        try String(
            contentsOf: repositoryRoot.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }
}

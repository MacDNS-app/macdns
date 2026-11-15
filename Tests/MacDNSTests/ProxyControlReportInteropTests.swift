// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import DNSProxyExtension
@testable import Shared

/// Guards the JSON key contract between the provider's report encoder
/// (`ProxyInterceptionState.encodedReport`) and the Shared `ProxyControlStateReport`
/// decoder used by the agent. A typo on either side silently breaks the
/// stale-version restart detection.
final class ProxyControlReportInteropTests: XCTestCase {
    func testProviderVersionSurvivesExtensionToSharedDecode() throws {
        let data = try XCTUnwrap(
            DNSProxyExtension.ProxyInterceptionState
                .intercepting(sessionID: "logs-only").encodedReport(providerVersion: "1.2.0.519"))
        let report = try JSONDecoder().decode(Shared.ProxyControlStateReport.self, from: data)
        XCTAssertEqual(report.state, "intercepting")
        XCTAssertNil(report.reason)
        XCTAssertEqual(report.providerVersion, "1.2.0.519")
    }

    func testBypassReportOmitsVersionWhenNil() throws {
        let data = try XCTUnwrap(
            DNSProxyExtension.ProxyInterceptionState
                .bypass(.probeFailed).encodedReport(providerVersion: nil))
        let report = try JSONDecoder().decode(Shared.ProxyControlStateReport.self, from: data)
        XCTAssertEqual(report.state, "bypass")
        XCTAssertEqual(report.reason, "probeFailed")
        XCTAssertNil(report.providerVersion)
    }

    // MARK: - Constant Drift

    /// The provider cannot import `Shared`, so every proxy-control constant it
    /// needs exists twice. Nothing in the build fails when one copy is edited
    /// alone: the agent then talks to a Mach service the provider never
    /// registered, or presents a code-sign requirement the provider rejects, and
    /// the provider stays in bypass until someone notices DNS is unprotected.
    func testMachServiceNameMatchesShared() {
        XCTAssertEqual(
            DNSProxyExtension.machServiceName,
            Shared.proxyControlMachServiceName
        )
    }

    func testAgentRequirementMatchesShared() {
        XCTAssertEqual(
            DNSProxyExtension.proxyControlAgentRequirement,
            Shared.proxyControlAgentRequirement
        )
    }

    func testMaxPayloadBytesMatchesShared() {
        XCTAssertEqual(
            DNSProxyExtension.maxPayloadBytes,
            Shared.proxyControlMaxPayloadBytes
        )
    }

    /// A reason the App cannot decode collapses to `unknown`, hiding why the
    /// provider stopped intercepting. Comparing the raw-value sets catches a
    /// case added on one side only.
    func testBypassReasonsMatchShared() {
        let provider = Set(
            DNSProxyExtension.ProxyInterceptionReason.allCases.map(\.rawValue)
        )
        let shared = Set(
            Shared.ProxyInterceptionReason.allCases.map(\.rawValue)
        )
        XCTAssertEqual(provider, shared)
    }

    /// Every provider reason must survive the wire round-trip the App performs,
    /// not just the one spot-checked above.
    func testEveryBypassReasonDecodesIntoSharedState() throws {
        for reason in DNSProxyExtension.ProxyInterceptionReason.allCases {
            let data = try XCTUnwrap(
                DNSProxyExtension.ProxyInterceptionState
                    .bypass(reason).encodedReport(providerVersion: nil),
                "encoding failed for \(reason.rawValue)"
            )
            let report = try JSONDecoder().decode(
                Shared.ProxyControlStateReport.self, from: data)
            XCTAssertNotNil(
                Shared.ProxyInterceptionState(report: report),
                "App cannot decode bypass reason \(reason.rawValue)"
            )
        }
    }
}

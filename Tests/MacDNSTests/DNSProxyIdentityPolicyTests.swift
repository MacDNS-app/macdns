// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import DNSProxyExtension

final class DNSProxyIdentityPolicyTests: XCTestCase {

    private func evidence(
        claimedIdentifier: String = "app.macdns.agent",
        hasAuditToken: Bool = true,
        resolvedRole: DNSProxyProcessRole? = .agent,
        staticIdentifier: String? = "app.macdns.agent",
        staticTeamIdentifier: String? = "TEAMID1234",
        staticCodeValid: Bool = true,
        sourceCDHashMatches: Bool = true
    ) -> DNSProxyPassthroughEvidence {
        DNSProxyPassthroughEvidence(
            claimedSigningIdentifier: claimedIdentifier,
            hasAuditToken: hasAuditToken,
            resolvedRole: resolvedRole,
            staticSigningIdentifier: staticIdentifier,
            staticTeamIdentifier: staticTeamIdentifier,
            staticCodeValid: staticCodeValid,
            sourceCDHashMatches: sourceCDHashMatches
        )
    }

    private func isTrusted(_ evidence: DNSProxyPassthroughEvidence) -> Bool {
        DNSProxyIdentityPolicy.isPassthrough(
            evidence: evidence,
            expectedTeamIdentifier: "TEAMID1234"
        )
    }

    func testFullyVerifiedAgentIsPassthrough() {
        XCTAssertTrue(isTrusted(evidence()))
    }

    func testDNSProxyRoleIsPassthrough() {
        XCTAssertTrue(
            isTrusted(
                evidence(
                    claimedIdentifier: "app.macdns.dnsproxy",
                    resolvedRole: .dnsProxy,
                    staticIdentifier: "app.macdns.dnsproxy"
                )
            )
        )
    }

    func testUnknownClaimedIdentifierIsRejected() {
        XCTAssertFalse(
            isTrusted(
                evidence(
                    claimedIdentifier: "com.attacker.tool",
                    resolvedRole: nil,
                    staticIdentifier: "com.attacker.tool"
                )
            )
        )
    }

    func testRejectsSubstringPrefixSuffixAndCaseVariants() {
        for claimed in [
            "evil.app.macdns.agent",
            "app.macdns.agent.helper",
            "APP.MACDNS.AGENT",
            "",
        ] {
            XCTAssertFalse(
                isTrusted(evidence(claimedIdentifier: claimed)),
                "expected \(claimed) to be rejected"
            )
        }
    }

    func testSpoofedIdentifierWithoutAuditTokenIsRejected() {
        XCTAssertFalse(isTrusted(evidence(hasAuditToken: false)))
    }

    func testPathOutsideExpectedRoleIsRejected() {
        XCTAssertFalse(isTrusted(evidence(resolvedRole: nil)))
    }

    func testStaticIdentifierMismatchIsRejected() {
        XCTAssertFalse(isTrusted(evidence(staticIdentifier: "com.attacker.tool")))
    }

    func testClaimedIdentifierNotMatchingResolvedRoleIsRejected() {
        XCTAssertFalse(
            isTrusted(
                evidence(
                    claimedIdentifier: "app.macdns.agent",
                    resolvedRole: .dnsProxy,
                    staticIdentifier: "app.macdns.dnsproxy"
                )
            )
        )
    }

    func testForeignTeamIdentifierIsRejected() {
        XCTAssertFalse(isTrusted(evidence(staticTeamIdentifier: "OTHERTEAM0")))
    }

    func testMissingTeamIdentifierIsRejected() {
        XCTAssertFalse(isTrusted(evidence(staticTeamIdentifier: nil)))
    }

    func testInvalidStaticCodeIsRejected() {
        XCTAssertFalse(isTrusted(evidence(staticCodeValid: false)))
    }

    func testReplacedBinaryWithMismatchedCDHashIsRejected() {
        XCTAssertFalse(isTrusted(evidence(sourceCDHashMatches: false)))
    }

    // MARK: - Role Resolution

    func testRoleResolutionRequiresCanonicalTerminalPath() {
        XCTAssertEqual(
            DNSProxyBypassableRoles.role(
                forCanonicalPath: "/Applications/MacDNS.app/Contents/MacOS/MacDNSAgent"
            ),
            .agent
        )
        XCTAssertEqual(
            DNSProxyBypassableRoles.role(
                forCanonicalPath:
                    "/Library/SystemExtensions/ABC/app.macdns.dnsproxy.systemextension/Contents/MacOS/app.macdns.dnsproxy"
            ),
            .dnsProxy
        )
    }

    func testRoleResolutionRejectsLookalikePaths() {
        XCTAssertNil(
            DNSProxyBypassableRoles.role(
                forCanonicalPath: "/tmp/evil/MacDNS.app/Contents/MacOS/MacDNSAgent.backup"
            )
        )
        XCTAssertNil(
            DNSProxyBypassableRoles.role(forCanonicalPath: "/tmp/MacDNSAgent")
        )
    }
}

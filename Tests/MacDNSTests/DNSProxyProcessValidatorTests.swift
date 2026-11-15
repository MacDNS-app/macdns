// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Security
import XCTest

@testable import DNSProxyExtension

final class DNSProxyProcessValidatorTests: XCTestCase {

    func testRoleRequirementsUseExactDesignatedRequirementConstraints() {
        let teamIdentifier = "TEAMID1234"
        let expectations: [(DNSProxyProcessRole, String)] = [
            (
                .agent,
                #"anchor apple generic and identifier "app.macdns.agent" and certificate leaf[subject.OU] = "TEAMID1234""#
            ),
            (
                .dnsProxy,
                #"anchor apple generic and identifier "app.macdns.dnsproxy" and certificate leaf[subject.OU] = "TEAMID1234""#
            ),
        ]

        for (role, expectedRequirement) in expectations {
            let requirementString = DNSProxyProcessValidator.requirementString(
                for: role,
                expectedTeamIdentifier: teamIdentifier
            )
            XCTAssertEqual(requirementString, expectedRequirement)

            var requirement: SecRequirement?
            XCTAssertEqual(
                SecRequirementCreateWithString(
                    requirementString as CFString,
                    SecCSFlags(),
                    &requirement
                ),
                errSecSuccess
            )
            XCTAssertNotNil(requirement)
        }
    }

    func testCacheKeySeparatesResolvedRoleAndClaimedIdentifier() {
        let cache = DNSProxyValidationCache(maxEntries: 3)
        let base = cacheKey(role: .agent, claimedIdentifier: "app.macdns.agent")
        let changedRole = cacheKey(
            role: .dnsProxy,
            claimedIdentifier: "app.macdns.agent"
        )
        let changedClaim = cacheKey(
            role: .agent,
            claimedIdentifier: "app.macdns.dnsproxy"
        )

        cache.insert(true, for: base)
        cache.insert(false, for: changedRole)
        cache.insert(false, for: changedClaim)

        XCTAssertEqual(cache.value(for: base), true)
        XCTAssertEqual(cache.value(for: changedRole), false)
        XCTAssertEqual(cache.value(for: changedClaim), false)
    }

    func testCacheEvictsOldestEntryAtDeterministicCapacity() {
        let cache = DNSProxyValidationCache(maxEntries: 2)
        let first = cacheKey(pid: 1)
        let second = cacheKey(pid: 2)
        let third = cacheKey(pid: 3)

        cache.insert(true, for: first)
        cache.insert(false, for: second)
        XCTAssertEqual(cache.value(for: first), true)

        cache.insert(true, for: third)

        XCTAssertNil(cache.value(for: first))
        XCTAssertEqual(cache.value(for: second), false)
        XCTAssertEqual(cache.value(for: third), true)
        XCTAssertEqual(cache.count, 2)
    }

    func testValidatorCacheExpiresNegativeVerdictAtOneSecond() {
        var now: TimeInterval = 100
        let cache = DNSProxyProcessValidator.makeCache(maxEntries: 4, now: { now })
        let rejected = cacheKey(pid: 1)
        let trusted = cacheKey(pid: 2)

        cache.insert(false, for: rejected)
        cache.insert(true, for: trusted)

        now = 100.999
        XCTAssertEqual(cache.value(for: rejected), false)

        // An expired verdict is absent, so the next flow validates in full.
        now = 101
        XCTAssertNil(cache.value(for: rejected))

        now = 10_000
        XCTAssertEqual(cache.value(for: trusted), true)
    }

    private func cacheKey(
        pid: Int32 = 42,
        role: DNSProxyProcessRole? = .agent,
        claimedIdentifier: String = "app.macdns.agent"
    ) -> DNSProxyProcessCacheKey {
        DNSProxyProcessCacheKey(
            pid: pid,
            pidVersion: 7,
            sourceIdentifier: Data([0x01, 0x02, 0x03]),
            resolvedRole: role,
            claimedSigningIdentifier: claimedIdentifier
        )
    }
}

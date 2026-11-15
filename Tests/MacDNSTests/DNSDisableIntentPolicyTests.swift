// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class DNSDisableIntentPolicyTests: XCTestCase {
    func testTeardownFailureCannotPreventDisabledIntentPersistence() async {
        var executed: [DNSDisableStep] = []

        let outcome = await DNSDisableIntentPolicy.execute { step in
            executed.append(step)
            return step != .disableDNSProxy
        }

        XCTAssertEqual(outcome, .abortedAfter(.disableDNSProxy))
        XCTAssertEqual(executed, [.persistDisabledIntent, .disableDNSProxy])
        XCTAssertEqual(
            executed.first,
            .persistDisabledIntent,
            "Disabled intent must be persisted before the first teardown await"
        )
    }

    func testContentFilterTeardownFailureStillPersistedIntentFirst() async {
        var executed: [DNSDisableStep] = []

        let outcome = await DNSDisableIntentPolicy.execute { step in
            executed.append(step)
            return step != .disableContentFilter
        }

        XCTAssertEqual(outcome, .abortedAfter(.disableContentFilter))
        XCTAssertEqual(
            executed,
            [.persistDisabledIntent, .disableDNSProxy, .disableContentFilter]
        )
    }

    func testFullTeardownRunsEveryStepInOrder() async {
        var executed: [DNSDisableStep] = []

        let outcome = await DNSDisableIntentPolicy.execute { step in
            executed.append(step)
            return true
        }

        XCTAssertEqual(outcome, .completed)
        XCTAssertEqual(executed, DNSDisableIntentPolicy.orderedSteps)
        XCTAssertEqual(
            DNSDisableIntentPolicy.orderedSteps.first,
            .persistDisabledIntent
        )
    }
}

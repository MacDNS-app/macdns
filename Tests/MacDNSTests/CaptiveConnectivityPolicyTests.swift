// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent

final class CaptiveConnectivityPolicyTests: XCTestCase {
    func testCaptiveHTTPEvidenceWinsWithoutDoH() {
        XCTAssertEqual(
            decide(http: .captive, directDoH: .notRun, resolver: .unavailable),
            .candidate(.captive)
        )
    }

    func testHealthyRequiresHTTPNormalAndDirectDoHSuccess() {
        XCTAssertEqual(
            decide(http: .normal, directDoH: .success, resolver: .available(warmingUp: false)),
            .candidate(.healthy)
        )
        XCTAssertEqual(
            decide(
                http: .normal,
                directDoH: .failure,
                networkDNS: .answered,
                resolver: .available(warmingUp: false)
            ),
            .candidate(.compatibilityRequired(portalCleared: true))
        )
    }

    func testDirectDoHSuccessCannotClearUncertainPortalEvidence() {
        for http in [CaptiveHTTPProbeEvidence.inconclusive, .error] {
            XCTAssertEqual(
                decide(http: http, directDoH: .success, resolver: .available(warmingUp: false)),
                .retry
            )
        }
    }

    func testPostWarmupDirectFailureSelectsScopedCompatibility() {
        XCTAssertEqual(
            decide(
                http: .inconclusive,
                directDoH: .failure,
                networkDNS: .answered,
                resolver: .available(warmingUp: false)
            ),
            .candidate(.compatibilityRequired(portalCleared: false))
        )
        XCTAssertEqual(
            decide(
                http: .error,
                directDoH: .failure,
                networkDNS: .answered,
                resolver: .available(warmingUp: false)
            ),
            .candidate(.compatibilityRequired(portalCleared: false))
        )
    }

    /// An outage takes the network's resolvers down with direct DoH. Moving
    /// public DNS onto them would replace serve-stale answers with SERVFAIL,
    /// so compatibility needs proof that the network DNS answers.
    func testCompatibilityRequiresAnAnsweringNetworkResolver() {
        for http in [CaptiveHTTPProbeEvidence.normal, .inconclusive, .error] {
            for networkDNS in [NetworkDNSProbeEvidence.notRun, .unanswered] {
                XCTAssertEqual(
                    decide(
                        http: http,
                        directDoH: .failure,
                        networkDNS: networkDNS,
                        resolver: .available(warmingUp: false)
                    ),
                    .retry,
                    "http=\(http) networkDNS=\(networkDNS) must not select compatibility"
                )
            }
        }
    }

    func testNetworkDNSProbeRunsOnlyWhenCompatibilityIsTheCandidate() {
        XCTAssertTrue(
            CaptiveConnectivityPolicy.needsNetworkDNSProbe(
                http: .error,
                directDoH: .failure,
                resolver: .available(warmingUp: false)
            )
        )
        XCTAssertTrue(
            CaptiveConnectivityPolicy.needsNetworkDNSProbe(
                http: .normal,
                directDoH: .failure,
                resolver: .available(warmingUp: false)
            )
        )
        XCTAssertFalse(
            CaptiveConnectivityPolicy.needsNetworkDNSProbe(
                http: .normal,
                directDoH: .success,
                resolver: .available(warmingUp: false)
            )
        )
        XCTAssertFalse(
            CaptiveConnectivityPolicy.needsNetworkDNSProbe(
                http: .error,
                directDoH: .failure,
                resolver: .available(warmingUp: true)
            )
        )
        XCTAssertFalse(
            CaptiveConnectivityPolicy.needsNetworkDNSProbe(
                http: .captive,
                directDoH: .notRun,
                resolver: .unavailable
            )
        )
    }

    func testWarmupFailureIsRetryableButWarmupSuccessCounts() {
        XCTAssertEqual(
            decide(http: .normal, directDoH: .failure, resolver: .available(warmingUp: true)),
            .retry
        )
        XCTAssertEqual(
            decide(http: .normal, directDoH: .success, resolver: .available(warmingUp: true)),
            .candidate(.healthy)
        )
    }

    func testUnavailableResolverRequestsPreparationWithoutPublishingHealth() {
        for http in [CaptiveHTTPProbeEvidence.normal, .inconclusive, .error] {
            XCTAssertEqual(
                decide(http: http, directDoH: .notRun, resolver: .unavailable),
                .prepareResolver
            )
        }
    }

    func testCompatibilityVariantsMapToTheSameExternalStatus() {
        XCTAssertEqual(
            CaptiveConnectivityOutcome.compatibilityRequired(portalCleared: true).status,
            .dnsIntercepted
        )
        XCTAssertEqual(
            CaptiveConnectivityOutcome.compatibilityRequired(portalCleared: false).status,
            .dnsIntercepted
        )
        XCTAssertNotEqual(
            CaptiveConnectivityOutcome.compatibilityRequired(portalCleared: true),
            CaptiveConnectivityOutcome.compatibilityRequired(portalCleared: false)
        )
    }

    func testTrackerRequiresConsecutiveIdenticalCompleteCandidates() {
        var tracker = CaptiveConnectivityConfirmationTracker(confirmationsRequired: 2)

        XCTAssertEqual(tracker.consume(.candidate(.healthy)), .pending)
        XCTAssertEqual(
            tracker.consume(.candidate(.compatibilityRequired(portalCleared: true))),
            .pending
        )
        XCTAssertEqual(
            tracker.consume(.candidate(.compatibilityRequired(portalCleared: true))),
            .confirmed(.compatibilityRequired(portalCleared: true), changed: true)
        )
    }

    func testRetryResetsPartialCandidateAndPreservesConfirmedOutcome() {
        var tracker = CaptiveConnectivityConfirmationTracker(confirmationsRequired: 2)
        XCTAssertEqual(tracker.consume(.candidate(.healthy)), .pending)
        XCTAssertEqual(tracker.consume(.retry), .retry)
        XCTAssertEqual(tracker.consume(.candidate(.healthy)), .pending)
        XCTAssertEqual(
            tracker.consume(.candidate(.healthy)),
            .confirmed(.healthy, changed: true)
        )

        XCTAssertEqual(
            tracker.consume(.candidate(.compatibilityRequired(portalCleared: false))),
            .pending
        )
        XCTAssertEqual(tracker.consume(.retry), .retry)
        XCTAssertEqual(tracker.confirmedOutcome, .healthy)
    }

    func testTrackerReportsCompatibilityEvidenceChangeWithSameExternalStatus() {
        var tracker = CaptiveConnectivityConfirmationTracker(confirmationsRequired: 2)
        _ = tracker.consume(.candidate(.compatibilityRequired(portalCleared: false)))
        _ = tracker.consume(.candidate(.compatibilityRequired(portalCleared: false)))

        XCTAssertEqual(
            tracker.consume(.candidate(.compatibilityRequired(portalCleared: true))),
            .pending
        )
        XCTAssertEqual(
            tracker.consume(.candidate(.compatibilityRequired(portalCleared: true))),
            .confirmed(.compatibilityRequired(portalCleared: true), changed: true)
        )
    }

    func testNetworkInvalidationClearsConfirmedEvidence() {
        var tracker = CaptiveConnectivityConfirmationTracker(confirmationsRequired: 2)
        _ = tracker.consume(.candidate(.healthy))
        _ = tracker.consume(.candidate(.healthy))

        tracker.invalidateNetwork()

        XCTAssertNil(tracker.confirmedOutcome)
        XCTAssertEqual(tracker.consume(.candidate(.healthy)), .pending)
    }

    private func decide(
        http: CaptiveHTTPProbeEvidence,
        directDoH: DirectDoHProbeEvidence,
        networkDNS: NetworkDNSProbeEvidence = .notRun,
        resolver: ResolverProbeAvailability
    ) -> CaptiveConnectivityDecision {
        CaptiveConnectivityPolicy.decide(
            http: http,
            directDoH: directDoH,
            networkDNS: networkDNS,
            resolver: resolver
        )
    }
}

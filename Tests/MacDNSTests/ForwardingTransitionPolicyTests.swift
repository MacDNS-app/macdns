// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest
@testable import MacDNSAgent

final class ForwardingTransitionPolicyTests: XCTestCase {
    func testRepeatedDirectDoHFailuresNeverEscalateScopedForwarding() {
        for portalCleared in [false, true] {
            XCTAssertEqual(
                CompatibilityTransitionPolicy.action(
                    forwardingEnabled: true,
                    fullBypassActive: false,
                    portalCleared: portalCleared
                ),
                .keepScopedForwarding
            )
        }
    }

    func testPortalClearanceRestoresForwardingFromAnApprovedBypass() {
        XCTAssertEqual(
            CompatibilityTransitionPolicy.action(
                forwardingEnabled: true,
                fullBypassActive: true,
                portalCleared: true
            ),
            .restoreScopedForwardingFromBypass
        )
        XCTAssertEqual(
            CompatibilityTransitionPolicy.action(
                forwardingEnabled: true,
                fullBypassActive: true,
                portalCleared: false
            ),
            .keepApprovedBypass
        )
    }

    func testUncertainPortalKeepsApprovedBypassBeforeForwardingExists() {
        XCTAssertEqual(
            CompatibilityTransitionPolicy.action(
                forwardingEnabled: false,
                fullBypassActive: true,
                portalCleared: false
            ),
            .keepApprovedBypass
        )
        XCTAssertEqual(
            CompatibilityTransitionPolicy.action(
                forwardingEnabled: false,
                fullBypassActive: true,
                portalCleared: true
            ),
            .establishScopedForwarding
        )
    }

    func testPublishesOnlyUnchangedRunningTransition() {
        let snapshot = ForwardingTransitionSnapshot(
            stopGeneration: 1,
            transitionGeneration: 2,
            resolverRunning: true,
            forwardingEnabled: false
        )

        XCTAssertTrue(
            ForwardingTransitionPolicy.mayPublish(
                captured: snapshot,
                current: snapshot
            )
        )
    }

    func testNetworkIntentInvalidatesCapturedTransition() {
        let captured = ForwardingTransitionSnapshot(
            stopGeneration: 1,
            transitionGeneration: 2,
            resolverRunning: true,
            forwardingEnabled: false
        )

        XCTAssertFalse(
            ForwardingTransitionPolicy.mayPublish(
                captured: captured,
                current: ForwardingTransitionSnapshot(
                    stopGeneration: 1,
                    transitionGeneration: 3,
                    resolverRunning: true,
                    forwardingEnabled: false
                )
            )
        )
    }

    func testIntentIsRejectedAfterServicesFullyStop() {
        let intent = ForwardingTransitionIntent(
            stopGeneration: 4,
            transitionGeneration: 9
        )

        XCTAssertFalse(
            ForwardingTransitionPolicy.isCurrentIntent(
                intent,
                currentStopGeneration: 4,
                currentTransitionGeneration: 9,
                isStopping: false,
                resolverRunning: false,
                captiveBypassEnabled: false
            )
        )
    }

    func testIntentRemainsCurrentWhileCaptiveRecoveryOwnsBypass() {
        let intent = ForwardingTransitionIntent(
            stopGeneration: 4,
            transitionGeneration: 9
        )

        XCTAssertTrue(
            ForwardingTransitionPolicy.isCurrentIntent(
                intent,
                currentStopGeneration: 4,
                currentTransitionGeneration: 9,
                isStopping: false,
                resolverRunning: false,
                captiveBypassEnabled: true
            )
        )
    }

    func testIntentCaptureIsRejectedWhileStopping() {
        XCTAssertNil(
            ForwardingTransitionPolicy.nextIntent(
                currentStopGeneration: 4,
                currentTransitionGeneration: 9,
                currentLifecycleGeneration: 12,
                callbackLifecycleGeneration: 12,
                acceptingCallbacks: true,
                isStopping: true,
                resolverRunning: true,
                captiveBypassEnabled: false
            )
        )
    }

    func testIntentCaptureIsRejectedAfterServicesStop() {
        XCTAssertNil(
            ForwardingTransitionPolicy.nextIntent(
                currentStopGeneration: 4,
                currentTransitionGeneration: 9,
                currentLifecycleGeneration: 12,
                callbackLifecycleGeneration: 12,
                acceptingCallbacks: true,
                isStopping: false,
                resolverRunning: false,
                captiveBypassEnabled: false
            )
        )
    }

    func testIntentCaptureAdvancesActiveTransition() {
        XCTAssertEqual(
            ForwardingTransitionPolicy.nextIntent(
                currentStopGeneration: 4,
                currentTransitionGeneration: 9,
                currentLifecycleGeneration: 12,
                callbackLifecycleGeneration: 12,
                acceptingCallbacks: true,
                isStopping: false,
                resolverRunning: true,
                captiveBypassEnabled: false
            ),
            ForwardingTransitionIntent(
                stopGeneration: 4,
                transitionGeneration: 10
            )
        )
    }

    func testIntentCaptureRejectsCallbackFromPreviousLifecycle() {
        XCTAssertNil(
            ForwardingTransitionPolicy.nextIntent(
                currentStopGeneration: 4,
                currentTransitionGeneration: 9,
                currentLifecycleGeneration: 13,
                callbackLifecycleGeneration: 12,
                acceptingCallbacks: true,
                isStopping: false,
                resolverRunning: true,
                captiveBypassEnabled: false
            )
        )
    }

    func testIntentCaptureRejectsCallbacksAfterFailedStop() {
        XCTAssertNil(
            ForwardingTransitionPolicy.nextIntent(
                currentStopGeneration: 4,
                currentTransitionGeneration: 9,
                currentLifecycleGeneration: 12,
                callbackLifecycleGeneration: 12,
                acceptingCallbacks: false,
                isStopping: false,
                resolverRunning: true,
                captiveBypassEnabled: false
            )
        )
    }

    func testRejectsStopOrNetworkChangeBetweenFFIEnableAndReadinessCommit() {
        let captured = ForwardingTransitionSnapshot(
            stopGeneration: 1,
            transitionGeneration: 2,
            resolverRunning: true,
            forwardingEnabled: false
        )

        XCTAssertFalse(
            ForwardingTransitionPolicy.mayPublish(
                captured: captured,
                current: ForwardingTransitionSnapshot(
                    stopGeneration: 2,
                    transitionGeneration: 2,
                    resolverRunning: false,
                    forwardingEnabled: false
                )
            )
        )
        XCTAssertFalse(
            ForwardingTransitionPolicy.mayPublish(
                captured: captured,
                current: ForwardingTransitionSnapshot(
                    stopGeneration: 1,
                    transitionGeneration: 3,
                    resolverRunning: true,
                    forwardingEnabled: false
                )
            )
        )
    }

    func testRejectsDirectDoHRecoveryWhenForwardingStateChangedDuringProbe() {
        let captured = ForwardingTransitionSnapshot(
            stopGeneration: 1,
            transitionGeneration: 2,
            resolverRunning: true,
            forwardingEnabled: true
        )

        XCTAssertFalse(
            ForwardingTransitionPolicy.mayPublish(
                captured: captured,
                current: ForwardingTransitionSnapshot(
                    stopGeneration: 1,
                    transitionGeneration: 2,
                    resolverRunning: true,
                    forwardingEnabled: false
                )
            )
        )
    }

    func testRejectsStoppedResolver() {
        let captured = ForwardingTransitionSnapshot(
            stopGeneration: 1,
            transitionGeneration: 2,
            resolverRunning: true,
            forwardingEnabled: false
        )

        XCTAssertFalse(
            ForwardingTransitionPolicy.mayPublish(
                captured: captured,
                current: ForwardingTransitionSnapshot(
                    stopGeneration: 1,
                    transitionGeneration: 2,
                    resolverRunning: false,
                    forwardingEnabled: false
                )
            )
        )
    }

    func testStopDuringReadinessCommitLeavesStateUnpublished() {
        let captured = ForwardingTransitionSnapshot(
            stopGeneration: 1,
            transitionGeneration: 2,
            resolverRunning: true,
            forwardingEnabled: false
        )
        var readinessCleared = false
        var statePublished = false

        let result = ForwardingTransitionOrchestrator.commitReadiness(
            captured: captured,
            current: {
                ForwardingTransitionSnapshot(
                    stopGeneration: 2,
                    transitionGeneration: 2,
                    resolverRunning: false,
                    forwardingEnabled: false
                )
            },
            setReady: {
                readinessCleared = true
                return true
            },
            publish: {
                statePublished = true
                return false
            }
        )

        XCTAssertEqual(result, .stale)
        XCTAssertFalse(readinessCleared)
        XCTAssertFalse(statePublished)
    }

    func testCaptiveResolvedStaleCommitKeepsBypass() {
        let captured = ForwardingTransitionSnapshot(
            stopGeneration: 1,
            transitionGeneration: 2,
            resolverRunning: true,
            forwardingEnabled: false
        )
        var captiveBypassEnabled = true
        var readinessCleared = false
        var failSafeEntered = false
        var readyWakeSent = false
        var profileRepublished = false

        let result = ForwardingTransitionOrchestrator.finishCaptiveResolution(
            commitReadiness: {
                ForwardingTransitionOrchestrator.commitReadiness(
                    captured: captured,
                    current: {
                        ForwardingTransitionSnapshot(
                            stopGeneration: 1,
                            transitionGeneration: 3,
                            resolverRunning: true,
                            forwardingEnabled: false
                        )
                    },
                    setReady: {
                        readinessCleared = true
                        return true
                    },
                    publish: {
                        captiveBypassEnabled = false
                        return true
                    }
                )
            },
            enterFailSafe: {
                failSafeEntered = true
                captiveBypassEnabled = true
            },
            wakeReady: {
                readyWakeSent = true
            },
            republishNetworkProfile: {
                profileRepublished = true
            }
        )

        XCTAssertEqual(result, .stale)
        XCTAssertTrue(captiveBypassEnabled)
        XCTAssertFalse(readinessCleared)
        XCTAssertTrue(failSafeEntered)
        XCTAssertFalse(readyWakeSent)
        XCTAssertFalse(profileRepublished)
    }

    /// A portal can answer the RFC 7050 discovery with a negative TTL of a day.
    /// Once the portal clears, the profile must be derived again instead of
    /// keeping NAT64 synthesis off until that TTL ends.
    func testCaptiveResolvedCommitRepublishesTheNetworkProfile() {
        var events: [String] = []

        let result = ForwardingTransitionOrchestrator.finishCaptiveResolution(
            commitReadiness: {
                events.append("commit")
                return .committed(wasBypassing: true)
            },
            enterFailSafe: {
                events.append("fail-safe")
            },
            wakeReady: {
                events.append("wake")
            },
            republishNetworkProfile: {
                events.append("profile")
            }
        )

        XCTAssertEqual(result, .committed(wasBypassing: true))
        XCTAssertEqual(events, ["commit", "profile", "wake"])
    }

    /// The fail-safe may keep forwarding behind a published bypass, but only
    /// when a user approval authorizes the bypass in the first place.
    func testApprovedFailSafeKeepsForwardingBehindPublishedBypass() {
        var events: [String] = []
        let forwardingEnabled = true
        var captiveBypassEnabled = false
        var resolverStopped = false

        ForwardingTransitionOrchestrator.enterFailSafe(
            commitBypass: {
                let action = ForwardingFailSafeAuthorizationPolicy.action(
                    isStopping: false,
                    stopGenerationMatches: true,
                    transitionGenerationMatches: true,
                    bypassAlreadyActive: captiveBypassEnabled,
                    fullBypassAuthorized: true
                )
                XCTAssertEqual(action, .claimFullBypass)
                events.append("bypass")
                captiveBypassEnabled = true
                return .published
            },
            resolverIsRunning: { true },
            stopResolver: { resolverStopped = true },
            wakeProxy: { events.append("wake") }
        )

        XCTAssertEqual(events, ["bypass", "wake"])
        XCTAssertTrue(forwardingEnabled)
        XCTAssertTrue(captiveBypassEnabled)
        XCTAssertFalse(resolverStopped)
    }

    /// A captive indication is unauthenticated, so a fail-safe reached from one
    /// must never switch the DNS Proxy, the blocklist and the Content Filter
    /// off by itself.
    func testUnapprovedFailSafeKeepsProtectionInsteadOfClaimingBypass() {
        XCTAssertEqual(
            ForwardingFailSafeAuthorizationPolicy.action(
                isStopping: false,
                stopGenerationMatches: true,
                transitionGenerationMatches: true,
                bypassAlreadyActive: false,
                fullBypassAuthorized: false
            ),
            .keepProtectionClosed
        )
    }

    /// The stale `.readinessRejected` / `.stale` branches of the forwarding
    /// enable can reach the fail-safe with a transition another handler already
    /// replaced. They must not claim a full bypass on top of it.
    func testStaleTransitionCannotCreateANewBypass() {
        XCTAssertEqual(
            ForwardingFailSafeAuthorizationPolicy.action(
                isStopping: false,
                stopGenerationMatches: true,
                transitionGenerationMatches: false,
                bypassAlreadyActive: false,
                fullBypassAuthorized: true
            ),
            .discard
        )
        XCTAssertEqual(
            ForwardingFailSafeAuthorizationPolicy.action(
                isStopping: false,
                stopGenerationMatches: true,
                transitionGenerationMatches: false,
                bypassAlreadyActive: false,
                fullBypassAuthorized: false
            ),
            .discard
        )
    }

    /// Cleanup fail-safes legitimately run behind a newer transition while the
    /// bypass they are holding is still active, so they stay allowed. They lose
    /// the bypass as soon as the approval does.
    func testFailSafeHoldingAnActiveBypassSurvivesANewerTransition() {
        XCTAssertEqual(
            ForwardingFailSafeAuthorizationPolicy.action(
                isStopping: false,
                stopGenerationMatches: true,
                transitionGenerationMatches: false,
                bypassAlreadyActive: true,
                fullBypassAuthorized: true
            ),
            .claimFullBypass
        )
        XCTAssertEqual(
            ForwardingFailSafeAuthorizationPolicy.action(
                isStopping: false,
                stopGenerationMatches: true,
                transitionGenerationMatches: false,
                bypassAlreadyActive: true,
                fullBypassAuthorized: false
            ),
            .keepProtectionClosed
        )
    }

    func testFailSafeIsDiscardedAfterAStopTookOver() {
        XCTAssertEqual(
            ForwardingFailSafeAuthorizationPolicy.action(
                isStopping: true,
                stopGenerationMatches: true,
                transitionGenerationMatches: true,
                bypassAlreadyActive: true,
                fullBypassAuthorized: true
            ),
            .discard
        )
        XCTAssertEqual(
            ForwardingFailSafeAuthorizationPolicy.action(
                isStopping: false,
                stopGenerationMatches: false,
                transitionGenerationMatches: true,
                bypassAlreadyActive: true,
                fullBypassAuthorized: true
            ),
            .discard
        )
    }

    /// With `.keepProtectionClosed` the orchestrator must not stop the resolver,
    /// because a stopped resolver hands the provider the bypass the fail-safe
    /// was refused.
    func testUnapprovedFailSafeNeverStopsTheResolverOrWakesABypass() {
        var events: [String] = []

        let result = ForwardingTransitionOrchestrator.enterFailSafe(
            commitBypass: {
                let action = ForwardingFailSafeAuthorizationPolicy.action(
                    isStopping: false,
                    stopGenerationMatches: true,
                    transitionGenerationMatches: true,
                    bypassAlreadyActive: false,
                    fullBypassAuthorized: false
                )
                XCTAssertEqual(action, .keepProtectionClosed)
                events.append("restore-interception")
                return .noLongerNeeded
            },
            resolverIsRunning: { true },
            stopResolver: { events.append("stop") },
            wakeProxy: { events.append("wake") }
        )

        XCTAssertEqual(result, .noLongerNeeded)
        XCTAssertEqual(events, ["restore-interception"])
    }

    func testDisablePublishesStateOnlyAfterBackendDisableSucceeds() {
        XCTAssertFalse(
            ForwardingTransitionOrchestrator.disableAndPublish(
                disableForwarding: { false },
                publishDisabledState: { true }
            )
        )
        XCTAssertFalse(
            ForwardingTransitionOrchestrator.disableAndPublish(
                disableForwarding: { true },
                publishDisabledState: { false }
            )
        )

        XCTAssertTrue(
            ForwardingTransitionOrchestrator.disableAndPublish(
                disableForwarding: { true },
                publishDisabledState: { true }
            )
        )
    }

    func testDirectDoHRecoveryDisablesBeforeReadinessAndStatePublication() {
        var events: [String] = []

        let result = ForwardingTransitionOrchestrator.completeDirectDoHRecovery(
            isCurrent: {
                events.append("current")
                return true
            },
            disableForwarding: {
                events.append("disable")
                return true
            },
            publishReadiness: {
                events.append("readiness")
                return true
            },
            commitDisabledState: {
                events.append("commit")
                return true
            },
            enterFailSafe: { enabled in
                events.append("fail-safe-\(enabled)")
            },
            republishNetworkProfile: {
                events.append("profile")
            }
        )

        XCTAssertEqual(result, .committed(wasBypassing: true))
        XCTAssertEqual(
            events,
            ["current", "disable", "current", "readiness", "commit", "profile"]
        )
    }

    func testDirectDoHRecoveryDisableFailureEntersFailSafeBeforeReadiness() {
        var events: [String] = []

        let result = ForwardingTransitionOrchestrator.completeDirectDoHRecovery(
            isCurrent: {
                events.append("current")
                return true
            },
            disableForwarding: {
                events.append("disable")
                return false
            },
            publishReadiness: {
                events.append("readiness")
                return true
            },
            commitDisabledState: {
                events.append("commit")
                return false
            },
            enterFailSafe: { enabled in
                events.append("fail-safe-\(enabled)")
            },
            republishNetworkProfile: {
                events.append("profile")
            }
        )

        XCTAssertEqual(result, .disableRejected)
        XCTAssertEqual(events, ["current", "disable", "fail-safe-true"])
    }

    func testDirectDoHRecoveryStaleAfterDisableEntersFailSafeWithForwardingOff() {
        var checks = 0
        var events: [String] = []

        let result = ForwardingTransitionOrchestrator.completeDirectDoHRecovery(
            isCurrent: {
                checks += 1
                events.append("current-\(checks)")
                return checks == 1
            },
            disableForwarding: {
                events.append("disable")
                return true
            },
            publishReadiness: {
                events.append("readiness")
                return true
            },
            commitDisabledState: {
                events.append("commit")
                return false
            },
            enterFailSafe: { enabled in
                events.append("fail-safe-\(enabled)")
            },
            republishNetworkProfile: {
                events.append("profile")
            }
        )

        XCTAssertEqual(result, .stale)
        XCTAssertEqual(
            events,
            ["current-1", "disable", "current-2", "fail-safe-false"]
        )
    }

    func testDirectDoHRecoveryReadinessFailureEntersFailSafe() {
        var events: [String] = []

        let result = ForwardingTransitionOrchestrator.completeDirectDoHRecovery(
            isCurrent: { true },
            disableForwarding: {
                events.append("disable")
                return true
            },
            publishReadiness: {
                events.append("readiness")
                return false
            },
            commitDisabledState: {
                events.append("commit")
                return false
            },
            enterFailSafe: { enabled in
                events.append("fail-safe-\(enabled)")
            },
            republishNetworkProfile: {
                events.append("profile")
            }
        )

        XCTAssertEqual(result, .readinessRejected)
        XCTAssertEqual(
            events,
            ["disable", "readiness", "fail-safe-false"]
        )
    }

    func testDirectDoHRecoveryFinalGenerationMismatchRestoresFailSafe() {
        var events: [String] = []

        let result = ForwardingTransitionOrchestrator.completeDirectDoHRecovery(
            isCurrent: { true },
            disableForwarding: {
                events.append("disable")
                return true
            },
            publishReadiness: {
                events.append("readiness")
                return true
            },
            commitDisabledState: {
                events.append("commit")
                return nil
            },
            enterFailSafe: { enabled in
                events.append("fail-safe-\(enabled)")
            },
            republishNetworkProfile: {
                events.append("profile")
            }
        )

        XCTAssertEqual(result, .stale)
        XCTAssertEqual(
            events,
            ["disable", "readiness", "commit", "fail-safe-false"]
        )
    }

    func testFailSafeStopsRunningResolverWhenBypassPublicationFails() {
        var events: [String] = []

        ForwardingTransitionOrchestrator.enterFailSafe(
            commitBypass: {
                events.append("bypass")
                return .bypassRejected
            },
            resolverIsRunning: { true },
            stopResolver: { events.append("stop") },
            wakeProxy: { events.append("wake") }
        )

        XCTAssertEqual(events, ["bypass", "stop", "wake"])
    }

    func testStopAfterCaptiveEnqueuePreventsRestartWithOriginalGeneration() {
        let intent = ForwardingTransitionIntent(
            stopGeneration: 7,
            transitionGeneration: 11
        )
        var restartCalled = false

        let restarted = ForwardingTransitionOrchestrator.restartIfCurrent(
            intent: intent,
            isCurrent: { false },
            restart: { expectedStopGeneration in
                restartCalled = true
                XCTAssertEqual(expectedStopGeneration, 7)
                return true
            }
        )

        XCTAssertFalse(restarted)
        XCTAssertFalse(restartCalled)
    }

    func testStopCompletedFailSafeHasZeroEffects() {
        var events: [String] = []

        let result = ForwardingTransitionOrchestrator.enterFailSafe(
            commitBypass: {
                events.append("commit")
                return .noLongerNeeded
            },
            resolverIsRunning: {
                events.append("running")
                return true
            },
            stopResolver: { events.append("stop") },
            wakeProxy: { events.append("wake") }
        )

        XCTAssertEqual(result, .noLongerNeeded)
        XCTAssertEqual(events, ["commit"])
    }

    func testConfigurationChangePreparesNetworkBeforeRefreshAndRecheck() {
        var events: [String] = []

        NetworkConfigurationChangeOrchestrator.apply(
            isCurrent: {
                events.append("current")
                return true
            },
            invalidateDetector: { events.append("invalidate") },
            publishEphemeralRoutes: { events.append("routes") },
            rebuildNetworkInfrastructure: { events.append("rebuild") },
            publishNetworkProfile: { events.append("profile") },
            forwardingActive: {
                events.append("forwarding-active")
                return true
            },
            refreshForwardingTargets: { events.append("refresh") },
            isConnected: true,
            recheckConnectivity: { events.append("recheck") }
        )

        XCTAssertEqual(
            events,
            [
                "current", "invalidate", "current", "routes", "current",
                "rebuild", "current", "profile", "current", "forwarding-active",
                "refresh", "current", "recheck",
            ]
        )
    }

    func testConfigurationChangeWithoutForwardingStillRechecks() {
        var events: [String] = []

        NetworkConfigurationChangeOrchestrator.apply(
            isCurrent: { true },
            invalidateDetector: { events.append("invalidate") },
            publishEphemeralRoutes: { events.append("routes") },
            rebuildNetworkInfrastructure: { events.append("rebuild") },
            publishNetworkProfile: { events.append("profile") },
            forwardingActive: { false },
            refreshForwardingTargets: { events.append("refresh") },
            isConnected: true,
            recheckConnectivity: { events.append("recheck") }
        )

        XCTAssertEqual(events, ["invalidate", "routes", "rebuild", "profile", "recheck"])
    }

    func testConfigurationChangeOnStaleIntentHasNoEffect() {
        var events: [String] = []

        NetworkConfigurationChangeOrchestrator.apply(
            isCurrent: { false },
            invalidateDetector: { events.append("invalidate") },
            publishEphemeralRoutes: { events.append("routes") },
            rebuildNetworkInfrastructure: { events.append("rebuild") },
            publishNetworkProfile: { events.append("profile") },
            forwardingActive: {
                events.append("forwarding-active")
                return true
            },
            refreshForwardingTargets: { events.append("refresh") },
            isConnected: true,
            recheckConnectivity: { events.append("recheck") }
        )

        XCTAssertTrue(events.isEmpty)
    }

    func testConfigurationChangeStopAfterInvalidationSkipsRebuildAndRecheck() {
        var checks = 0
        var events: [String] = []

        NetworkConfigurationChangeOrchestrator.apply(
            isCurrent: {
                checks += 1
                return checks == 1
            },
            invalidateDetector: { events.append("invalidate") },
            publishEphemeralRoutes: { events.append("routes") },
            rebuildNetworkInfrastructure: { events.append("rebuild") },
            publishNetworkProfile: { events.append("profile") },
            forwardingActive: {
                events.append("forwarding-active")
                return true
            },
            refreshForwardingTargets: { events.append("refresh") },
            isConnected: true,
            recheckConnectivity: { events.append("recheck") }
        )

        XCTAssertEqual(events, ["invalidate"])
    }

    func testOfflineConfigurationChangeNeverStartsAProbe() {
        var events: [String] = []

        NetworkConfigurationChangeOrchestrator.apply(
            isCurrent: { true },
            invalidateDetector: { events.append("invalidate") },
            publishEphemeralRoutes: { events.append("routes") },
            rebuildNetworkInfrastructure: { events.append("rebuild") },
            publishNetworkProfile: { events.append("profile") },
            forwardingActive: { false },
            refreshForwardingTargets: { events.append("refresh") },
            isConnected: false,
            recheckConnectivity: { events.append("recheck") }
        )

        // The profile is still published offline, so the resolver drops the
        // previous network's NAT64 prefix.
        XCTAssertEqual(events, ["invalidate", "routes", "rebuild", "profile"])
    }

    func testNewCaptiveGenerationGetsConservativeBypassThenCanCommit() {
        var bypassRequested = false
        var forwardingEnabled = true
        var captiveBypassEnabled = false
        var transitionGeneration: UInt64 = 3
        var events: [String] = []

        ForwardingTransitionOrchestrator.enterFailSafe(
            commitBypass: {
                bypassRequested = true
                captiveBypassEnabled = true
                transitionGeneration =
                    ForwardingTransitionPolicy.generationAfterFailSafeStateChange(
                        expectedGeneration: 2,
                        currentGeneration: transitionGeneration
                    )
                events.append("bypass-on")
                return .published
            },
            resolverIsRunning: { true },
            stopResolver: { events.append("stop") },
            wakeProxy: { events.append("wake-bypass") }
        )

        forwardingEnabled = false
        events.append("forwarding-cleanup")

        let newCaptiveSnapshot = ForwardingTransitionSnapshot(
            stopGeneration: 1,
            transitionGeneration: transitionGeneration,
            resolverRunning: true,
            forwardingEnabled: false
        )
        let result = ForwardingTransitionOrchestrator.commitReadiness(
            captured: newCaptiveSnapshot,
            current: { newCaptiveSnapshot },
            setReady: {
                bypassRequested = false
                events.append("bypass-off")
                return true
            },
            publish: {
                captiveBypassEnabled = false
                return true
            }
        )

        XCTAssertEqual(result, .committed(wasBypassing: true))
        XCTAssertFalse(bypassRequested)
        XCTAssertFalse(forwardingEnabled)
        XCTAssertFalse(captiveBypassEnabled)
        XCTAssertEqual(transitionGeneration, 3)
        XCTAssertEqual(
            events,
            [
                "bypass-on", "wake-bypass",
                "forwarding-cleanup", "bypass-off",
            ]
        )
    }

    // MARK: - Fail-safe bypass commit

    /// The opening verdict is taken before the publish, which cannot hold the
    /// state lock. Committing on it lets a callback that lost ownership
    /// mid-flight re-establish a bypass, so the commit decision has to be the
    /// one taken afterwards.
    func testFailSafeCommitTakesBackABypassItNoLongerOwns() {
        var events: [String] = []

        let result = ForwardingTransitionOrchestrator.commitFailSafeBypass(
            decide: {
                events.append("decide")
                return .claimFullBypass
            },
            restoreInterception: { events.append("restore") },
            publishBypass: {
                events.append("publish")
                return true
            },
            commit: { bypassPublished in
                events.append("commit")
                XCTAssertTrue(bypassPublished)
                // A newer transition restored interception while the publish
                // was in flight.
                return (.noLongerNeeded, true)
            }
        )

        XCTAssertEqual(result, .noLongerNeeded)
        XCTAssertEqual(events, ["decide", "publish", "commit", "restore"])
    }

    /// A commit that still owns the transition keeps the published bypass and
    /// must not undo it.
    func testFailSafeCommitKeepsAnOwnedBypass() {
        var restores = 0

        let result = ForwardingTransitionOrchestrator.commitFailSafeBypass(
            decide: { .claimFullBypass },
            restoreInterception: { restores += 1 },
            publishBypass: { true },
            commit: { _ in (.published, false) }
        )

        XCTAssertEqual(result, .published)
        XCTAssertEqual(restores, 0)
    }

    /// An unauthorized fail-safe never publishes a bypass in the first place.
    func testUnauthorizedFailSafeNeverPublishes() {
        var events: [String] = []

        let result = ForwardingTransitionOrchestrator.commitFailSafeBypass(
            decide: { .keepProtectionClosed },
            restoreInterception: { events.append("restore") },
            publishBypass: {
                events.append("publish")
                return true
            },
            commit: { _ in
                events.append("commit")
                return (.published, false)
            }
        )

        XCTAssertEqual(result, .noLongerNeeded)
        XCTAssertEqual(events, ["restore"])
    }

    /// A discarded fail-safe leaves the state to whoever owns it now: it
    /// neither publishes nor takes anything back.
    func testDiscardedFailSafeTouchesNothing() {
        var events: [String] = []

        let result = ForwardingTransitionOrchestrator.commitFailSafeBypass(
            decide: { .discard },
            restoreInterception: { events.append("restore") },
            publishBypass: {
                events.append("publish")
                return true
            },
            commit: { _ in
                events.append("commit")
                return (.published, false)
            }
        )

        XCTAssertEqual(result, .noLongerNeeded)
        XCTAssertTrue(events.isEmpty)
    }
}

// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import DNSProxyExtension

final class DNSProxyLifecycleCoordinatorTests: XCTestCase {

    func testStartPublishesRunningWithFreshGeneration() {
        let coordinator = DNSProxyLifecycleCoordinator()
        XCTAssertEqual(coordinator.phase, .stopped)

        let generation = coordinator.beginStart()
        XCTAssertEqual(coordinator.phase, .starting)

        coordinator.finishStart()
        XCTAssertEqual(coordinator.phase, .running)
        XCTAssertTrue(coordinator.isCurrent(generation))
    }

    func testStopInvalidatesTheRunningGeneration() {
        let coordinator = DNSProxyLifecycleCoordinator()
        let generation = coordinator.beginStart()
        coordinator.finishStart()

        coordinator.beginStop()
        XCTAssertEqual(coordinator.phase, .stopping)
        XCTAssertFalse(coordinator.isCurrent(generation))

        coordinator.finishStop()
        XCTAssertEqual(coordinator.phase, .stopped)
    }

    func testRestartDoesNotRevalidateAnEarlierGeneration() {
        let coordinator = DNSProxyLifecycleCoordinator()
        let first = coordinator.beginStart()
        coordinator.finishStart()
        coordinator.beginStop()
        coordinator.finishStop()

        let second = coordinator.beginStart()
        coordinator.finishStart()

        XCTAssertFalse(coordinator.isCurrent(first))
        XCTAssertTrue(coordinator.isCurrent(second))
    }

    func testCallbacksAreStaleWhileStopping() {
        let coordinator = DNSProxyLifecycleCoordinator()
        let generation = coordinator.beginStart()
        coordinator.finishStart()
        coordinator.beginStop()

        // A socket callback that captured the running generation must not act
        // once teardown has begun, even before it completes.
        XCTAssertFalse(coordinator.isCurrent(generation))
    }

    func testGenerationCapturedDuringStartIsNotCurrentUntilRunning() {
        let coordinator = DNSProxyLifecycleCoordinator()
        let generation = coordinator.beginStart()

        XCTAssertFalse(coordinator.isCurrent(generation))
        coordinator.finishStart()
        XCTAssertTrue(coordinator.isCurrent(generation))
    }

    func testStopCompletionRunsExactlyOnce() {
        let coordinator = DNSProxyLifecycleCoordinator()
        _ = coordinator.beginStart()
        coordinator.finishStart()

        XCTAssertTrue(coordinator.beginStop())
        XCTAssertFalse(coordinator.beginStop())
        coordinator.finishStop()
    }

    func testStoppedCoordinatorDoesNotAdmitNewFlow() {
        let coordinator = DNSProxyLifecycleCoordinator()

        XCTAssertNil(coordinator.generationForNewFlow())
    }

    func testRestartResetsProxyStateToBypass() {
        let state = ProxyStateManager()
        state.setBypassMode(false)

        state.prepareForStart()

        XCTAssertTrue(state.bypassMode)
    }

    func testTerminationIsAuthorizedWhenNoRestartOccurred() {
        let coordinator = DNSProxyLifecycleCoordinator()
        _ = coordinator.beginStart()
        coordinator.finishStart()
        coordinator.beginStop()

        let token = coordinator.finishStop()

        XCTAssertTrue(
            coordinator.mayTerminate(token),
            "the replacement-drain and bounce workflows depend on the process actually exiting")
    }

    func testTerminationIsSuppressedWhenBeginStartClaimsANewerGeneration() {
        let coordinator = DNSProxyLifecycleCoordinator()
        _ = coordinator.beginStart()
        coordinator.finishStart()
        coordinator.beginStop()
        let token = coordinator.finishStop()

        // A restart inside the 500ms exit delay must invalidate the pending token.
        _ = coordinator.beginStart()

        XCTAssertFalse(coordinator.mayTerminate(token))
        coordinator.finishStart()
        XCTAssertFalse(coordinator.mayTerminate(token))
    }

    func testTerminationTokenFromAnEarlierStopIsNeverReauthorized() {
        let coordinator = DNSProxyLifecycleCoordinator()
        _ = coordinator.beginStart()
        coordinator.finishStart()
        coordinator.beginStop()
        let firstToken = coordinator.finishStop()

        _ = coordinator.beginStart()
        coordinator.finishStart()
        coordinator.beginStop()
        let secondToken = coordinator.finishStop()

        XCTAssertFalse(coordinator.mayTerminate(firstToken))
        XCTAssertTrue(coordinator.mayTerminate(secondToken))
    }

    func testStopWaitsForAdmittedResourceCreation() {
        let coordinator = DNSProxyLifecycleCoordinator()
        let generation = coordinator.beginStart()
        coordinator.finishStart()
        let operationStarted = DispatchSemaphore(value: 0)
        let releaseOperation = DispatchSemaphore(value: 0)
        let stopFinished = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            coordinator.performIfCurrent(generation) {
                operationStarted.signal()
                releaseOperation.wait()
            }
        }
        XCTAssertEqual(operationStarted.wait(timeout: .now() + 1), .success)

        DispatchQueue.global().async {
            _ = coordinator.beginStop()
            stopFinished.signal()
        }
        XCTAssertEqual(stopFinished.wait(timeout: .now() + 0.05), .timedOut)

        releaseOperation.signal()
        XCTAssertEqual(stopFinished.wait(timeout: .now() + 1), .success)
    }
}

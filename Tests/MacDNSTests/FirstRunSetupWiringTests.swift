// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import MacDNS

/// An Enable that belongs to the fresh install setup asks for notifications
/// after the extension request and before the resolver starts, whose first
/// query raises the local network request. While the first-run window is open
/// it shows the outcome itself. `AppViewModel` cannot be instantiated in a
/// test process, so the wiring is pinned here.
final class FirstRunSetupWiringTests: XCTestCase {

    func testNotificationWaitRunsAfterTheExtensionAndBeforeTheResolver() throws {
        let body = try functionBody("func enableDNS(")
        let extensionRequest = try XCTUnwrap(body.range(of: "try await ensureDNSProxyConfigured("))
        let proxyDisable = try XCTUnwrap(body.range(of: "try await disableDNSProxyBeforeResolverStartIfNeeded()"))
        let wait = try XCTUnwrap(
            body.range(of: "await awaitFirstRunNotificationAnswer(generation: lifecycleGeneration)"),
            "enableDNS must wait for the notification answer during the setup"
        )
        let resolverStart = try XCTUnwrap(body.range(of: "XPCClient.shared.startResolverAsync()"))
        XCTAssertLessThan(extensionRequest.lowerBound, wait.lowerBound)
        XCTAssertLessThan(proxyDisable.lowerBound, wait.lowerBound)
        XCTAssertLessThan(wait.lowerBound, resolverStart.lowerBound)
    }

    /// The wait suspends Enable, so a removal, disable or update may start
    /// meanwhile. The lifecycle must be checked again before the resolver.
    func testEnableChecksItsLifecycleAgainAfterTheNotificationWait() throws {
        let body = try functionBody("func enableDNS(")
        let wait = try XCTUnwrap(
            body.range(of: "await awaitFirstRunNotificationAnswer(generation: lifecycleGeneration)"))
        let resolverStart = try XCTUnwrap(body.range(of: "XPCClient.shared.startResolverAsync()"))
        let between = body[wait.upperBound..<resolverStart.lowerBound]
        XCTAssertTrue(between.contains("persistedStateAvailability == .loaded"))
        XCTAssertTrue(between.contains("isCurrentDNSLifecycle(lifecycleGeneration)"))
    }

    func testNotificationWaitRunsOnlyWhenTheAttemptContinuesTheSetup() throws {
        let body = try functionBody("func enableDNS(")
        let wait = try XCTUnwrap(
            body.range(of: "await awaitFirstRunNotificationAnswer(generation: lifecycleGeneration)"))
        XCTAssertTrue(
            isInside("if continuesSetup {", at: wait.lowerBound, in: body),
            "the notification wait must be guarded by the attempt continuing the setup"
        )
    }

    /// Only an attempt that waited or was skipped replaced the request after
    /// protection starts. Every other attempt, including a setup whose window
    /// was closed, keeps it, so the two macOS requests never overlap.
    func testOnlyAHandledAttemptSkipsTheRequestAfterProtectionStarts() throws {
        let body = try functionBody("func enableDNS(")
        XCTAssertTrue(
            body.contains(
                "notificationsHandled = await awaitFirstRunNotificationAnswer(generation: lifecycleGeneration)"))
        let request = try XCTUnwrap(body.range(of: "requestNotificationPermission()"))
        let guardRange = try XCTUnwrap(
            body.range(
                of: "if !notificationsHandled {", options: .backwards, range: body.startIndex..<request.lowerBound)
        )
        XCTAssertFalse(body[guardRange.upperBound..<request.lowerBound].contains("}"))
        let enabled = try XCTUnwrap(body.range(of: "isEnabled = true"))
        XCTAssertLessThan(enabled.lowerBound, request.lowerBound)
    }

    /// A request fired without waiting would reach macOS together with the
    /// local network request the resolver raises.
    func testTheSetupNeverAsksBeforeTheResolverWithoutWaiting() throws {
        let body = try functionBody("private func awaitFirstRunNotificationAnswer(")
        XCTAssertFalse(body.contains("requestNotificationPermission()"))
        let decision = try XCTUnwrap(body.range(of: "FirstRunNotificationWait.request("))
        let request = try XCTUnwrap(body.range(of: "requestNotificationAuthorization()"))
        XCTAssertLessThan(decision.lowerBound, request.lowerBound)
    }

    /// "Skip" before the wait starts must not move the request to the moment
    /// the resolver raises the local network request.
    func testASkippedQuestionIsHandledWithoutTheRequestAfterProtectionStarts() throws {
        let body = try functionBody("private func awaitFirstRunNotificationAnswer(")
        let skipped = try XCTUnwrap(body.range(of: "case .skipped:"))
        let afterSkipped = body[skipped.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertTrue(afterSkipped.hasPrefix("return true"), "a skipped question counts as handled")
        let afterStart = try XCTUnwrap(body.range(of: "case .afterProtectionStarts:"))
        let afterAfterStart = body[afterStart.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertTrue(afterAfterStart.hasPrefix("return false"), "a closed window keeps the request after start")
    }

    func testAgentApprovalResumesThroughTheSetupPolicy() throws {
        let body = try functionBody("private func refreshApprovalStateAfterExternalChange(")
        let decision = try XCTUnwrap(body.range(of: "FreshInstallSetupPolicy.resumesEnableAfterAgentApproval("))
        let enable = try XCTUnwrap(body.range(of: "enableDNS()"))
        XCTAssertLessThan(decision.lowerBound, enable.lowerBound)
        XCTAssertTrue(body.contains("setupGeneration: freshInstallSetupGeneration"))
    }

    func testASupersededAttemptEndsItsSetup() throws {
        let body = try functionBody("private func reportFreshInstallSetupOutcome(")
        let skip = try XCTUnwrap(body.range(of: "FreshInstallSetupPolicy.reportsAttempt("))
        let release = try XCTUnwrap(
            body.range(
                of: "freshInstallSetupGeneration = FreshInstallSetupPolicy.setupGenerationAfterSupersededAttempt(")
        )
        let outcome = try XCTUnwrap(body.range(of: "let outcome = FreshInstallSetupPolicy("))
        XCTAssertLessThan(skip.lowerBound, release.lowerBound)
        XCTAssertLessThan(release.lowerBound, outcome.lowerBound)
    }

    func testSetupRunningFollowsTheSetupGeneration() throws {
        let body = try functionBody("private var freshInstallSetupGeneration: UInt64? {")
        XCTAssertTrue(body.contains("didSet {"))
        XCTAssertTrue(body.contains("freshInstallSetupRunning = freshInstallSetupGeneration != nil"))
    }

    // MARK: - Continue gates

    func testTheExtensionGateRunsBeforeTheExtensionRequest() throws {
        let body = try functionBody("func enableDNS(")
        let gate = try gateRange(.networkExtension, in: body)
        let extensionRequest = try XCTUnwrap(body.range(of: "try await ensureDNSProxyConfigured("))
        XCTAssertLessThan(gate.lowerBound, extensionRequest.lowerBound)
        XCTAssertTrue(isInside("if continuesSetup {", at: gate.lowerBound, in: body))
    }

    /// Only the setup's attempt hands its generation to the DNS filtering gate.
    func testOnlyTheSetupPassesItsGenerationToTheExtensionRequest() throws {
        let body = try functionBody("func enableDNS(")
        XCTAssertTrue(
            body.contains(
                "try await ensureDNSProxyConfigured(setupGeneration: continuesSetup ? lifecycleGeneration : nil)")
        )
    }

    /// The DNS filtering request is the registration that `activate` runs
    /// after the closure. A superseded attempt must never register.
    func testTheDNSFilterGateRunsInsideTheActivationBeforeTheRegistration() throws {
        let body = try functionBody("private func ensureDNSProxyConfigured(")
        let activate = try XCTUnwrap(body.range(of: "try await extensionManager.activate(beforeRegistering: {"))
        let setupOnly = try XCTUnwrap(body.range(of: "guard let self, let setupGeneration else { return }"))
        let gate = try gateRange(.dnsFilter, in: body)
        XCTAssertLessThan(activate.lowerBound, setupOnly.lowerBound)
        XCTAssertLessThan(setupOnly.lowerBound, gate.lowerBound)
        let check = try XCTUnwrap(body[gate.upperBound...].range(of: "else { throw CancellationError() }"))
        let between = body[gate.upperBound..<check.lowerBound]
        XCTAssertTrue(between.contains("persistedStateAvailability == .loaded"))
        XCTAssertTrue(between.contains("isCurrentDNSLifecycle(setupGeneration)"))
    }

    /// The DNS filtering gate cancels a superseded attempt. That attempt must
    /// end silently, without a failure status for the user.
    func testACancelledAttemptEndsWithoutAFailure() throws {
        let body = try functionBody("func enableDNS(")
        let cancelled = try XCTUnwrap(body.range(of: "} catch is CancellationError {"))
        let generic = try XCTUnwrap(body.range(of: "} catch {", range: cancelled.upperBound..<body.endIndex))
        let handler = body[cancelled.upperBound..<generic.lowerBound]
        XCTAssertFalse(handler.contains("statusMessage"))
        XCTAssertFalse(handler.contains("FreshInstallSetupAlert"))
    }

    func testTheNotificationsGateRunsBeforeTheNotificationRequest() throws {
        let body = try functionBody("func enableDNS(")
        let refresh = try XCTUnwrap(body.range(of: "await refreshNotificationAuthorization()"))
        let gate = try gateRange(.notifications, in: body)
        let request = try XCTUnwrap(
            body.range(of: "await awaitFirstRunNotificationAnswer(generation: lifecycleGeneration)"))
        XCTAssertLessThan(refresh.lowerBound, gate.lowerBound, "the gate reads a fresh authorization")
        XCTAssertLessThan(gate.lowerBound, request.lowerBound)
        XCTAssertTrue(isInside("if continuesSetup {", at: gate.lowerBound, in: body))
        XCTAssertTrue(body[gate].contains("stepDone: notificationsDecided || firstRunNotificationsSkipped"))
    }

    /// The app can neither trigger nor read the local network request, so
    /// Enable never waits for it.
    func testEnableNeverWaitsForLocalNetworkAccess() throws {
        let body = try functionBody("func enableDNS(")
        XCTAssertFalse(body.contains("localNetwork"))
        XCTAssertFalse(body.contains("local network access"))
    }

    /// Each gate suspends Enable, so a removal, disable or update may start
    /// meanwhile. The lifecycle is checked before the next macOS request.
    func testALifecycleCheckFollowsEachGateInEnable() throws {
        let body = try functionBody("func enableDNS(")
        for step in ["networkExtension", "notifications"] {
            let gate = try gateRange(step, in: body)
            let check = try XCTUnwrap(
                body[gate.upperBound...].range(of: "else { return }"), "no lifecycle check after the \(step) gate")
            let between = body[gate.upperBound..<check.lowerBound]
            XCTAssertTrue(between.contains("persistedStateAvailability == .loaded"), step)
            XCTAssertTrue(between.contains("isCurrentDNSLifecycle(lifecycleGeneration)"), step)
            XCTAssertFalse(between.contains("await "), "nothing may run between the \(step) gate and its check")
        }
    }

    /// A lifecycle change can land before a gate exists, for example a Disable
    /// during the extension activation, which the generation `didSet` cannot
    /// end. The gate checks the attempt's lifecycle right before it starts.
    func testAGateNeverStartsForASupersededAttempt() throws {
        let body = try functionBody("private func awaitFirstRunContinue(")
        XCTAssertTrue(body.contains("generation: UInt64"))
        let check = try XCTUnwrap(
            body.range(
                of: "guard persistedStateAvailability == .loaded, isCurrentDNSLifecycle(generation) else { return }")
        )
        let gate = try XCTUnwrap(body.range(of: "let gate = FirstRunContinueGate()"))
        XCTAssertLessThan(check.lowerBound, gate.lowerBound)
        XCTAssertFalse(body[check.upperBound..<gate.lowerBound].contains("await "))
    }

    func testEveryGatePassesItsAttemptsGeneration() throws {
        let enable = try functionBody("func enableDNS(")
        for step in ["networkExtension", "notifications"] {
            XCTAssertTrue(enable[try gateRange(step, in: enable)].contains("generation: lifecycleGeneration"), step)
        }
        let proxy = try functionBody("private func ensureDNSProxyConfigured(")
        XCTAssertTrue(proxy[try gateRange(.dnsFilter, in: proxy)].contains("generation: setupGeneration"))
        XCTAssertTrue(enable.contains("await awaitFirstRunNotificationAnswer(generation: lifecycleGeneration)"))
    }

    /// The authorization refresh suspends, so a Disable can land between it
    /// and the wait. Neither the wait nor the macOS request may follow it.
    func testTheNotificationWaitAndRequestNeverRunForASupersededAttempt() throws {
        let body = try functionBody("private func awaitFirstRunNotificationAnswer(")
        XCTAssertTrue(body.contains("generation: UInt64"))
        let refresh = try XCTUnwrap(body.range(of: "await refreshNotificationAuthorization()"))
        let check = try XCTUnwrap(
            body.range(
                of:
                    "guard persistedStateAvailability == .loaded, isCurrentDNSLifecycle(generation) else { return true }",
                range: refresh.upperBound..<body.endIndex
            )
        )
        let wait = try XCTUnwrap(body.range(of: "let wait = FirstRunNotificationWait()"))
        XCTAssertLessThan(check.lowerBound, wait.lowerBound)
        XCTAssertFalse(body[check.upperBound..<wait.lowerBound].contains("await "))

        let answer = try XCTUnwrap(body.range(of: "await wait.wait {"))
        let request = try XCTUnwrap(body.range(of: "requestNotificationAuthorization()"))
        let requestGuard = body[answer.upperBound..<request.lowerBound]
        XCTAssertTrue(requestGuard.contains("persistedStateAvailability == .loaded"))
        XCTAssertTrue(requestGuard.contains("isCurrentDNSLifecycle(generation)"))
    }

    func testTheApprovedStepEndsWithTheAttempt() throws {
        let body = try functionBody("func enableDNS(")
        let task = try XCTUnwrap(body.range(of: "Task { @MainActor in"))
        let clear = try XCTUnwrap(body.range(of: "defer { firstRunApprovedStep = nil }"))
        XCTAssertLessThan(task.lowerBound, clear.lowerBound)
    }

    func testAGateWaitsOnlyByTheGateDecision() throws {
        let body = try functionBody("private func awaitFirstRunContinue(")
        let decision = try XCTUnwrap(body.range(of: "FirstRunContinueGate.waits("))
        let wait = try XCTUnwrap(body.range(of: "await gate.wait()"))
        XCTAssertLessThan(decision.lowerBound, wait.lowerBound)
        XCTAssertTrue(body.contains("windowOpen: firstRunWindowOpen"))
        XCTAssertTrue(body.contains("approved: firstRunApprovedStep == step"))
    }

    /// The step reads nil while macOS shows its request, so the window comes
    /// forward only when the next gate starts waiting.
    func testTheAwaitedStepClearsWhenItsGateOpensOrEnds() throws {
        let open = try functionBody("private func openFirstRunContinueGate(")
        XCTAssertTrue(open.contains("firstRunContinueGate?.open()"))
        XCTAssertTrue(open.contains("firstRunAwaitingContinue = nil"))
        let gate = try functionBody("private func awaitFirstRunContinue(")
        let wait = try XCTUnwrap(gate.range(of: "await gate.wait()"))
        XCTAssertTrue(gate[wait.upperBound...].contains("firstRunAwaitingContinue = nil"))
    }

    func testContinueSkipAndCloseOpenTheGate() throws {
        XCTAssertTrue(try functionBody("func continueFirstRunStep(").contains("openFirstRunContinueGate()"))
        let skip = try functionBody("func skipFirstRunNotifications(")
        XCTAssertTrue(skip.contains("firstRunNotificationsSkipped = true"))
        XCTAssertTrue(skip.contains("openFirstRunContinueGate()"))
        XCTAssertTrue(skip.contains("firstRunNotificationWait?.end()"))
        let end = try functionBody("func endFirstRunWaits(")
        XCTAssertTrue(end.contains("openFirstRunContinueGate()"))
        XCTAssertTrue(end.contains("firstRunNotificationWait?.end()"))
    }

    /// While a setup with the window open owns the attempt, a late approval
    /// leaves the registration to the resumed Enable and its Continue.
    func testLateRegistrationDeferralFollowsTheOpenWindowAndTheSetup() throws {
        let update = try functionBody("private func updateLateProviderRegistrationDeferral(")
        XCTAssertTrue(update.contains("FreshInstallSetupPolicy.defersLateProviderRegistration("))
        XCTAssertTrue(update.contains("windowOpen: firstRunWindowOpen"))
        XCTAssertTrue(update.contains("setupGeneration: freshInstallSetupGeneration"))
        XCTAssertTrue(update.contains("currentGeneration: dnsLifecycleGeneration"))
        XCTAssertTrue(
            try functionBody("var firstRunWindowOpen = false {").contains("updateLateProviderRegistrationDeferral()"))
        XCTAssertTrue(
            try functionBody("private var freshInstallSetupGeneration: UInt64? {").contains(
                "updateLateProviderRegistrationDeferral()")
        )
        XCTAssertTrue(
            try functionBody("private var dnsLifecycleGeneration: UInt64 = 0 {").contains(
                "updateLateProviderRegistrationDeferral()")
        )
        let source = try sourceFile()
        XCTAssertEqual(source.components(separatedBy: "defersLateProviderRegistration =").count - 1, 1)
    }

    /// A setup that waits for an approval keeps its generation, so the
    /// deferral holds through a late approval while the window is open.
    func testAnAttemptWaitingForApprovalKeepsTheSetup() throws {
        let body = try functionBody("private func reportFreshInstallSetupOutcome(")
        let waiting = try XCTUnwrap(body.range(of: "case .waitingForApproval:"))
        let afterWaiting = body[waiting.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertTrue(afterWaiting.hasPrefix("return"))
    }

    func testClosingTheWindowEndsEveryWait() throws {
        let body = try functionBody(
            "func windowWillClose(",
            in: "Sources/MacDNS/UI/FirstRunWindowController.swift"
        )
        let closed = try XCTUnwrap(body.range(of: "viewModel?.firstRunWindowOpen = false"))
        let end = try XCTUnwrap(body.range(of: "viewModel?.endFirstRunWaits()"))
        XCTAssertLessThan(closed.lowerBound, end.lowerBound, "no later gate may wait once the waits ended")
    }

    /// A Disable, Uninstall, quit or update that supersedes an attempt
    /// waiting on a gate or the notification answer wakes it, so it sees the
    /// changed lifecycle in its check and frees Enable.
    func testEveryLifecycleChangeEndsTheFirstRunWaits() throws {
        let body = try functionBody("private var dnsLifecycleGeneration: UInt64 = 0 {")
        XCTAssertTrue(body.contains("endFirstRunWaits()"))
    }

    /// The DNS filtering gate also stops an attempt whose state is no longer
    /// loaded, so the log must not call every stop a supersession.
    func testTheCancelledAttemptLogCoversEveryStop() throws {
        let body = try functionBody("func enableDNS(")
        let cancelled = try XCTUnwrap(body.range(of: "} catch is CancellationError {"))
        let generic = try XCTUnwrap(body.range(of: "} catch {", range: cancelled.upperBound..<body.endIndex))
        let handler = body[cancelled.upperBound..<generic.lowerBound]
        XCTAssertTrue(handler.contains("stopped before saving the DNS Proxy configuration"))
        XCTAssertFalse(handler.contains("superseded"))
    }

    /// The window sets the approved step before "Turn On" starts setup. A
    /// start that never reaches the Enable task must not leave it for a later
    /// attempt, whose gate would then not wait. "Activate" sets none.
    func testARefusedStartClearsTheApprovedStep() throws {
        let start = try functionBody("private func startFreshInstallEnable(")
        let refused = try XCTUnwrap(start.range(of: "guard enableDNS(asFreshInstallSetup: true) else {"))
        let clear = try XCTUnwrap(start.range(of: "firstRunApprovedStep = nil"))
        XCTAssertLessThan(refused.lowerBound, clear.lowerBound)

        let turnOn = try functionBody("func turnOnFromFirstRun(")
        let preparing = try XCTUnwrap(turnOn.range(of: "guard !firstRunPreparing else { return false }"))
        let lines = turnOn[preparing.upperBound...].components(separatedBy: "\n").map {
            $0.trimmingCharacters(in: .whitespaces)
        }
        let refusals = lines.indices.filter { lines[$0] == "return false" }
        XCTAssertFalse(refusals.isEmpty)
        for index in refusals {
            XCTAssertEqual(lines[index - 1], "firstRunApprovedStep = nil")
        }
        XCTAssertFalse(try functionBody("func activateLicenseAndTurnOn(").contains("firstRunApprovedStep"))
    }

    // MARK: - Window

    func testTheWindowReadsTheExtensionActivationAndTheAwaitedStep() throws {
        let body = try functionBody(
            "fileprivate static func setup(for viewModel: AppViewModel)",
            in: "Sources/MacDNS/UI/FirstRunWindowController.swift"
        )
        XCTAssertTrue(body.contains("extensionActivated: ExtensionManager.shared.systemExtensionActivated,"))
        XCTAssertTrue(body.contains("awaitingContinue: viewModel.firstRunAwaitingContinue,"))
    }

    /// "Turn On" and "Continue" on the resumed window answer the step whose
    /// explanation is on display, so it never needs a second click.
    func testTurnOnApprovesTheCurrentStep() throws {
        let body = try makeActionsBody()
        XCTAssertTrue(body.contains("viewModel.firstRunApprovedStep = Self.setup(for: viewModel).currentStep"))
        XCTAssertTrue(
            try actionBody("turnOn: {", until: "viewModel.turnOnFromFirstRun(", in: body)
                .contains("approveCurrentStep()"))
        XCTAssertTrue(body.contains("continueStep: { viewModel.continueFirstRunStep() }"))
    }

    /// The failed and Trial ended screens show no step explanation, so their
    /// clicks answer nothing and the step asks for "Continue".
    func testTryAgainAndActivateApproveNoStep() throws {
        let body = try makeActionsBody()
        XCTAssertFalse(
            try actionBody("tryAgain: {", until: "viewModel.retryFreshInstallSetup()", in: body)
                .contains("approveCurrentStep()"))
        XCTAssertFalse(
            try actionBody("activate: {", until: "viewModel.activateLicenseAndTurnOn(", in: body)
                .contains("approveCurrentStep()"))
    }

    private func makeActionsBody() throws -> String {
        try functionBody(
            "fileprivate func makeActions(viewModel: AppViewModel)",
            in: "Sources/MacDNS/UI/FirstRunWindowController.swift"
        )
    }

    /// The text of the action labelled `label` up to its call to `start`.
    private func actionBody(_ label: String, until start: String, in body: String) throws -> Substring {
        let action = try XCTUnwrap(body.range(of: label), label)
        let call = try XCTUnwrap(body.range(of: start, range: action.upperBound..<body.endIndex), start)
        return body[action.upperBound..<call.lowerBound]
    }

    /// Skip stays while macOS shows the notification request, so a user who
    /// missed the banner is never left with a spinner and no button.
    func testTheWaitingStepShowsContinueAndSkipStaysWhileTheRequestRuns() throws {
        let body = try functionBody("private func stepsButtons(", in: "Sources/MacDNS/UI/FirstRunView.swift")
        let running = try XCTUnwrap(body.range(of: "case .running:"))
        let failed = try XCTUnwrap(body.range(of: "case .failed:"))
        let section = String(body[running.upperBound..<failed.lowerBound])
        let primary = try XCTUnwrap(section.range(of: "primary(\"Continue\", action: actions.continueStep)"))
        XCTAssertTrue(isInside("if setup.awaitsContinue {", at: primary.lowerBound, in: section))
        let skip = try XCTUnwrap(section.range(of: "secondaryButton(\"Skip\", action: actions.skipNotifications)"))
        XCTAssertTrue(isInside("if setup.offersSkip {", at: skip.lowerBound, in: section))
        XCTAssertFalse(isInside("if setup.awaitsContinue {", at: skip.lowerBound, in: section))
        XCTAssertLessThan(primary.lowerBound, skip.lowerBound)
    }

    /// The window comes forward only on the policy's transitions and never
    /// stays above System Settings, where the user approves the extension.
    func testTheWindowComesForwardOnlyByThePolicyWhileShown() throws {
        let content = try functionBody("var body: some View {", in: "Sources/MacDNS/UI/FirstRunWindowController.swift")
        let decision = try XCTUnwrap(content.range(of: "FirstRunSetupPolicy.bringsWindowToFront(from: old, to: new)"))
        let raise = try XCTUnwrap(content.range(of: "controller.bringWindowToFront()"))
        XCTAssertLessThan(decision.lowerBound, raise.lowerBound)

        let raiseBody = try functionBody(
            "fileprivate func bringWindowToFront(",
            in: "Sources/MacDNS/UI/FirstRunWindowController.swift"
        )
        let shown = try XCTUnwrap(raiseBody.range(of: "guard isShowing, let window else { return }"))
        let front = try XCTUnwrap(raiseBody.range(of: "window.makeKeyAndOrderFront(nil)"))
        XCTAssertLessThan(shown.lowerBound, front.lowerBound, "a closed window must never reopen")
        XCTAssertTrue(raiseBody.contains("NSApp.activate(ignoringOtherApps: true)"))
        let controller = try sourceFile("Sources/MacDNS/UI/FirstRunWindowController.swift")
        XCTAssertFalse(controller.contains(".level"))
    }

    func testSetupAlertsShowOnlyWhileTheWindowIsClosed() throws {
        let body = try functionBody("private func reportFreshInstallSetupOutcome(")
        let cases = body.components(separatedBy: "case .").dropFirst()
        let presenting = cases.filter { $0.contains("FreshInstallSetupAlert.") }
        XCTAssertEqual(presenting.count, 2, "the restart and failure alerts are expected")
        for section in presenting {
            let windowGuard = try XCTUnwrap(
                section.range(of: "guard !firstRunWindowOpen else"),
                "FreshInstallSetupAlert must show only while the first-run window is closed"
            )
            let alert = try XCTUnwrap(section.range(of: "FreshInstallSetupAlert."))
            XCTAssertLessThan(windowGuard.lowerBound, alert.lowerBound)
        }
    }

    func testReportPublishesTheOutcome() throws {
        let body = try functionBody("private func reportFreshInstallSetupOutcome(")
        let publish = try XCTUnwrap(body.range(of: "freshInstallSetupOutcome = outcome"))
        let firstCase = try XCTUnwrap(body.range(of: "case .waitingForApproval"))
        XCTAssertLessThan(publish.lowerBound, firstCase.lowerBound, "waiting for approval is published too")
    }

    func testASetupAttemptClearsThePreviousOutcome() throws {
        let body = try functionBody("func enableDNS(")
        let clear = try XCTUnwrap(body.range(of: "freshInstallSetupOutcome = nil"))
        let clearMessage = try XCTUnwrap(body.range(of: "freshInstallSetupFailureMessage = nil"))
        let task = try XCTUnwrap(body.range(of: "Task { @MainActor in"))
        XCTAssertLessThan(clear.lowerBound, task.lowerBound)
        XCTAssertLessThan(clearMessage.lowerBound, task.lowerBound)
    }

    /// The window shows the failure as the alert does: with the status message
    /// from when the attempt failed, not one that changed afterwards.
    func testReportKeepsTheFailureMessageWithTheOutcome() throws {
        let body = try functionBody("private func reportFreshInstallSetupOutcome(")
        let publish = try XCTUnwrap(body.range(of: "freshInstallSetupOutcome = outcome"))
        let message = try XCTUnwrap(
            body.range(of: "freshInstallSetupFailureMessage = outcome == .failed ? statusMessage : nil"))
        let firstCase = try XCTUnwrap(body.range(of: "case .waitingForApproval"))
        XCTAssertLessThan(publish.lowerBound, message.lowerBound)
        XCTAssertLessThan(message.lowerBound, firstCase.lowerBound)
    }

    func testTheWindowShowsTheFailureMessageKeptWithTheOutcome() throws {
        let body = try functionBody(
            "fileprivate func message(for screen: FirstRunScreen",
            in: "Sources/MacDNS/UI/FirstRunWindowController.swift"
        )
        let failed = try XCTUnwrap(body.range(of: "case .steps(.failed):"))
        let afterFailed = body[failed.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertTrue(afterFailed.hasPrefix("return viewModel.freshInstallSetupFailureMessage"))
    }

    private func gateRange(_ step: FirstRunSetupStep, in body: String) throws -> Range<String.Index> {
        try gateRange(String(describing: step), in: body)
    }

    /// The `awaitFirstRunContinue` call for `step`, from `await` to its closing parenthesis.
    private func gateRange(_ step: String, in body: String) throws -> Range<String.Index> {
        var searchStart = body.startIndex
        while let call = body.range(of: "await awaitFirstRunContinue(", range: searchStart..<body.endIndex) {
            let arguments = body[call.upperBound...].drop(while: { $0.isWhitespace })
            if arguments.hasPrefix("on: .\(step),") {
                var depth = 1
                var index = call.upperBound
                while index < body.endIndex {
                    if body[index] == "(" { depth += 1 }
                    if body[index] == ")" { depth -= 1 }
                    index = body.index(after: index)
                    if depth == 0 { return call.lowerBound..<index }
                }
                return try XCTUnwrap(nil as Range<String.Index>?, "unclosed Continue gate for \(step)")
            }
            searchStart = call.upperBound
        }
        return try XCTUnwrap(nil as Range<String.Index>?, "no Continue gate for \(step)")
    }

    /// Whether `position` lies inside the block opened by the last `opener`
    /// before it.
    private func isInside(_ opener: String, at position: String.Index, in body: String) -> Bool {
        guard let open = body.range(of: opener, options: .backwards, range: body.startIndex..<position) else {
            return false
        }
        var depth = 1
        for character in body[open.upperBound..<position] {
            if character == "{" { depth += 1 }
            if character == "}" { depth -= 1 }
            if depth == 0 { return false }
        }
        return true
    }

    private func sourceFile(
        _ relativePath: String = "Sources/MacDNS/ViewModels/AppViewModel.swift",
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
        return try XCTUnwrap(nil as String?, "\(relativePath) not found above the test source path")
    }

    private func functionBody(
        _ signature: String,
        in relativePath: String = "Sources/MacDNS/ViewModels/AppViewModel.swift",
        from filePath: String = #filePath
    ) throws -> String {
        var directory = URL(fileURLWithPath: filePath).deletingLastPathComponent()
        var contents: String?
        while directory.path != "/" {
            let candidate = directory.appendingPathComponent(relativePath)
            if FileManager.default.fileExists(atPath: candidate.path) {
                contents = try String(contentsOf: candidate, encoding: .utf8)
                break
            }
            directory = directory.deletingLastPathComponent()
        }
        let source = try XCTUnwrap(contents, "\(relativePath) not found above the test source path")
        let start = try XCTUnwrap(
            source.range(of: signature),
            "\(signature) not found in \(relativePath)"
        )
        let remainder = source[start.upperBound...]
        guard let end = remainder.range(of: "\n    }") else { return String(remainder) }
        return String(remainder[..<end.lowerBound])
    }
}

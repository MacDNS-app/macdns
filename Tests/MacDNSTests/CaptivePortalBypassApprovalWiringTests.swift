// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import ObjectiveC
import Shared
import XCTest

@testable import MacDNSAgent

/// The approval is the only writer of `captiveFullBypassApproval`, so it decides
/// whether the whole DNS security model can be switched off. `MacDNSAgent`, the
/// `XPCClient` and `AppViewModel` cannot be instantiated in a test process, so
/// the pure policy is covered in `CaptivePortalDecisionPolicyTests` and the
/// selected source structure that reaches it is checked here. Source checks do
/// not execute the agent or its timers.
final class CaptivePortalBypassApprovalWiringTests: XCTestCase {
    func testXPCInterfaceExposesTheApprovalEntrypoint() throws {
        let description = protocol_getMethodDescription(
            MacDNSXPCProtocol.self,
            NSSelectorFromString("approveCaptivePortalBypassWithReply:"),
            true,
            true
        )

        XCTAssertNotNil(
            description.name,
            "MacDNSXPCProtocol must expose approveCaptivePortalBypass; the approval has no other writer"
        )
    }

    /// The grant must bind to the network attached at grant time and must come
    /// from `CaptivePortalFullBypassApproval.grant`, whose deadline is derived
    /// from the grant instant, never from a probe result.
    func testAgentGrantsOnlyANetworkBoundApproval() throws {
        let body = try methodBody(
            of: "func approveCaptivePortalBypass",
            in: "Sources/MacDNSAgent/MacDNSAgent.swift"
        )

        XCTAssertTrue(
            body.contains("NetworkMonitor.currentNetworkIdentity()"),
            "the approval must bind to the currently attached network"
        )
        XCTAssertTrue(
            body.contains(".grant(") && body.contains("networkIdentity: identity"),
            "the approval must come from the grant factory bound to that identity"
        )
        XCTAssertTrue(
            body.contains("reply(false)"),
            "an unidentifiable network must refuse the grant"
        )
    }

    /// An agent that predates the method makes NSXPC fail the message instead of
    /// answering it. The error handler must report a refusal, never an approval.
    func testAppApprovalCallFailsClosedWithoutAnAgentThatImplementsIt() throws {
        let body = try methodBody(
            of: "func approveCaptivePortalBypass",
            in: "Sources/MacDNS/Services/XPCClient.swift"
        )

        XCTAssertTrue(
            body.contains("getProxy { _ in completion(false) }"),
            "an unreachable or older agent must resolve the approval as refused"
        )
    }

    /// Pressing the button while the constrained compatibility mode is already
    /// running has to change something. A probe re-confirmation cannot deliver
    /// the approval: `CaptivePortalDetector` only calls the delegate when the
    /// confirmed outcome changes, and a portal that keeps answering
    /// `.captive` never changes it, so the grant has to be applied on its own.
    func testAGrantedApprovalAppliesToAPortalTheDetectorAlreadySuspects() {
        XCTAssertTrue(
            CaptiveApprovalActivationPolicy.appliesImmediately(
                detectorStatus: .captive,
                fullBypassActive: false
            )
        )
        XCTAssertTrue(
            CaptiveApprovalActivationPolicy.appliesImmediately(
                detectorStatus: .dnsIntercepted,
                fullBypassActive: false
            )
        )
    }

    func testAGrantedApprovalChangesNothingWithoutASuspectedPortal() {
        XCTAssertFalse(
            CaptiveApprovalActivationPolicy.appliesImmediately(
                detectorStatus: .normal,
                fullBypassActive: false
            ),
            "an approval must not switch protection off on a healthy network"
        )
        XCTAssertFalse(
            CaptiveApprovalActivationPolicy.appliesImmediately(
                detectorStatus: .unknown,
                fullBypassActive: false
            )
        )
        XCTAssertFalse(
            CaptiveApprovalActivationPolicy.appliesImmediately(
                detectorStatus: .captive,
                fullBypassActive: true
            ),
            "a bypass that is already running needs no second transition"
        )
    }

    /// Leaving the bypass returns to the constrained compatibility mode for
    /// every status that could have justified the grant. Restoring only for
    /// `.captive` would drop a known-intercepted network into unconstrained
    /// resolution.
    func testLeavingTheBypassCoversEveryStatusAGrantCouldHaveCovered() {
        XCTAssertTrue(
            CaptiveApprovalActivationPolicy.needsConstrainedForwarding(.captive)
        )
        XCTAssertTrue(
            CaptiveApprovalActivationPolicy.needsConstrainedForwarding(
                .dnsIntercepted
            )
        )
        XCTAssertFalse(
            CaptiveApprovalActivationPolicy.needsConstrainedForwarding(.normal)
        )
        XCTAssertFalse(
            CaptiveApprovalActivationPolicy.needsConstrainedForwarding(.unknown)
        )
    }

    /// The reconciliation pass reads the approval, then acts on it outside that
    /// read. A grant that landed in between owns the decision, so revoking on
    /// the stale one would kill the new approval before its transition runs.
    func testRevocationStopsWhenTheApprovalItReadWasReplaced() throws {
        let body = try methodBody(
            of: "private func reconcileCaptiveFullBypassAuthorization",
            in: "Sources/MacDNSAgent/MacDNSAgent.swift"
        )
        let branch = try XCTUnwrap(
            body.range(of: "case .revokeBypass:"),
            "reconciliation must handle .revokeBypass"
        )
        let revocation = String(body[branch.upperBound...])

        let clear = try XCTUnwrap(
            revocation.range(
                of: "guard clearCaptiveFullBypassApproval(approval) else { return }"
            ),
            "revocation must abort when the approval it evaluated is no longer current"
        )
        let restore = try XCTUnwrap(
            revocation.range(of: "restoreProtectionAfterApprovalLapsed()")
        )

        XCTAssertTrue(
            clear.lowerBound < restore.lowerBound,
            "the guard must run before protection is restored"
        )
    }

    /// Structurally requires a direct rearm in the keep branch. Timer behavior
    /// is outside this source check.
    func testKeepBypassSourceBranchContainsADirectDeadlineRearm() throws {
        let body = try methodBody(
            of: "private func reconcileCaptiveFullBypassAuthorization",
            in: "Sources/MacDNSAgent/MacDNSAgent.swift"
        )

        XCTAssertTrue(
            keptBypassHasScopedRearm(in: body),
            "the .keepBypass branch must directly rearm the deadline"
        )
    }

    /// Checks retry placement under the still-bypassed condition, not whether
    /// a timer fires or a resolver restart succeeds.
    func testRestorationSourceSchedulesRetryInsideStillBypassedGuard() throws {
        let body = try methodBody(
            of: "private func restoreProtectionAfterApprovalLapsed",
            in: "Sources/MacDNSAgent/MacDNSAgent.swift"
        )

        XCTAssertTrue(
            restorationHasScopedRetry(in: body),
            "the still-bypassed guard must schedule a retry before returning"
        )
    }

    func testRearmGuardRejectsACallMovedToAnotherSwitchCase() throws {
        let body = try methodBody(
            of: "private func reconcileCaptiveFullBypassAuthorization",
            in: "Sources/MacDNSAgent/MacDNSAgent.swift"
        )
        let moved = body.replacingOccurrences(
            of:
                "case .keepBypass:\n            rearmCaptiveApprovalExpiryTimer(for: approval)\n        case .dropApproval:",
            with:
                "case .keepBypass:\n            return\n        case .dropApproval:\n            rearmCaptiveApprovalExpiryTimer(for: approval)"
        )

        XCTAssertNotEqual(moved, body, "The mutation must move the rearm call")
        XCTAssertFalse(keptBypassHasScopedRearm(in: moved))
    }

    private func keptBypassHasScopedRearm(in body: String) -> Bool {
        guard let start = body.range(of: "\n        case .keepBypass:") else { return false }
        let remainder = body[start.upperBound...]
        guard let end = remainder.range(of: "\n        case ") else { return false }
        return remainder[..<end.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines)
            == "rearmCaptiveApprovalExpiryTimer(for: approval)"
    }

    func testRearmGuardRejectsAnUnreachableCallInTheKeepBranch() throws {
        let body = try methodBody(
            of: "private func reconcileCaptiveFullBypassAuthorization",
            in: "Sources/MacDNSAgent/MacDNSAgent.swift"
        )
        let unreachable = body.replacingOccurrences(
            of: "case .keepBypass:",
            with: "case .keepBypass:\n            return"
        )

        XCTAssertNotEqual(unreachable, body)
        XCTAssertFalse(keptBypassHasScopedRearm(in: unreachable))
    }

    func testRetryGuardRejectsACallMovedOutsideTheStillBypassedBranch() throws {
        let body = try methodBody(
            of: "private func restoreProtectionAfterApprovalLapsed",
            in: "Sources/MacDNSAgent/MacDNSAgent.swift"
        )
        let call =
            "startCaptiveApprovalExpiryTimer(\n                firingIn: Self.captiveProtectionRestoreRetryInterval\n            )"
        let moved = body.replacingOccurrences(of: call, with: "") + "\n" + call

        XCTAssertTrue(body.contains(call), "The mutation must move an existing retry call")
        XCTAssertFalse(restorationHasScopedRetry(in: moved))
    }

    func testRetryGuardRejectsAnUnreachableCallAndAnInvertedCondition() throws {
        let body = try methodBody(
            of: "private func restoreProtectionAfterApprovalLapsed",
            in: "Sources/MacDNSAgent/MacDNSAgent.swift"
        )
        let unreachable = body.replacingOccurrences(
            of: "            startCaptiveApprovalExpiryTimer(",
            with: "            return\n            startCaptiveApprovalExpiryTimer("
        )
        let inverted = body.replacingOccurrences(
            of: "guard !lifecycleLock.withLock({ captivePortalBypassEnabled }) else {",
            with: "guard lifecycleLock.withLock({ captivePortalBypassEnabled }) else {"
        )

        XCTAssertNotEqual(unreachable, body)
        XCTAssertNotEqual(inverted, body)
        XCTAssertFalse(restorationHasScopedRetry(in: unreachable))
        XCTAssertFalse(restorationHasScopedRetry(in: inverted))
    }

    private func restorationHasScopedRetry(in body: String) -> Bool {
        let condition = "guard !lifecycleLock.withLock({ captivePortalBypassEnabled }) else {"
        guard let start = body.range(of: condition) else { return false }
        let remainder = body[start.upperBound...]
        guard let end = remainder.range(of: "\n        }") else { return false }
        let branch = String(remainder[..<end.lowerBound])
        let call =
            "startCaptiveApprovalExpiryTimer(\n                firingIn: Self.captiveProtectionRestoreRetryInterval\n            )"
        guard let retry = branch.range(of: call) else { return false }
        let beforeRetry = branch[..<retry.lowerBound]
        return beforeRetry.range(of: #"(?m)^\s*return\b"#, options: .regularExpression) == nil
    }

    /// Runtime state only: a `Codable` approval could be written into
    /// `state.json`, which would outlive both the window and the network.
    func testTheApprovalCannotBeEncodedIntoPersistedState() {
        XCTAssertFalse(
            CaptivePortalFullBypassApproval.self is any Codable.Type,
            "the approval must stay memory-only"
        )
    }

    // MARK: - Source inspection

    private func methodBody(
        of declaration: String,
        in relativePath: String
    ) throws -> String {
        let contents = try source(relativePath)
        let start = try XCTUnwrap(
            contents.range(of: declaration),
            "\(declaration) not found in \(relativePath)"
        )
        let remainder = contents[start.upperBound...]
        guard let end = remainder.range(of: "\n    }") else { return String(remainder) }
        return String(remainder[..<end.lowerBound])
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

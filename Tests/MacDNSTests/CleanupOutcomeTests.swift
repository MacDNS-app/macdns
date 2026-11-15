// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import ServiceManagement
import SystemExtensions
import XCTest

@testable import MacDNS

final class CleanupOutcomeTests: XCTestCase {
    func testOnlyDocumentedAbsenceErrorsAreExpected() {
        XCTAssertTrue(
            CleanupOutcome.isExpectedAbsence(NSError(domain: "SMAppServiceErrorDomain", code: Int(kSMErrorJobNotFound)))
        )
        XCTAssertTrue(
            CleanupOutcome.isExpectedAbsence(
                NSError(domain: OSSystemExtensionErrorDomain, code: OSSystemExtensionError.extensionNotFound.rawValue)))
        XCTAssertFalse(
            CleanupOutcome.isExpectedAbsence(
                NSError(domain: "SMAppServiceErrorDomain", code: Int(kSMErrorAuthorizationFailure))))
        XCTAssertFalse(CleanupOutcome.isExpectedAbsence(NSError(domain: "other", code: Int(kSMErrorJobNotFound))))
    }

    func testWrappedAgentAbsenceIsExpected() {
        let missing = NSError(domain: "SMAppServiceErrorDomain", code: Int(kSMErrorJobNotFound))
        XCTAssertTrue(CleanupOutcome.isExpectedAbsence(AgentError.unregistrationFailed(missing)))
    }

    func testDelegatePreservesRebootPendingAndCompletesOnce() {
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: "app.macdns.dnsproxy", queue: .main)
        var results: [OSSystemExtensionRequest.Result] = []
        let delegate = SystemExtensionDeactivationDelegate { result in
            if case .success(let value) = result { results.append(value) }
        }
        delegate.request(request, didFinishWithResult: .willCompleteAfterReboot)
        delegate.request(request, didFinishWithResult: .completed)
        delegate.request(request, didFailWithError: NSError(domain: "test", code: 1))
        XCTAssertEqual(results, [.willCompleteAfterReboot])
    }

    func testRebootPendingIsNotCompleted() {
        XCTAssertTrue(CleanupOutcome.needsReboot(.willCompleteAfterReboot))
        XCTAssertFalse(CleanupOutcome.needsReboot(.completed))
    }
}

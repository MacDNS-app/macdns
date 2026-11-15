// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import MacDNS

/// `enableDNS()` guards itself with `isEnablingDNS` and clears it from a `defer`.
/// A license lookup with no deadline suspends that task forever against a connected
/// but unresponsive Agent, the `defer` never runs, and every later enable attempt is
/// refused for the rest of the App session. `AppViewModel` cannot be instantiated in
/// a test process, so the wiring that keeps the lookup bounded is pinned here.
final class EnableDNSLicenseLookupTests: XCTestCase {

    func testEnableDNSClearsItsProgressFlagFromADefer() throws {
        let body = try enableDNSBody()

        XCTAssertTrue(
            body.contains("defer { isEnablingDNS = false }"),
            "enableDNS must clear its progress flag on every exit path"
        )
    }

    func testEnableDNSLooksUpTheLicenseThroughTheTimeoutProtectedAPI() throws {
        let body = try enableDNSBody()

        XCTAssertTrue(
            body.contains("XPCClient.shared.getLicenseInfoAsync()"),
            "enableDNS must use the timeout-protected license lookup"
        )
        XCTAssertFalse(
            body.contains("withCheckedContinuation"),
            "an unbounded continuation in enableDNS can strand isEnablingDNS forever"
        )
    }

    /// A failed lookup means unknown, not fail-closed: writing a `!isServiceAllowed`
    /// info here would make the license guard at the top of `enableDNS` refuse every
    /// later attempt, reproducing the same permanent block through another route.
    func testAFailedLookupLeavesTheLicenseUnknown() throws {
        let body = try enableDNSBody()

        XCTAssertTrue(
            body.contains("licenseInfo = nil"),
            "a failed license lookup must leave the license unknown"
        )
        XCTAssertFalse(
            body.contains("failClosedInfo()"),
            "enableDNS must not fail the license closed on a transport failure"
        )
    }

    /// The App must have no second, deadline-free way to read the license.
    func testTheClientExposesNoUnboundedLicenseLookup() throws {
        let source = try source("Sources/MacDNS/Services/XPCClient.swift")

        XCTAssertFalse(
            source.contains("func getLicenseInfo(completion:"),
            "the callback-based license lookup has no timeout and must not come back"
        )
        let bounded = try XCTUnwrap(
            source.range(of: "func getLicenseInfoAsync()"),
            "the timeout-protected license lookup is missing"
        )
        XCTAssertTrue(
            source[bounded.upperBound...].prefix(200).contains("withResultTimeout"),
            "the license lookup must stay wrapped in a timeout"
        )
    }

    private func enableDNSBody(from filePath: String = #filePath) throws -> String {
        let contents = try source("Sources/MacDNS/ViewModels/AppViewModel.swift", from: filePath)
        let start = try XCTUnwrap(
            contents.range(of: "func enableDNS("),
            "func enableDNS( not found in AppViewModel.swift"
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

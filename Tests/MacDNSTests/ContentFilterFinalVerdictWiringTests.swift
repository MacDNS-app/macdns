// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

final class ContentFilterFinalVerdictWiringTests: XCTestCase {
    func testEveryDataCallbackProducesAFinalVerdict() throws {
        let contents = try source(
            "Sources/ContentFilterExtension/ContentFilterProvider.swift"
        )

        for handler in [
            "override func handleOutboundDataComplete(\n        for flow: NEFilterFlow\n    ) -> NEFilterDataVerdict",
            "override func handleInboundData(\n        from flow: NEFilterFlow,",
            "override func handleInboundDataComplete(\n        for flow: NEFilterFlow\n    ) -> NEFilterDataVerdict",
        ] {
            XCTAssertTrue(
                contents.contains(handler),
                "every NEFilterDataProvider data callback must be implemented: \(handler)"
            )
        }
        XCTAssertEqual(
            contents.components(separatedBy: "finalFlowVerdict(for: flow)").count - 1,
            4,
            "all four data callbacks must share the same final decision"
        )
        XCTAssertTrue(
            contents.contains("withFilterInbound: false"),
            "inbound handlers complete the contract; inbound inspection must stay off"
        )
    }

    private func source(
        _ relativePath: String,
        from filePath: String = #filePath
    ) throws -> String {
        var url = URL(fileURLWithPath: filePath)
        for _ in 0 ..< 3 {
            url.deleteLastPathComponent()
        }
        return try String(
            contentsOf: url.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }
}

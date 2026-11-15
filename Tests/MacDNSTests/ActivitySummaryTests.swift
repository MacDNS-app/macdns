// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

@testable import MacDNS
import Shared
import XCTest

final class ActivitySummaryTests: XCTestCase {
    private func blocked(_ category: BlocklistCategory, _ count: Int) -> BlockedDomain {
        BlockedDomain(domain: "\(UUID().uuidString).example", category: category, blockCount: count)
    }

    func testEmptyList() {
        let summary = ActivitySummary(domains: [])
        XCTAssertEqual(summary.domainCount, 0)
        XCTAssertEqual(summary.totalBlocks, 0)
        XCTAssertNil(summary.topCategory)
    }

    func testSumsAndTopCategory() {
        let summary = ActivitySummary(domains: [
            blocked(.adsTracking, 5), blocked(.adsTracking, 3), blocked(.malwareSecurity, 7),
        ])
        XCTAssertEqual(summary.domainCount, 3)
        XCTAssertEqual(summary.totalBlocks, 15)
        XCTAssertEqual(summary.topCategory, .adsTracking)
    }

    func testTieBreaksByCategoryOrder() {
        let summary = ActivitySummary(domains: [blocked(.malwareSecurity, 4), blocked(.adsTracking, 4)])
        XCTAssertEqual(summary.topCategory, .adsTracking)
    }
}

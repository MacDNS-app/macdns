// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

@testable import MacDNS
import XCTest

final class SettingsSectionTests: XCTestCase {
    func testSidebarOrderAndGroups() {
        XCTAssertEqual(SettingsSection.allCases.first, .overview)
        XCTAssertNil(SettingsSection.overview.group)
        XCTAssertEqual(SettingsSection.sections(in: .dns), [.resolver, .forwardZones, .overrides])
        XCTAssertEqual(SettingsSection.sections(in: .filtering), [.blocklist, .allowlist])
        XCTAssertEqual(SettingsSection.sections(in: .insights), [.queries, .activity])
        XCTAssertEqual(SettingsSection.sections(in: .macdns), [.advanced, .licenseUpdates])
    }

    func testGroupTitles() {
        XCTAssertEqual(SettingsSectionGroup.allCases.map(\.title), ["DNS", "Filtering", "Insights", "MacDNS"])
    }

    func testEverySectionAfterOverviewIsListedInGroupOrder() {
        let grouped = SettingsSectionGroup.allCases.flatMap { SettingsSection.sections(in: $0) }
        XCTAssertEqual([.overview] + grouped, SettingsSection.allCases)
    }

    func testQueriesKeywordsFindQueries() {
        XCTAssertEqual(SettingsSection.queries.keywords, ["queries", "lookups", "history", "hosts", "log"])
        XCTAssertTrue(SettingsSection.allCases.filter { $0.matches("history") }.contains(.queries))
        XCTAssertTrue(SettingsSection.allCases.filter { $0.matches("hosts") }.contains(.queries))
    }

    func testKeywordFindsSectionCaseInsensitively() {
        XCTAssertEqual(SettingsSection.allCases.filter { $0.matches("DNSSEC") }, [.resolver])
        XCTAssertTrue(SettingsSection.overrides.matches("cname"))
        XCTAssertTrue(SettingsSection.licenseUpdates.matches("License"))
    }

    func testFormerTitlesStillFindTheRenamedSections() {
        XCTAssertEqual(SettingsSection.allCases.filter { $0.matches("resolver") }, [.resolver])
        XCTAssertEqual(SettingsSection.allCases.filter { $0.matches("overrides") }, [.overrides])
        XCTAssertEqual(SettingsSection.allCases.filter { $0.matches("query mode") }, [.resolver])
    }

    func testGroupTitleFindsEverySectionInTheGroup() {
        XCTAssertEqual(
            SettingsSection.allCases.filter { $0.matches("dns") },
            [.resolver, .forwardZones, .overrides]
        )
        XCTAssertEqual(
            SettingsSection.allCases.filter { $0.matches("filter") },
            [.blocklist, .allowlist]
        )
        XCTAssertEqual(
            SettingsSection.allCases.filter { $0.matches("insights") },
            [.queries, .activity]
        )
    }

    func testWhitespaceQueryMatchesEverySection() {
        XCTAssertEqual(SettingsSection.allCases.filter { $0.matches("   ") }, SettingsSection.allCases)
    }

    func testUnknownQueryMatchesNothing() {
        XCTAssertTrue(SettingsSection.allCases.filter { $0.matches("zzzz") }.isEmpty)
    }

    func testPreviousAndNextFollowTheSidebarAcrossGroups() {
        XCTAssertEqual(SettingsSection.overview.next, .resolver)
        XCTAssertEqual(SettingsSection.overrides.next, .blocklist)
        XCTAssertEqual(SettingsSection.blocklist.previous, .overrides)
        XCTAssertEqual(SettingsSection.allowlist.next, .queries)
        XCTAssertEqual(SettingsSection.queries.previous, .allowlist)
        XCTAssertEqual(SettingsSection.queries.next, .activity)
        XCTAssertEqual(SettingsSection.activity.previous, .queries)
        XCTAssertEqual(SettingsSection.activity.next, .advanced)
        XCTAssertEqual(SettingsSection.advanced.previous, .activity)
        XCTAssertEqual(SettingsSection.resolver.previous, .overview)
    }

    func testPreviousAndNextStopAtTheEnds() {
        XCTAssertNil(SettingsSection.overview.previous)
        XCTAssertNil(SettingsSection.licenseUpdates.next)
    }

    func testNextVisitsEverySectionOnce() {
        let walk = Array(sequence(first: SettingsSection.overview, next: \.next))
        XCTAssertEqual(walk, SettingsSection.allCases)
    }

    func testPinnedTitlesAndSymbols() {
        XCTAssertEqual(SettingsSection.allCases.map(\.title), [
            "Overview", "DNS Providers", "Forward Zones", "Local Records", "Blocklist",
            "Allowlist", "Queries", "Blocked", "Advanced", "License & Updates",
        ])
        XCTAssertEqual(SettingsSection.allCases.map(\.symbolName), [
            "lock.shield.fill", "server.rack", "globe",
            "arrow.triangle.swap", "nosign", "checkmark.shield.fill",
            "chart.bar.xaxis", "hand.raised", "slider.horizontal.3", "key.fill",
        ])
    }
}

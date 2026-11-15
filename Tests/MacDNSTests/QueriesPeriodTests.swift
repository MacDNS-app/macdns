// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

@testable import MacDNS

/// Clicking a bar of the Lookups Over Time chart zooms into it, one level at a time.
final class QueriesPeriodTests: XCTestCase {
    /// 2025-11-07 12:17:05 UTC.
    private let now = 1_762_517_825
    /// 2025-11-07 00:00 UTC.
    private let today = 1_762_473_600
    private let day = 86_400

    func testADayOf7DOr30DZoomsIntoThatDay() {
        for range in [QueryHistoryRange.week, .month] {
            XCTAssertEqual(
                QueriesPeriod(range: range).zoom(into: today - 3 * day, now: now),
                QueryHistoryZoom(span: .day, start: today - 3 * day))
        }
    }

    func testAnHourOf24HOrOfAZoomedDayZoomsIntoThatHour() {
        let hour = today + 9 * 3600
        let periods = [
            QueriesPeriod(range: .day),
            QueriesPeriod(range: .month, zoom: QueryHistoryZoom(span: .day, start: today)),
        ]
        for period in periods {
            XCTAssertEqual(period.zoom(into: hour, now: now), QueryHistoryZoom(span: .hour, start: hour))
        }
    }

    func testFiveMinuteBarsHaveNoFinerView() {
        let hour = today + 12 * 3600
        XCTAssertNil(QueriesPeriod(range: .hour).zoom(into: hour, now: now))
        XCTAssertNil(
            QueriesPeriod(range: .day, zoom: QueryHistoryZoom(span: .hour, start: hour)).zoom(into: hour, now: now))
    }

    func testABarThatHasNotStartedHasNothingToShow() {
        let zoomedToday = QueriesPeriod(range: .week, zoom: QueryHistoryZoom(span: .day, start: today))
        XCTAssertNil(zoomedToday.zoom(into: today + 13 * 3600, now: now))
    }

    /// Five-minute buckets come from single lookups, which are kept for 7 days.
    func testAnHourOlderThanTheSingleLookupsHasNoFiveMinuteView() {
        let oldDay = today - 10 * day
        let zoomedOldDay = QueriesPeriod(range: .month, zoom: QueryHistoryZoom(span: .day, start: oldDay))
        XCTAssertNil(zoomedOldDay.zoom(into: oldDay + 9 * 3600, now: now))

        let lastKeptHour = today + 13 * 3600 - 7 * day
        let zoomedWeekAgo = QueriesPeriod(range: .month, zoom: QueryHistoryZoom(span: .day, start: today - 7 * day))
        XCTAssertEqual(
            zoomedWeekAgo.zoom(into: lastKeptHour, now: now), QueryHistoryZoom(span: .hour, start: lastKeptHour))
        XCTAssertNil(zoomedWeekAgo.zoom(into: lastKeptHour - 3600, now: now))
    }

    func testTheRequestAndTheBucketsFollowTheZoom() {
        let unzoomed = QueriesPeriod(range: .month)
        XCTAssertEqual(unzoomed.request, .last(.month))
        XCTAssertEqual(unzoomed.bucketRange, .month)

        let zoomedDay = QueryHistoryZoom(span: .day, start: today)
        XCTAssertEqual(QueriesPeriod(range: .month, zoom: zoomedDay).request, .zoomed(zoomedDay))
        XCTAssertEqual(QueriesPeriod(range: .month, zoom: zoomedDay).bucketRange, .day)

        let zoomedHour = QueryHistoryZoom(span: .hour, start: today)
        XCTAssertEqual(QueriesPeriod(range: .day, zoom: zoomedHour).bucketRange, .hour)
    }

    func testTextsNameTheLastRangeOrTheZoomedBucket() {
        XCTAssertEqual(QueriesPeriod(range: .day).phrase, "in the last 24 hours")
        XCTAssertEqual(QueriesPeriod(range: .day, zoom: QueryHistoryZoom(span: .day, start: today)).phrase, "on this day")
        XCTAssertEqual(
            QueriesPeriod(range: .day, zoom: QueryHistoryZoom(span: .hour, start: today)).phrase, "in this hour")
    }
}

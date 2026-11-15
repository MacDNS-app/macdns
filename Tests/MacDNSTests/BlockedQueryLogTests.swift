// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import MacDNSAgent

/// Records what the sampled BLOCKED log would write, against a manual clock.
private final class LineRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [BlockedQueryLog.Line] = []
    private var clock: TimeInterval = 0

    var lines: [BlockedQueryLog.Line] { lock.withLock { recorded } }
    var now: TimeInterval { lock.withLock { clock } }

    func advance(to time: TimeInterval) { lock.withLock { clock = time } }
    func write(_ line: BlockedQueryLog.Line) { lock.withLock { recorded.append(line) } }
}

final class BlockedQueryLogTests: XCTestCase {
    func testLogSamplerCapsAWindowAndReportsSuppression() {
        var sampler = BlockedLogSampler(limitPerWindow: 3, window: 1)

        XCTAssertEqual(sampler.admit(now: 10), .init(emit: true, suppressed: 0))
        XCTAssertEqual(sampler.admit(now: 10.1), .init(emit: true, suppressed: 0))
        XCTAssertEqual(sampler.admit(now: 10.2), .init(emit: true, suppressed: 0))
        XCTAssertEqual(sampler.admit(now: 10.3), .init(emit: false, suppressed: 0))
        XCTAssertEqual(sampler.admit(now: 10.4), .init(emit: false, suppressed: 0))
        XCTAssertEqual(
            sampler.admit(now: 11.5), .init(emit: true, suppressed: 2),
            "a new window must report what the budget suppressed")
        XCTAssertEqual(sampler.admit(now: 11.6), .init(emit: true, suppressed: 0))
    }

    func testBlockedLinesFollowTheBudgetAndReportWhatWasSuppressed() {
        let recorder = LineRecorder()
        let log = BlockedQueryLog(
            sampler: BlockedLogSampler(limitPerWindow: 2, window: 1),
            uptime: { recorder.now },
            write: { recorder.write($0) }
        )

        recorder.advance(to: 10)
        log.record(domain: "a.example", rule: "example", category: "ads_tracking")
        log.record(domain: "b.example", rule: "example", category: "ads_tracking")
        log.record(domain: "c.example", rule: "example", category: "ads_tracking")
        recorder.advance(to: 11.5)
        log.record(domain: "d.example", rule: "d.example", category: "malware_security")

        XCTAssertEqual(
            recorder.lines,
            [
                .blocked(domain: "a.example", rule: "example", category: "ads_tracking"),
                .blocked(domain: "b.example", rule: "example", category: "ads_tracking"),
                .suppressed(1),
                .blocked(domain: "d.example", rule: "d.example", category: "malware_security"),
            ]
        )
    }
}

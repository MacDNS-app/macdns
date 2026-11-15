// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Emission budget for the per-block INFO line.
///
/// Normal blocked traffic stays fully logged. A flood is capped per window and
/// the loss is reported, so the log cannot become the amplifier it was when
/// every blocked query wrote a line from the resolver callback.
struct BlockedLogSampler {
    struct Outcome: Equatable {
        /// Whether this observation's own BLOCKED line should be written.
        let emit: Bool
        /// Lines suppressed since the previous summary. Non-zero means the
        /// caller must report the loss.
        let suppressed: Int
    }

    private let limitPerWindow: Int
    private let window: TimeInterval
    private var windowStart: TimeInterval?
    private var emitted = 0
    private var suppressed = 0

    init(limitPerWindow: Int = 50, window: TimeInterval = 1) {
        self.limitPerWindow = limitPerWindow
        self.window = window
    }

    mutating func admit(now: TimeInterval) -> Outcome {
        guard let start = windowStart, now - start < window else {
            let carried = suppressed
            windowStart = now
            emitted = 1
            suppressed = 0
            return Outcome(emit: true, suppressed: carried)
        }
        if emitted < limitPerWindow {
            emitted += 1
            return Outcome(emit: true, suppressed: 0)
        }
        suppressed += 1
        return Outcome(emit: false, suppressed: 0)
    }
}

/// The sampled BLOCKED line operators read in `log show`, fed by the
/// resolver's blocked callback. Blocked counts live in the lookup history, so
/// this only logs. The callback arrives on the resolver's telemetry thread and
/// must never block it.
final class BlockedQueryLog: @unchecked Sendable {
    enum Line: Equatable {
        case blocked(domain: String, rule: String, category: String)
        case suppressed(Int)
    }

    static let shared = BlockedQueryLog()

    private let lock = NSLock()
    private var sampler: BlockedLogSampler
    private let uptime: () -> TimeInterval
    private let write: (Line) -> Void

    init(
        sampler: BlockedLogSampler = BlockedLogSampler(),
        uptime: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
        write: @escaping (Line) -> Void = BlockedQueryLog.writeToAgentLog
    ) {
        self.sampler = sampler
        self.uptime = uptime
        self.write = write
    }

    func record(domain: String, rule: String, category: String) {
        let outcome = lock.withLock { sampler.admit(now: uptime()) }
        if outcome.suppressed > 0 {
            write(.suppressed(outcome.suppressed))
        }
        if outcome.emit {
            write(.blocked(domain: domain, rule: rule, category: category))
        }
    }

    private static func writeToAgentLog(_ line: Line) {
        switch line {
        case .blocked(let domain, let rule, let category):
            AgentLogger.shared.dnsBlocked(domain: domain, rule: rule, category: category)
        case .suppressed(let count):
            AgentLogger.shared.info(
                "blocked telemetry: \(count) BLOCKED line(s) suppressed by the log budget")
        }
    }
}

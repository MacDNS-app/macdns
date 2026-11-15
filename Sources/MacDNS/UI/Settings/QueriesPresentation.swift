// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import SwiftUI

/// How one lookup ended, with the same rules as the history `result` filter.
enum QueryOutcome: CaseIterable, Equatable {
    case answered, blocked, notFound, failed

    init(route: String, rcode: Int) {
        switch (route, rcode) {
        case ("blocked", _): self = .blocked
        case ("failed", _), ("invalid", _): self = .failed
        case (_, 0): self = .answered
        case (_, 3): self = .notFound
        default: self = .failed
        }
    }

    /// The result most of a host's lookups had. Ties go to the earlier case.
    static func dominant(in host: QueryHistoryTopHosts.Host) -> QueryOutcome {
        let answered = max(0, host.count - host.blocked - host.notFound - host.failed)
        let counts: [(QueryOutcome, Int)] = [
            (.answered, answered), (.blocked, host.blocked), (.notFound, host.notFound), (.failed, host.failed),
        ]
        return counts.reduce(counts[0]) { $1.1 > $0.1 ? $1 : $0 }.0
    }

    var title: String {
        switch self {
        case .answered: return "Answered"
        case .blocked: return "Blocked"
        case .notFound: return "Not Found"
        case .failed: return "Failed"
        }
    }

    var color: Color {
        switch self {
        case .answered: return .statusHealthy
        case .blocked: return .statusCritical
        case .notFound: return .statusCaution
        case .failed: return .historyFailed
        }
    }

    var resultFilter: QueryHistoryResultFilter {
        switch self {
        case .answered: return .answered
        case .blocked: return .blocked
        case .notFound: return .notFound
        case .failed: return .failed
        }
    }
}

extension QueryHistoryResultFilter {
    var title: String {
        switch self {
        case .all: return "All Results"
        case .answered: return "Answered"
        case .blocked: return "Blocked"
        case .notFound: return "Not Found"
        case .failed: return "Failed"
        }
    }
}

extension QueryHistoryRange {
    var shortTitle: String {
        switch self {
        case .hour: return "1H"
        case .day: return "24H"
        case .week: return "7D"
        case .month: return "30D"
        }
    }

    var periodName: String {
        switch self {
        case .hour: return "hour"
        case .day: return "24 hours"
        case .week: return "7 days"
        case .month: return "30 days"
        }
    }
}

extension QueriesPeriod {
    /// How a sentence names the period, as in "Lookups in the last 24 hours".
    var phrase: String {
        switch zoom?.span {
        case nil: return "in the last \(range.periodName)"
        case .day: return "on this day"
        case .hour: return "in this hour"
        }
    }

    /// A figure tile's caption when there is no earlier period to compare with.
    var caption: String {
        switch zoom?.span {
        case nil: return "last \(range.periodName)"
        case .day: return "this day"
        case .hour: return "this hour"
        }
    }
}

enum QueriesFormat {
    /// Where an answer came from, in words for people who don't know DNS.
    static func answeredBy(route: String, provider: String) -> String {
        switch route {
        case "cache": return "Cache"
        case "provider": return provider.isEmpty ? "Provider" : provider
        case "stale": return "Expired Copy"
        case "blocked": return "Blocklist"
        case "override": return "Local Record"
        case "forward": return "Forward Zone"
        case "captive": return "Wi-Fi Login"
        case "local": return "Built-in"
        case "failed": return "MacDNS"
        case "invalid": return "Rejected"
        default: return route
        }
    }

    /// The three biggest sources of a host's answers, providers by name, with shares.
    static func answerSources(routes: [String: Int], providers: [QueryHistoryHostDetail.ProviderCount]) -> String {
        let total = routes.values.reduce(0, +)
        var parts: [(name: String, count: Int)] = []
        for (route, count) in routes where count > 0 {
            if route == "provider", !providers.isEmpty {
                parts += providers.map { ($0.name, $0.count) }
            } else {
                parts.append((answeredBy(route: route, provider: ""), count))
            }
        }
        parts.sort { $0.count != $1.count ? $0.count > $1.count : $0.name < $1.name }
        return parts.prefix(3).map { "\($0.name) \(share($0.count, of: total))" }.joined(separator: " · ")
    }

    static func recordType(_ qtype: Int) -> String {
        let names = [
            1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
            64: "SVCB", 65: "HTTPS", 255: "ANY",
        ]
        return names[qtype] ?? "TYPE\(qtype)"
    }

    /// Short enough for a figure tile. The page header names the period.
    static func periodChange(total: Int, previous: Int?, period: QueriesPeriod) -> String {
        guard let previous else { return period.caption }
        guard previous > 0 else { return "None in previous" }
        let change = Int((Double(total - previous) / Double(previous) * 100).rounded())
        if change == 0 { return "Same as previous" }
        return "\(change > 0 ? "↑" : "↓") \(abs(change))% vs previous"
    }

    static func share(_ part: Int, of total: Int) -> String {
        guard total > 0, part > 0 else { return "0%" }
        let percent = Double(part) / Double(total) * 100
        return percent < 1 ? "<1%" : "\(Int(percent.rounded()))%"
    }

    /// An average response time, in seconds from one second up.
    static func milliseconds(_ value: Double) -> String {
        if value < 10 { return String(format: "%.1f ms", value) }
        let rounded = Int(value.rounded())
        return rounded < 1000 ? "\(rounded) ms" : String(format: "%.1f s", value / 1000)
    }

    /// One lookup's time for the Log, whose column is in milliseconds. From one
    /// second up it switches to seconds and says so, and it never groups digits.
    static func logLatency(_ value: Double) -> String {
        if value < 1 { return "<1" }
        let rounded = Int(value.rounded())
        return rounded < 1000 ? "\(rounded)" : String(format: "%.1f s", value / 1000)
    }

    /// The zoomed bar, as the page header names it.
    static func zoomTitle(_ zoom: QueryHistoryZoom) -> String {
        let start = time(zoom.start)
        switch zoom.span {
        case .day:
            return start.formatted(.dateTime.weekday(.abbreviated).month(.abbreviated).day())
        case .hour:
            let end = time(zoom.start + 3600)
            let day = start.formatted(.dateTime.month(.abbreviated).day())
            return
                "\(day), \(start.formatted(date: .omitted, time: .shortened))–\(end.formatted(date: .omitted, time: .shortened))"
        }
    }

    static func time(_ unixSeconds: Int) -> Date {
        Date(timeIntervalSince1970: TimeInterval(unixSeconds))
    }

    /// Popular entries are refreshed about once per answer lifetime, and 5
    /// minutes is a typical one. A rough guide, not a measurement.
    static func popularPrefetchImpact(count: Int) -> String {
        guard count > 0 else { return "Off: only answers used in the last few hours are renewed." }
        let perSecond = String(format: "%.1f", Double(count) / 300)
        return "Adds about \(perSecond) lookups per second to your providers while this Mac is awake."
    }
}

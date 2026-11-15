// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import os.log

class AgentLogger {
    static let shared = AgentLogger()

    private let logger = os.Logger(subsystem: "app.macdns.agent", category: "general")
    private let dnsLogger = os.Logger(subsystem: "app.macdns.agent", category: "dns")

    func debug(_ message: String) {
        logger.debug("\(message, privacy: .public)")
    }

    func info(_ message: String) {
        logger.info("\(message, privacy: .public)")
    }

    /// Persisted by the unified log, unlike `info`. Use it for state transitions
    /// that must survive in `log show`, such as license changes.
    func notice(_ message: String) {
        logger.notice("\(message, privacy: .public)")
    }

    func error(_ message: String) {
        logger.error("\(message, privacy: .public)")
    }

    func warning(_ message: String) {
        logger.warning("\(message, privacy: .public)")
    }

    // MARK: - DNS Channel
    //
    // Every field is `privacy: .public`, including the queried name. That is a
    // product decision. A redacted `domain` leaves a line like
    // `SERVFAIL: domain=<private> qtype=A` that identifies no lookup, and macOS
    // offers no practical way to read it back. `log config --mode` dropped the
    // `private_data` key years ago, and the only remaining route is a
    // system-wide `com.apple.system.logging` profile that unredacts every
    // process on the machine. `.private` here means the data is gone.
    //
    // `Logger` redacts interpolated `String` values by default, so every field
    // needs the annotation or it prints as <private>.
    // `AgentLoggerVisibilityTests` pins this.
    //
    // The exposure is bounded elsewhere. QUERY and REPLY fire only when the
    // user turns on query logging (`log_queries` / `log_replies`, both off by
    // default). BLOCKED and SERVFAIL are not gated. If that becomes
    // unacceptable, gate them on the same toggle instead of redacting the
    // field, which makes the line useless without making it private in any
    // way the user can undo.
    //
    // These take the fields apart instead of a preformatted `String` because
    // os_log applies privacy per interpolation. Use single-line literals only.
    // The invariant lint's region scanner rejects multi-line string literals
    // in any file it reads, including inside comments.

    func dnsQuery(domain: String, qtype: String) {
        dnsLogger.info(
            "QUERY: domain=\(domain, privacy: .public) qtype=\(qtype, privacy: .public)")
    }

    func dnsReply(
        domain: String,
        qtype: String,
        rcode: String,
        answers: UInt32,
        provider: String,
        data: String
    ) {
        dnsLogger.info(
            "REPLY: domain=\(domain, privacy: .public) qtype=\(qtype, privacy: .public) rcode=\(rcode, privacy: .public) answers=\(answers, privacy: .public) provider=\(provider, privacy: .public) data=\(data, privacy: .public)"
        )
    }

    func dnsBlocked(domain: String, rule: String, category: String) {
        dnsLogger.info(
            "BLOCKED: domain=\(domain, privacy: .public) rule=\(rule, privacy: .public) category=\(category, privacy: .public)"
        )
    }

    func dnsServfail(domain: String, qtype: String, reason: String) {
        dnsLogger.info(
            "SERVFAIL: domain=\(domain, privacy: .public) qtype=\(qtype, privacy: .public) reason=\(reason, privacy: .public)"
        )
    }
}

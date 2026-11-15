// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

struct ProxyProbeFailure: Error, Equatable {
    enum Stage: String {
        case nonce, socket, connect, send, readLength, readBody, response, authentication
    }

    enum Reason: Equatable {
        case unavailable
        case systemError(Int32)
        case timeout
        case connectionClosed
        case shortWrite
        case invalidResponseLength
        case invalidResponse
        case authenticationMismatch

        var summary: String {
            switch self {
            case .unavailable: return "unavailable"
            case .systemError(let code): return "systemError errno=\(code)"
            case .timeout: return "timeout"
            case .connectionClosed: return "connectionClosed"
            case .shortWrite: return "shortWrite"
            case .invalidResponseLength: return "invalidResponseLength"
            case .invalidResponse: return "invalidResponse"
            case .authenticationMismatch: return "authenticationMismatch"
            }
        }
    }

    let stage: Stage
    let reason: Reason

    var summary: String { "stage=\(stage.rawValue) reason=\(reason.summary)" }

    /// The resolver port answered and the answer failed validation.
    var isRejectedAnswer: Bool {
        switch reason {
        case .invalidResponseLength, .invalidResponse, .authenticationMismatch:
            return true
        case .unavailable, .systemError, .timeout, .connectionClosed, .shortWrite:
            return false
        }
    }
}

/// Contains only diagnostic metadata, never session or challenge material.
struct ProxyProbeResult {
    let outcome: ProxyControlChallengeOutcome
    let elapsedMilliseconds: UInt64

    var summary: String {
        let status: String
        switch outcome {
        case .ready: status = "ready"
        case .notReady: status = "notReady"
        case .failed(let failure): status = "failed \(failure.summary)"
        }
        return "\(status) elapsed_ms=\(elapsedMilliseconds)"
    }
}

struct ProxyProbeReport {
    let udp: ProxyProbeResult
    let tcp: ProxyProbeResult

    var summary: String { "udp=\(udp.summary) tcp=\(tcp.summary)" }

    var containsRejectedAnswer: Bool {
        [udp, tcp].contains { result in
            if case .failed(let failure) = result.outcome { return failure.isRejectedAnswer }
            return false
        }
    }

    /// A transport signed `ready = 0`.
    var containsNotReadyAnswer: Bool {
        udp.outcome == .notReady || tcp.outcome == .notReady
    }
}

struct ProxyProbeDiagnostics {
    private var previousUDP: ProxyControlChallengeOutcome?
    private var previousTCP: ProxyControlChallengeOutcome?

    /// Elapsed time is excluded so a persistent failure produces one log entry.
    mutating func record(_ report: ProxyProbeReport?) -> Bool {
        let udp = report?.udp.outcome
        let tcp = report?.tcp.outcome
        let changed = previousUDP != udp || previousTCP != tcp
        previousUDP = udp
        previousTCP = tcp
        return changed
    }
}

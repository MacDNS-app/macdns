// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Inputs to the interception decision, gathered off the DNS hot path.
struct DNSProxyHealthInputs {
    let sessionInstalled: Bool
    let udpVerified: Bool
    let tcpVerified: Bool
    let readyBit: Bool
    let dnsDestinationsPresent: Bool
}

extension DNSProxyHealthInputs {
    /// Maps probe outcomes onto the decision inputs. A transport that never
    /// authenticated proves nothing about readiness, and readiness requires both
    /// transports to have signed `ready = 1`.
    init(
        sessionInstalled: Bool, udp: ProxyControlChallengeOutcome,
        tcp: ProxyControlChallengeOutcome, dnsDestinationsPresent: Bool
    ) {
        self.init(
            sessionInstalled: sessionInstalled,
            udpVerified: udp.isAuthenticated,
            tcpVerified: tcp.isAuthenticated,
            readyBit: udp == .ready && tcp == .ready,
            dnsDestinationsPresent: dnsDestinationsPresent)
    }
}

enum DNSProxyHealthDecision: Equatable {
    case intercept(sessionID: String)
    case bypass(ProxyInterceptionReason)

    var shouldBypass: Bool {
        if case .bypass = self { return true }
        return false
    }
}

/// Pure decision: interception requires an installed session, a ready resolver,
/// both transports proven, and a non-empty observed DNS destination set.
enum DNSProxyHealthEvaluator {
    static func decide(_ inputs: DNSProxyHealthInputs, sessionID: String) -> DNSProxyHealthDecision {
        guard inputs.sessionInstalled else { return .bypass(.sessionUnavailable) }
        // Transports first: a transport that never answered cannot report on the
        // resolver, so blaming readiness would hide the real root cause.
        guard inputs.udpVerified, inputs.tcpVerified else { return .bypass(.probeFailed) }
        guard inputs.readyBit else { return .bypass(.resolverNotReady) }
        guard inputs.dnsDestinationsPresent else { return .bypass(.dnsDestinationsUnavailable) }
        return .intercept(sessionID: sessionID)
    }
}

/// A loaded resolver can miss a challenge, so one unanswered probe round while
/// intercepting is repeated before it ends interception. An answer that failed
/// validation and an authenticated `ready = 0` are never repeated.
struct DNSProxyProbeRetryPolicy {
    private var unansweredRounds = 0

    /// Whether the round is to run again instead of applying `decision`.
    mutating func shouldRepeat(
        _ decision: DNSProxyHealthDecision, probes: ProxyProbeReport, intercepting: Bool
    ) -> Bool {
        guard
            intercepting, decision == .bypass(.probeFailed),
            !probes.containsRejectedAnswer, !probes.containsNotReadyAnswer,
            unansweredRounds == 0
        else {
            unansweredRounds = 0
            return false
        }
        unansweredRounds = 1
        return true
    }
}

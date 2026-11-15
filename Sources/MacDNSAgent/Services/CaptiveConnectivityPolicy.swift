// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

enum CaptiveHTTPProbeEvidence: String, Equatable {
    case normal
    case captive
    case inconclusive
    case error
}

enum DirectDoHProbeEvidence: String, Equatable {
    case notRun
    case success
    case failure
}

/// Whether the resolvers that compatibility forwarding would use answered a
/// fresh query. Probed only when compatibility is the candidate outcome.
enum NetworkDNSProbeEvidence: String, Equatable {
    case notRun
    case answered
    case unanswered
}

enum ResolverProbeAvailability: Equatable {
    case available(warmingUp: Bool)
    case unavailable
}

enum CaptiveConnectivityOutcome: Equatable, CustomStringConvertible {
    case healthy
    case captive
    case compatibilityRequired(portalCleared: Bool)

    var status: CaptivePortalStatus {
        switch self {
        case .healthy:
            return .normal
        case .captive:
            return .captive
        case .compatibilityRequired:
            return .dnsIntercepted
        }
    }

    var description: String {
        switch self {
        case .healthy:
            return "healthy"
        case .captive:
            return "captive"
        case .compatibilityRequired(let portalCleared):
            return "compatibility-required(portal-cleared=\(portalCleared))"
        }
    }
}

enum CaptiveConnectivityDecision: Equatable {
    case candidate(CaptiveConnectivityOutcome)
    case retry
    case prepareResolver
}

enum CaptiveConnectivityConfirmationUpdate: Equatable {
    case pending
    case confirmed(CaptiveConnectivityOutcome, changed: Bool)
    case retry
    case prepareResolver
}

enum CaptiveConnectivityPolicy {
    static func decide(
        http: CaptiveHTTPProbeEvidence,
        directDoH: DirectDoHProbeEvidence,
        networkDNS: NetworkDNSProbeEvidence,
        resolver: ResolverProbeAvailability
    ) -> CaptiveConnectivityDecision {
        if http == .captive {
            return .candidate(.captive)
        }

        guard case .available(let warmingUp) = resolver else {
            return .prepareResolver
        }

        let candidate: CaptiveConnectivityOutcome
        switch (http, directDoH) {
        case (.normal, .success):
            return .candidate(.healthy)
        case (.normal, .failure) where !warmingUp:
            candidate = .compatibilityRequired(portalCleared: true)
        case (.inconclusive, .failure) where !warmingUp,
            (.error, .failure) where !warmingUp:
            candidate = .compatibilityRequired(portalCleared: false)
        default:
            return .retry
        }

        // Forwarding to resolvers that do not answer turns a WAN outage into
        // SERVFAIL for names the public cache could still serve stale.
        guard networkDNS == .answered else {
            return .retry
        }
        return .candidate(candidate)
    }

    /// True when the evidence so far selects compatibility, so the network's
    /// resolvers must be probed before that candidate can count.
    static func needsNetworkDNSProbe(
        http: CaptiveHTTPProbeEvidence,
        directDoH: DirectDoHProbeEvidence,
        resolver: ResolverProbeAvailability
    ) -> Bool {
        guard
            case .candidate(.compatibilityRequired) = decide(
                http: http,
                directDoH: directDoH,
                networkDNS: .answered,
                resolver: resolver
            )
        else {
            return false
        }
        return true
    }
}

struct CaptiveConnectivityConfirmationTracker {
    let confirmationsRequired: Int
    private(set) var confirmedOutcome: CaptiveConnectivityOutcome?
    private var candidate: CaptiveConnectivityOutcome?
    private var candidateCount = 0

    init(confirmationsRequired: Int) {
        precondition(confirmationsRequired > 0)
        self.confirmationsRequired = confirmationsRequired
    }

    mutating func consume(
        _ decision: CaptiveConnectivityDecision
    ) -> CaptiveConnectivityConfirmationUpdate {
        switch decision {
        case .retry:
            resetCandidate()
            return .retry
        case .prepareResolver:
            resetCandidate()
            return .prepareResolver
        case .candidate(let outcome):
            if candidate == outcome {
                candidateCount += 1
            } else {
                candidate = outcome
                candidateCount = 1
            }

            guard candidateCount >= confirmationsRequired else {
                return .pending
            }

            let changed = confirmedOutcome != outcome
            confirmedOutcome = outcome
            resetCandidate()
            return .confirmed(outcome, changed: changed)
        }
    }

    mutating func resetCandidate() {
        candidate = nil
        candidateCount = 0
    }

    mutating func invalidateNetwork() {
        resetCandidate()
        confirmedOutcome = nil
    }
}

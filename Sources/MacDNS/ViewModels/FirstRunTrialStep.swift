// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import os.log

enum FirstRunTrialOutcome: Equatable {
    case unsupportedLocation
    case agentUnavailable
    case licenseUnknown
    case licensed(blocksEnable: Bool)

    /// Turn On continues to `enableDNS()` unless the license is ended or the
    /// app runs outside /Applications.
    var continuesToEnable: Bool {
        switch self {
        case .unsupportedLocation:
            return false
        case .agentUnavailable, .licenseUnknown:
            return true
        case .licensed(let blocksEnable):
            return !blocksEnable
        }
    }
}

/// Installs the agent and registers the trial before the first Enable.
/// A failed install or an unreachable license server never stops Enable:
/// the agent retries the trial in `startResolver`.
struct FirstRunTrialStep {
    private static let logger = Logger(subsystem: "app.macdns", category: "FirstRunTrialStep")

    let isSupportedLocation: Bool
    let agentInstalled: Bool
    let installAgent: () async throws -> Void
    let licenseInfo: () async -> LicenseInfo?
    /// Requests the trial. Returns the agent's answer, or nil when the caller
    /// does not wait for it (close and quit) or the request failed.
    let requestTrial: () async -> LicenseInfo?

    func run() async -> FirstRunTrialOutcome {
        guard isSupportedLocation else { return .unsupportedLocation }

        if !agentInstalled {
            do {
                try await installAgent()
            } catch {
                Self.logger.warning("First run agent install failed: \(error.localizedDescription, privacy: .public)")
                return .agentUnavailable
            }
        }

        guard var info = await licenseInfo() else { return .licenseUnknown }

        if info.status == .unknown {
            guard let trial = await requestTrial() else { return .licenseUnknown }
            info = trial
        }

        return .licensed(
            blocksEnable: LicenseEnableGatePolicy.blocksEnable(info, agentInstalled: true) || Self.trialRanOut(info))
    }

    /// Periodic validation runs only while protection is on, so a trial that
    /// ended while it was off is still stored as `.trial`. Its expiry date
    /// settles it without calling Keygen with protection off.
    private static func trialRanOut(_ info: LicenseInfo) -> Bool {
        guard info.status == .trial, !info.isServiceAllowed, let expiresAt = info.expiresAt else { return false }
        return Date() >= expiresAt
    }
}

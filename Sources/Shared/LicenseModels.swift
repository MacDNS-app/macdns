// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

// MARK: - License Status

public enum LicenseStatus: String, Codable, Sendable {
    case trial  // Active trial period
    case trialExpired  // Trial ended, no license
    case valid  // Valid paid license
    case expired  // Paid license expired
    case invalid  // License key invalid/revoked
    case unknown  // Initial state before first check
}

// MARK: - Validation Receipt

/// A `validate-key` answer as Keygen signed it: the body and the two signed
/// headers that cannot be recomputed from it. It is stored in `license.json`
/// so an offline start can prove the last validation. The fields next to it
/// prove nothing, because the file is user-writable.
public struct LicenseValidationReceipt: Codable, Equatable, Sendable {
    public let body: Data
    public let date: String
    public let signature: String

    public init(body: Data, date: String, signature: String) {
        self.body = body
        self.date = date
        self.signature = signature
    }
}

// MARK: - License State (Persisted)

/// Persisted in license.json.
public struct LicenseState: Codable, Sendable {
    public var licenseKey: String?
    public var licenseId: String?  // keygen.sh license UUID
    public var machineId: String?  // keygen.sh machine UUID
    public var status: LicenseStatus
    public var expiresAt: Date?  // Source of truth from API (both trial and paid)
    public var lastValidatedAt: Date?
    public var deactivationPending: Bool?
    public var machineReactivationPending: Bool?
    public var validationReceipt: LicenseValidationReceipt?

    public init(
        licenseKey: String? = nil,
        licenseId: String? = nil,
        machineId: String? = nil,
        status: LicenseStatus = .unknown,
        expiresAt: Date? = nil,
        lastValidatedAt: Date? = nil,
        deactivationPending: Bool? = false,
        machineReactivationPending: Bool? = false,
        validationReceipt: LicenseValidationReceipt? = nil
    ) {
        self.licenseKey = licenseKey
        self.licenseId = licenseId
        self.machineId = machineId
        self.status = status
        self.expiresAt = expiresAt
        self.lastValidatedAt = lastValidatedAt
        self.deactivationPending = deactivationPending
        self.machineReactivationPending = machineReactivationPending
        self.validationReceipt = validationReceipt
    }

    /// Whether services may run: an unexpired trial or paid license with no
    /// machine reactivation pending.
    public var isActive: Bool {
        guard machineReactivationPending != true else { return false }
        switch status {
        case .trial, .valid:
            if let expires = expiresAt {
                return Date() < expires
            }
            return true  // No expiration = perpetual
        case .trialExpired, .expired, .invalid, .unknown:
            return false
        }
    }

    public var trialDaysRemaining: Int? {
        guard status == .trial, let expires = expiresAt else { return nil }
        let remaining = Calendar.current.dateComponents([.day], from: Date(), to: expires).day ?? 0
        return max(0, remaining)
    }

    public var trialHoursRemaining: Int? {
        guard status == .trial, let expires = expiresAt else { return nil }
        let remaining = Calendar.current.dateComponents([.hour], from: Date(), to: expires).hour ?? 0
        return max(0, remaining)
    }

    /// Decided by the API's `expiresAt` alone. `status` is not consulted.
    public var isTrialExpired: Bool {
        guard let expires = expiresAt else {
            return false
        }
        return Date() >= expires
    }
}

// MARK: - License Info (XPC Transfer)

public struct LicenseInfo: Codable, Sendable {
    public let status: LicenseStatus
    public let statusDescription: String
    public let expiresAt: Date?
    public let trialDaysRemaining: Int?
    public let trialHoursRemaining: Int?
    public let licenseKey: String?
    public let isServiceAllowed: Bool
    /// Why service is blocked when the status alone does not explain it, such
    /// as an unreadable license file or a clock behind server time.
    public let blockReason: String?

    public init(from state: LicenseState, isServiceAllowed: Bool, blockReason: String? = nil) {
        self.status = state.status
        self.expiresAt = state.expiresAt
        self.trialDaysRemaining = state.trialDaysRemaining
        self.trialHoursRemaining = state.trialHoursRemaining
        self.licenseKey = state.licenseKey
        self.isServiceAllowed = isServiceAllowed
        self.blockReason = blockReason

        switch state.status {
        case .trial:
            if let days = state.trialDaysRemaining {
                if days == 0 {
                    if let hours = state.trialHoursRemaining {
                        self.statusDescription = hours == 1 ? "Trial: 1 hour left" : "Trial: \(hours) hours left"
                    } else {
                        self.statusDescription = "Trial: expiring soon"
                    }
                } else {
                    self.statusDescription = days == 1 ? "Trial: 1 day left" : "Trial: \(days) days left"
                }
            } else {
                self.statusDescription = "Trial active"
            }
        case .trialExpired:
            self.statusDescription = "Trial expired"
        case .valid:
            if let expires = state.expiresAt {
                let now = Date()
                if now >= expires {
                    self.statusDescription = "License expired"
                } else {
                    let remaining = expires.timeIntervalSince(now)
                    let days = Int(remaining / (24 * 60 * 60))
                    let hours = Int(remaining / (60 * 60))

                    if days > 0 {
                        self.statusDescription = days == 1 ? "Licensed: 1 day left" : "Licensed: \(days) days left"
                    } else if hours > 0 {
                        self.statusDescription = hours == 1 ? "Licensed: 1 hour left" : "Licensed: \(hours) hours left"
                    } else {
                        self.statusDescription = "Licensed: expiring soon"
                    }
                }
            } else {
                self.statusDescription = "Licensed"
            }
        case .expired:
            self.statusDescription = "License expired"
        case .invalid:
            self.statusDescription = "Invalid license"
        case .unknown:
            self.statusDescription = "Checking license..."
        }
    }
}

// MARK: - License Activation Result

public enum LicenseActivationResult: Codable, Sendable {
    case success(message: String)
    case error(message: String)
    case alreadyActivated
    case machineLimit(limit: Int)
    case invalidKey
    case networkError(message: String)

    private enum CodingKeys: String, CodingKey {
        case type, message, limit
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)

        switch type {
        case "success":
            let message = try container.decode(String.self, forKey: .message)
            self = .success(message: message)
        case "error":
            let message = try container.decode(String.self, forKey: .message)
            self = .error(message: message)
        case "alreadyActivated":
            self = .alreadyActivated
        case "machineLimit":
            let limit = try container.decode(Int.self, forKey: .limit)
            self = .machineLimit(limit: limit)
        case "invalidKey":
            self = .invalidKey
        case "networkError":
            let message = try container.decode(String.self, forKey: .message)
            self = .networkError(message: message)
        default:
            self = .error(message: "Unknown result type")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        switch self {
        case .success(let message):
            try container.encode("success", forKey: .type)
            try container.encode(message, forKey: .message)
        case .error(let message):
            try container.encode("error", forKey: .type)
            try container.encode(message, forKey: .message)
        case .alreadyActivated:
            try container.encode("alreadyActivated", forKey: .type)
        case .machineLimit(let limit):
            try container.encode("machineLimit", forKey: .type)
            try container.encode(limit, forKey: .limit)
        case .invalidKey:
            try container.encode("invalidKey", forKey: .type)
        case .networkError(let message):
            try container.encode("networkError", forKey: .type)
            try container.encode(message, forKey: .message)
        }
    }
}

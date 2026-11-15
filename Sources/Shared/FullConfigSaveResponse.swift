// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

public struct FullConfigSaveResponse: Codable, Equatable, Sendable {

    public enum Status: String, Codable, Sendable {
        /// Disk and required runtime projections converged.
        case committed
        /// An identical request at the consumed revision was confirmed.
        case alreadyCommitted
        /// Compare-and-swap revision mismatch.
        case conflict
        /// Retryable: a lifecycle transition prevented the save.
        case lifecycleBusy
        /// Non-retryable failure.
        case rejected
    }

    public enum RejectionReason: String, Codable, Sendable {
        case invalidConfiguration
        case persistenceFailure
        case runtimeApplyFailure
        case revisionExhausted
    }

    public let status: Status
    /// The Agent's authoritative revision after the request. Present even on
    /// rollback, so a retry rebases onto the revision the transaction consumed.
    /// Absent when a persistence failure leaves the document unreadable.
    public let authoritativeRevision: ConfigRevision?
    public let rejectionReason: RejectionReason?

    public init(
        status: Status,
        authoritativeRevision: ConfigRevision? = nil,
        rejectionReason: RejectionReason? = nil
    ) {
        self.status = status
        self.authoritativeRevision = authoritativeRevision
        self.rejectionReason = rejectionReason
    }

    public var isPersisted: Bool {
        status == .committed || status == .alreadyCommitted
    }

    public func encoded() throws -> Data {
        try JSONEncoder().encode(self)
    }

    public static func decoded(from data: Data?) -> FullConfigSaveResponse? {
        guard let data else { return nil }
        return try? JSONDecoder().decode(FullConfigSaveResponse.self, from: data)
    }
}

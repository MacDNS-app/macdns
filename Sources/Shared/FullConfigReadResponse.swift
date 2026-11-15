// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// The Agent's answer to `readFullConfig`: the configuration, or the reason
/// `state.json` could not be served.
public struct FullConfigReadResponse: Codable, Equatable, Sendable {

    public enum Status: String, Codable, Sendable {
        case loaded
        /// `state.json` does not hold a valid configuration.
        case invalid
        /// `state.json` could not be read. A later read can succeed.
        case ioFailure
        /// `state.json` was written by a newer MacDNS.
        case incompatibleSchema
    }

    public let status: Status
    /// The configuration as a JSON object. Present only when `status` is `loaded`.
    public let configJSON: Data?

    public init(status: Status, configJSON: Data? = nil) {
        self.status = status
        self.configJSON = configJSON
    }

    /// `nil` when `config` is not JSON-serializable.
    public static func loaded(_ config: [String: Any]) -> FullConfigReadResponse? {
        guard
            FullConfigPayloadPolicy.isValidPayload(config),
            let configJSON = try? JSONSerialization.data(withJSONObject: config)
        else {
            return nil
        }
        return FullConfigReadResponse(status: .loaded, configJSON: configJSON)
    }

    public var config: [String: Any]? {
        guard status == .loaded, let configJSON else { return nil }
        return (try? JSONSerialization.jsonObject(with: configJSON))
            as? [String: Any]
    }

    public func encoded() throws -> Data {
        try JSONEncoder().encode(self)
    }

    public static func decoded(from data: Data?) -> FullConfigReadResponse? {
        guard let data else { return nil }
        return try? JSONDecoder().decode(FullConfigReadResponse.self, from: data)
    }
}

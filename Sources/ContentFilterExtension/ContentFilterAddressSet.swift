// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation

/// A set of IPv4 and IPv6 addresses compared by their parsed bytes, so the way
/// a literal or a flow destination is written cannot change the match.
struct ContentFilterAddressSet {
    private let addresses: Set<Data>

    init(literals: Set<String>) {
        addresses = Set(literals.compactMap(Self.addressBytes))
    }

    func contains(_ address: String) -> Bool {
        guard let bytes = Self.addressBytes(address) else { return false }
        return addresses.contains(bytes)
    }

    /// The 4 or 16 network-order bytes of an address literal, or `nil` when it
    /// is neither IPv4 nor IPv6. An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`)
    /// is the IPv4 address, so it yields the same 4 bytes.
    static func addressBytes(_ literal: String) -> Data? {
        var ipv4 = in_addr()
        if inet_pton(AF_INET, literal, &ipv4) == 1 {
            return withUnsafeBytes(of: ipv4) { Data($0) }
        }
        var ipv6 = in6_addr()
        if inet_pton(AF_INET6, literal, &ipv6) == 1 {
            let bytes = withUnsafeBytes(of: ipv6) { Data($0) }
            return bytes.starts(with: ipv4MappedPrefix) ? Data(bytes.suffix(4)) : bytes
        }
        return nil
    }

    private static let ipv4MappedPrefix = Data(repeating: 0, count: 10) + Data([0xff, 0xff])
}

// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation

public enum DNSResolverAddressParser {
    /// Resolvers the network hands us, filtered down to addresses that can
    /// actually answer a query. A hotspot advertising `0.0.0.0` or a multicast
    /// group as its DNS server would otherwise be configured as a captive
    /// forwarding target and black-hole every query until the forward timeout.
    /// With none left the agent falls back to bypass, which keeps portal
    /// sign-in working over the system resolver.
    public static func serverAddresses(globalDNS: [String: Any]?, dhcpOption6: Data?) -> [String] {
        var servers: [String] = []

        if let globalServers = globalDNS?["ServerAddresses"] as? [String] {
            for server in globalServers where isUsableForwardTarget(server) && !servers.contains(server) {
                servers.append(server)
            }
        }

        if let dhcpOption6 {
            for server in ipv4Addresses(fromDHCPOption6: dhcpOption6) where !servers.contains(server) {
                servers.append(server)
            }
        }

        return servers
    }

    public static func ipv4Addresses(fromDHCPOption6 option6: Data) -> [String] {
        var servers: [String] = []
        var offset = 0

        while offset + 4 <= option6.count {
            let ip = "\(option6[offset]).\(option6[offset + 1]).\(option6[offset + 2]).\(option6[offset + 3])"
            if isUsableForwardTarget(ip), !servers.contains(ip) {
                servers.append(ip)
            }
            offset += 4
        }

        return servers
    }

    /// The one forward-target address gate in the Swift tree, used by the
    /// network parser, the App's IP validation and the policy save path.
    /// Mirrors `zones::validate_forward_target` in the resolver.
    public static func isUsableForwardTarget(_ value: String) -> Bool {
        isIPAddress(value) && unusableForwardTargetKind(value) == nil
    }

    public static func isIPAddress(_ value: String) -> Bool {
        addressOctets(family: AF_INET, value: value) != nil
            || addressOctets(family: AF_INET6, value: value) != nil
    }

    /// Why the address can never answer a DNS query, or nil when it can.
    /// Loopback and host-owned addresses stay usable because a local resolver
    /// may legitimately listen on port 53.
    public static func unusableForwardTargetKind(_ value: String) -> String? {
        if let octets = addressOctets(family: AF_INET, value: value) {
            if octets.allSatisfy({ $0 == 0 }) { return "unspecified" }
            if octets.allSatisfy({ $0 == 255 }) { return "broadcast" }
            if (224...239).contains(octets[0]) { return "multicast" }
            return nil
        }
        if let octets = addressOctets(family: AF_INET6, value: value) {
            if octets.allSatisfy({ $0 == 0 }) { return "unspecified" }
            if octets[0] == 0xFF { return "multicast" }
            return nil
        }
        return nil
    }

    private static func addressOctets(family: Int32, value: String) -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: family == AF_INET ? 4 : 16)
        let parsed = value.withCString { text in
            buffer.withUnsafeMutableBytes { storage in
                inet_pton(family, text, storage.baseAddress)
            }
        }
        return parsed == 1 ? buffer : nil
    }
}

// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Network
import NetworkExtension
import os.log

@objc(ContentFilterProvider)
final class ContentFilterProvider: NEFilterDataProvider {
    private let logger = Logger(subsystem: "app.macdns.contentfilter", category: "filter")
    private let processValidator = ContentFilterProcessValidator()

    // MARK: - DoH/DoT Provider IP Lists

    static let dohIPv4: Set<String> = [
        // Google
        "8.8.8.8",
        "8.8.4.4",
        // Cloudflare (standard)
        "1.1.1.1",
        "1.0.0.1",
        // Cloudflare (malware blocking)
        "1.1.1.2",
        "1.0.0.2",
        // Cloudflare (family)
        "1.1.1.3",
        "1.0.0.3",
        // Quad9 (standard)
        "9.9.9.9",
        "149.112.112.112",
        // Quad9 (no blocking)
        "9.9.9.10",
        "149.112.112.10",
        // Quad9 (ECS)
        "9.9.9.11",
        "149.112.112.11",
        // OpenDNS
        "208.67.222.222",
        "208.67.220.220",
        // OpenDNS Family Shield
        "208.67.222.123",
        "208.67.220.123",
        // AdGuard (standard)
        "94.140.14.14",
        "94.140.15.15",
        // AdGuard (family)
        "94.140.14.15",
        "94.140.15.16",
        // AdGuard (non-filtering)
        "94.140.14.140",
        "94.140.14.141",
        // NextDNS
        "45.90.28.0",
        "45.90.30.0",
        // CleanBrowsing (security)
        "185.228.168.9",
        "185.228.169.9",
        // CleanBrowsing (adult)
        "185.228.168.10",
        "185.228.169.11",
        // CleanBrowsing (family)
        "185.228.168.168",
        "185.228.169.168",
        // Mullvad
        "194.242.2.2",
        "194.242.2.3",
        "194.242.2.4",
        "194.242.2.5",
        "194.242.2.9",
        // DNS.SB
        "185.222.222.222",
        "45.11.45.11",
        // Control D
        "76.76.2.0",
        "76.76.10.0",
        // DNS0.eu
        "193.110.81.0",
        "185.253.5.0",
        // AliDNS (Alibaba)
        "223.5.5.5",
        "223.6.6.6",
        // Comodo
        "8.26.56.26",
        "8.20.247.20",
        // Yandex
        "77.88.8.8",
        "77.88.8.1",
        // Yandex Safe
        "77.88.8.88",
        "77.88.8.2",
        // Yandex Family
        "77.88.8.7",
        "77.88.8.3",
    ]

    static let dohIPv6: Set<String> = [
        // Google
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        // Cloudflare (standard)
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        // Cloudflare (malware blocking)
        "2606:4700:4700::1112",
        "2606:4700:4700::1002",
        // Cloudflare (family)
        "2606:4700:4700::1113",
        "2606:4700:4700::1003",
        // Quad9 (standard)
        "2620:fe::fe",
        "2620:fe::9",
        // Quad9 (no blocking)
        "2620:fe::10",
        "2620:fe::fe:10",
        // Quad9 (ECS)
        "2620:fe::11",
        "2620:fe::fe:11",
        // OpenDNS
        "2620:119:35::35",
        "2620:119:53::53",
        // AdGuard (standard)
        "2a10:50c0::ad1:ff",
        "2a10:50c0::ad2:ff",
        // AdGuard (family)
        "2a10:50c0::bad1:ff",
        "2a10:50c0::bad2:ff",
        // AdGuard (non-filtering)
        "2a10:50c0::1:ff",
        "2a10:50c0::2:ff",
        // NextDNS
        "2a07:a8c0::",
        "2a07:a8c1::",
        // CleanBrowsing (security)
        "2a0d:2a00:1::",
        "2a0d:2a00:2::",
        // Mullvad
        "2a07:e340::2",
        "2a07:e340::3",
        // DNS.SB
        "2a09::",
        "2a11::",
        // DNS0.eu
        "2a0f:fc80::",
        "2a0f:fc81::",
        // AliDNS (Alibaba)
        "2400:3200::1",
        "2400:3200:baba::1",
        // Yandex
        "2a02:6b8::feed:0ff",
        "2a02:6b8:0:1::feed:0ff",
    ]

    static let dohProviders = ContentFilterAddressSet(
        literals: dohIPv4.union(dohIPv6)
    )

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        logger.info("Content Filter starting - configuring DoH/DoT blocking rules")

        var filterRules: [NEFilterRule] = []

        appendFilterRules(&filterRules, remoteNetworks: [("0.0.0.0", 0), ("::", 0)], port: "853")
        appendFilterRules(&filterRules, remoteNetworks: Self.dohIPv4.sorted().map { ($0, 32) }, port: "443")
        appendFilterRules(&filterRules, remoteNetworks: Self.dohIPv6.sorted().map { ($0, 128) }, port: "443")

        // Flows outside the rules pass through. The rules use `.filterData`, so
        // matching flows reach `handleNewFlow`.
        let filterSettings = NEFilterSettings(rules: filterRules, defaultAction: .allow)

        apply(filterSettings) { error in
            if let error = error {
                self.logger.error("Failed to apply filter settings: \(error.localizedDescription, privacy: .public)")
            } else {
                self.logger.info(
                    "Content Filter rules applied successfully: \(filterRules.count, privacy: .public) targeted rules"
                )
            }
            completionHandler(error)
        }
    }

    private func appendFilterRules(
        _ filterRules: inout [NEFilterRule],
        remoteNetworks: [(String, Int)],
        port: String
    ) {
        for (remoteAddress, remotePrefix) in remoteNetworks {
            appendFilterRule(
                &filterRules,
                remoteAddress: remoteAddress,
                remotePrefix: remotePrefix,
                port: port,
                networkProtocol: .TCP
            )
            appendFilterRule(
                &filterRules,
                remoteAddress: remoteAddress,
                remotePrefix: remotePrefix,
                port: port,
                networkProtocol: .UDP
            )
        }
    }

    private func appendFilterRule(
        _ filterRules: inout [NEFilterRule],
        remoteAddress: String,
        remotePrefix: Int,
        port: String,
        networkProtocol: NENetworkRule.`Protocol`
    ) {
        let remoteNetwork = NWHostEndpoint(hostname: remoteAddress, port: port)
        let networkRule = NENetworkRule(
            remoteNetwork: remoteNetwork,
            remotePrefix: remotePrefix,
            localNetwork: nil,
            localPrefix: 0,
            protocol: networkProtocol,
            direction: .outbound
        )
        filterRules.append(NEFilterRule(networkRule: networkRule, action: .filterData))
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("Content Filter stopping: \(String(describing: reason), privacy: .public)")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        autoreleasepool {
            guard let socketFlow = flow as? NEFilterSocketFlow else {
                return .allow()
            }

            guard let remoteEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint
            else {
                switch ContentFilterEndpointlessFlowPolicy.newFlowDecision(
                    sourceTrusted: isTrustedSource(socketFlow)
                ) {
                case .allow:
                    return .allow()
                case .inspect:
                    return Self.inspectOutboundDataVerdict
                case .drop:
                    return .drop()
                }
            }

            return isAllowed(socketFlow, remoteEndpoint: remoteEndpoint)
                ? .allow() : .drop()
        }
    }

    /// Only flows kept under inspection by `handleNewFlow` reach the data
    /// callbacks: flows inside the filtered rule scope that had no destination
    /// yet. Inbound data is never requested (`filterInbound: false`). The inbound
    /// handlers complete the `NEFilterDataProvider` contract and share the same
    /// final verdict so no inspected flow is ever left without one.
    override func handleOutboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        autoreleasepool {
            finalFlowVerdict(for: flow)
        }
    }

    override func handleOutboundDataComplete(
        for flow: NEFilterFlow
    ) -> NEFilterDataVerdict {
        autoreleasepool {
            finalFlowVerdict(for: flow)
        }
    }

    override func handleInboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        autoreleasepool {
            finalFlowVerdict(for: flow)
        }
    }

    override func handleInboundDataComplete(
        for flow: NEFilterFlow
    ) -> NEFilterDataVerdict {
        autoreleasepool {
            finalFlowVerdict(for: flow)
        }
    }

    private func finalFlowVerdict(
        for flow: NEFilterFlow
    ) -> NEFilterDataVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        guard let remoteEndpoint = socketFlow.remoteEndpoint as? NWHostEndpoint
        else {
            switch ContentFilterEndpointlessFlowPolicy.finalFlowDecision(
                sourceTrusted: isTrustedSource(socketFlow)
            ) {
            case .allow:
                return .allow()
            case .inspect, .drop:
                logger.debug("Blocked DoT/DoQ: destination unavailable")
                return .drop()
            }
        }

        return isAllowed(socketFlow, remoteEndpoint: remoteEndpoint)
            ? .allow() : .drop()
    }

    /// Verdict for a flow whose destination is known. Shared by the new-flow
    /// and the outbound-data paths so a deferred flow is judged by the same
    /// rules once its destination shows up.
    private func isAllowed(
        _ flow: NEFilterSocketFlow,
        remoteEndpoint: NWHostEndpoint
    ) -> Bool {
        let ip = remoteEndpoint.hostname
        let port = Int(remoteEndpoint.port) ?? 0

        let isBlockable = port == 853 || (port == 443 && Self.dohProviders.contains(ip))
        guard isBlockable else { return true }

        let source = processValidator.evaluate(
            auditToken: flow.sourceAppAuditToken
        )
        guard let sourcePath = source.canonicalPath else {
            logger.info("Blocked DoH/DoT: source path unavailable")
            return false
        }
        if source.trusted {
            return true
        }

        if port == 853 {
            logger.info("Blocked DoT/DoQ: \(ip, privacy: .public):853 source=\(sourcePath, privacy: .public)")
        } else {
            logger.debug("Blocked DoH/DoH3: \(ip, privacy: .public):443 source=\(sourcePath, privacy: .public)")
        }
        return false
    }

    private func isTrustedSource(_ flow: NEFilterSocketFlow) -> Bool {
        processValidator.evaluate(auditToken: flow.sourceAppAuditToken).trusted
    }

    /// Withholds a final verdict and asks for the first outbound byte, which is
    /// when an unconnected UDP socket has already committed to a destination.
    private static var inspectOutboundDataVerdict: NEFilterNewFlowVerdict {
        .filterDataVerdict(
            withFilterInbound: false,
            peekInboundBytes: 0,
            filterOutbound: true,
            peekOutboundBytes: 1
        )
    }
}

// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Monotonic resolver counters read out of the Rust engine.
///
/// Counters only ever increase and reset with the agent process. They are not
/// persisted. Consumers that want rates or long windows sample this
/// periodically and difference downstream.
public struct ResolverStatsSnapshot: Codable, Equatable, Sendable {
    public let queriesTotal: UInt64
    public let cacheHits: UInt64
    public let cacheMisses: UInt64
    public let blocked: UInt64
    public let servfail: UInt64
    public let prefetchRefills: UInt64
    public let staleServed: UInt64
    public let rebindingFiltered: UInt64
    public let belowNXDomainHits: UInt64
    public let udpOverloadDrops: UInt64
    public let tcpOverloadDrops: UInt64

    public init(
        queriesTotal: UInt64,
        cacheHits: UInt64,
        cacheMisses: UInt64,
        blocked: UInt64,
        servfail: UInt64,
        prefetchRefills: UInt64,
        staleServed: UInt64,
        rebindingFiltered: UInt64,
        belowNXDomainHits: UInt64,
        udpOverloadDrops: UInt64,
        tcpOverloadDrops: UInt64
    ) {
        self.queriesTotal = queriesTotal
        self.cacheHits = cacheHits
        self.cacheMisses = cacheMisses
        self.blocked = blocked
        self.servfail = servfail
        self.prefetchRefills = prefetchRefills
        self.staleServed = staleServed
        self.rebindingFiltered = rebindingFiltered
        self.belowNXDomainHits = belowNXDomainHits
        self.udpOverloadDrops = udpOverloadDrops
        self.tcpOverloadDrops = tcpOverloadDrops
    }
}

public struct AgentRuntimeStateSnapshot: Codable, Equatable, Sendable {
    public let servicesRunning: Bool
    public let captivePortalDetected: Bool
    public let forwarding: Bool
    public let lifecycleGeneration: UInt64
    public let transitionInProgress: Bool
    // Optional so old Agent payloads decode as nil (unknown), which fails closed.
    public let proxyInterceptionState: String?
    public let proxyInterceptionReason: String?
    // CFBundleVersion of the running DNS Proxy provider. nil when unavailable.
    public let proxyProviderVersion: String?
    // True when the Agent's proxy-control XPC link has been failing
    // persistently while the resolver runs (Mach endpoint lost after a sysext
    // replacement race). Optional so old Agent payloads decode as nil.
    public let proxyControlUnreachable: Bool?
    // Resolver counters pulled from the Rust engine on demand. Optional so old
    // Agent payloads decode as nil, and nil when the dylib cannot answer. An
    // absent reading must never be confused with an all-zero one.
    public let resolverStats: ResolverStatsSnapshot?

    public init(
        servicesRunning: Bool,
        captivePortalDetected: Bool,
        forwarding: Bool,
        lifecycleGeneration: UInt64,
        transitionInProgress: Bool,
        proxyInterceptionState: String? = nil,
        proxyInterceptionReason: String? = nil,
        proxyProviderVersion: String? = nil,
        proxyControlUnreachable: Bool? = nil,
        resolverStats: ResolverStatsSnapshot? = nil
    ) {
        self.servicesRunning = servicesRunning
        self.captivePortalDetected = captivePortalDetected
        self.forwarding = forwarding
        self.lifecycleGeneration = lifecycleGeneration
        self.transitionInProgress = transitionInProgress
        self.proxyInterceptionState = proxyInterceptionState
        self.proxyInterceptionReason = proxyInterceptionReason
        self.proxyProviderVersion = proxyProviderVersion
        self.proxyControlUnreachable = proxyControlUnreachable
        self.resolverStats = resolverStats
    }
}

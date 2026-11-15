// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

/// Verdict shape for a filtered flow whose destination NetworkExtension has
/// not resolved yet.
enum ContentFilterEndpointlessFlowDecision: Equatable {
    /// Final allow.
    case allow
    /// No final verdict yet: keep the flow under inspection until its
    /// destination becomes observable.
    case inspect
    /// Final drop.
    case drop
}

/// Decides what happens to a filtered flow that has no remote endpoint.
///
/// A flow only reaches the provider after matching a DoT/DoQ or known-DoH
/// filter rule, and `NEFilterNewFlowVerdict.allow()` is final. An unconnected
/// UDP socket learns its destination only after that decision, so a final allow
/// would let the socket send DoQ to a destination the filter would have
/// dropped. Only MacDNS's own binaries, whose identity was already validated
/// from the audit token, keep the fast allow path that stops the filter from
/// killing the product itself.
enum ContentFilterEndpointlessFlowPolicy {
    /// Decision for a flow that has not carried any data yet.
    static func newFlowDecision(
        sourceTrusted: Bool
    ) -> ContentFilterEndpointlessFlowDecision {
        sourceTrusted ? .allow : .inspect
    }

    /// Final decision after an inspected flow had its chance to expose a
    /// destination. Identity is re-checked because a transient validation
    /// failure must not lock a MacDNS binary out of the fast allow path.
    static func finalFlowDecision(
        sourceTrusted: Bool
    ) -> ContentFilterEndpointlessFlowDecision {
        sourceTrusted ? .allow : .drop
    }
}

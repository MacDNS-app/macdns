// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import NetworkExtension

/// Seam over the close half of `NEAppProxyFlow`, so open-failure handling is
/// verifiable without a live NetworkExtension flow.
protocol ProxyFlowHandle: AnyObject {
    func closeReadWithError(_ error: Error?)
    func closeWriteWithError(_ error: Error?)
}

extension NEAppProxyFlow: ProxyFlowHandle {}

enum ProxyFlowOpenPolicy {
    /// Releases a flow whose `open` failed. Returning without closing both halves
    /// leaks an accepted NE flow until framework or process cleanup.
    static func closeAfterOpenFailure(_ flow: ProxyFlowHandle, error: Error) {
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
    }

    /// Whether an `open` failure is ordinary flow churn: the peer closed the
    /// flow or the system aborted it before the provider could open it.
    static func isRoutineOpenFailure(_ error: Error) -> Bool {
        guard let flowError = error as? NEAppProxyFlowError else { return false }
        return flowError.code == .peerReset || flowError.code == .aborted
    }
}

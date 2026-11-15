// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Seam over `NSXPCListener` so listener admission policy (the code signing
/// requirement, which must be installed before `resume`) is testable without a
/// signed Mach service.
protocol ProxyControlListenerEndpoint: AnyObject {
    var delegate: NSXPCListenerDelegate? { get set }
    func setConnectionCodeSigningRequirement(_ requirement: String)
    func resume()
    func invalidate()
}

extension NSXPCListener: ProxyControlListenerEndpoint {}

/// Seam over `NSXPCConnection` so ownership transfer and lifecycle callbacks are
/// testable without a live XPC peer.
protocol ProxyControlConnection: AnyObject {
    var exportedInterface: NSXPCInterface? { get set }
    var exportedObject: Any? { get set }
    var invalidationHandler: (() -> Void)? { get set }
    var interruptionHandler: (() -> Void)? { get set }
    func setCodeSigningRequirement(_ requirement: String)
    func resume()
    func invalidate()
}

extension NSXPCConnection: ProxyControlConnection {}

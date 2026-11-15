// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Darwin notification names shared by MacDNS components. Darwin notifications
/// are unauthenticated wake-up hints with no payload.
///
/// Components:
/// - MacDNS.app: Observes all notifications, controls proxy via NEDNSProxyManager
/// - MacDNSAgent: Posts notifications when state changes, controls the in-process resolver
/// - DNSProxyExtension: Observes bypass hints, evaluates authenticated resolver health
public enum DarwinNotifications {
    // MARK: - Agent to App Notifications

    /// Posted by Agent when the resolver is ready (services started).
    /// Wakes the App to reconcile the authenticated runtime state.
    public static let proxyEnable = "app.macdns.proxyEnable" as CFString

    /// Posted by Agent when the resolver is stopping.
    /// Wakes the App to reconcile the authenticated runtime state.
    public static let proxyDisable = "app.macdns.proxyDisable" as CFString

    /// Posted by Agent when captive portal is detected.
    /// Wakes the App to read captive portal status from authenticated runtime state.
    public static let captivePortalDetected = "app.macdns.captivePortalDetected" as CFString

    /// Posted by Agent when captive portal is resolved (internet access restored).
    /// Wakes the App to read captive portal status from authenticated runtime state.
    public static let captivePortalResolved = "app.macdns.captivePortalResolved" as CFString

    /// Posted by Agent when license status changes (valid, expired, renewed).
    /// App refreshes license UI and may enable/disable services.
    public static let licenseStatusChanged = "app.macdns.licenseStatusChanged" as CFString

    /// Posted by Agent when a new update is available.
    /// App shows update notification in About tab.
    public static let updateAvailable = "app.macdns.updateAvailable" as CFString

    /// Posted by Agent when the proxy-control link enters persistent outage.
    /// Wake-up hint only. The App re-pulls the authenticated runtime state and
    /// never changes behavior from this unauthenticated signal alone.
    public static let proxyControlOutageChanged = "app.macdns.proxyControlOutageChanged" as CFString

    // MARK: - Extension to App Notifications

    /// Posted by DNSProxyExtension when its interception state flips
    /// (bypass <-> intercepting), e.g. once the control challenge validates and
    /// bypass is disabled. App re-pulls the authenticated provider state so the
    /// UI reflects real interception. Wake-up only. The state itself still comes
    /// from the authenticated XPC pull, never from this unauthenticated signal.
    public static let proxyInterceptionChanged = "app.macdns.dnsproxy.interceptionChanged" as CFString

    // MARK: - Agent to Extension Notifications

    /// Posted by Agent to request an Extension health evaluation.
    /// Used during captive portal detection and when services are stopping.
    /// Bypass changes follow control-plane health evaluation.
    public static let bypassEnable = "app.macdns.dnsproxy.bypass.enable" as CFString

    /// Posted by Agent to request an Extension health evaluation.
    /// Used when the resolver is ready and captive portal is resolved.
    /// Interception requires authenticated resolver health evaluation.
    public static let bypassDisable = "app.macdns.dnsproxy.bypass.disable" as CFString
}

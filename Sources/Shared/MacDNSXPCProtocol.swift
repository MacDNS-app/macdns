// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

@objc(MacDNSXPCProtocol)
public protocol MacDNSXPCProtocol {
    func startResolver(withReply reply: @escaping (Bool) -> Void)
    func stopResolver(withReply reply: @escaping (Bool) -> Void)
    func stopResolverForce(force: Bool, withReply reply: @escaping (Bool) -> Void)

    /// True only when the resolver is actually running.
    func isServicesRunning(withReply reply: @escaping (Bool) -> Void)
    func getRuntimeState(withReply reply: @escaping (Data?) -> Void)

    /// SHA-256 of the agent executable, so the App detects any binary change,
    /// not just a version change.
    func getAgentBinaryHash(withReply reply: @escaping (String?) -> Void)

    func getFullConfig(withReply reply: @escaping ([String: Any]?) -> Void)
    /// The `getFullConfig` payload as a `FullConfigReadResponse`, which also
    /// says why `state.json` could not be served.
    func readFullConfig(withReply reply: @escaping (Data?) -> Void)
    func saveFullConfig(config: [String: Any], withReply reply: @escaping (Data?) -> Void)

    func getCaptivePortalStatus(withReply reply: @escaping (String) -> Void)
    func getResolverMode(withReply reply: @escaping (String) -> Void)
    func recheckCaptivePortal(withReply reply: @escaping (Bool) -> Void)
    /// Grants a full captive-portal bypass for the currently attached network.
    /// Bound to that network identity and expiring after
    /// `CaptivePortalFullBypassApproval.window`. No probe result can renew it.
    func approveCaptivePortalBypass(withReply reply: @escaping (Bool) -> Void)

    func getBlocklistSettings(withReply reply: @escaping (Data?) -> Void)
    func saveBlocklistSettings(settingsData: Data, withReply reply: @escaping (Bool) -> Void)
    func forceBlocklistUpdate(withReply reply: @escaping (Bool) -> Void)

    func flushCache(withReply reply: @escaping (Bool) -> Void)

    /// `request` and the reply are the `dns_history_query` JSON contract
    /// (`QueryHistoryRequest` / `QueryHistoryResponse`).
    func queryHistory(request: Data, withReply reply: @escaping (Data?) -> Void)
    /// Deletes every stored lookup. Replies false when the resolver could not
    /// confirm it.
    func clearQueryHistory(withReply reply: @escaping (Bool) -> Void)

    func getLicenseInfo(withReply reply: @escaping (Data?) -> Void)
    func activateLicense(licenseKey: String, withReply reply: @escaping (Data?) -> Void)
    func deactivateLicense(withReply reply: @escaping (Bool) -> Void)
    func validateLicense(withReply reply: @escaping (Data?) -> Void)

    func getUpdateInfo(withReply reply: @escaping (Data?) -> Void)
    func checkForUpdatesNow(withReply reply: @escaping (Data?) -> Void)
}

/// Guards the untyped full-configuration dictionary that crosses the XPC
/// boundary in both directions.
///
/// `JSONSerialization.data(withJSONObject:)` raises an Objective-C exception,
/// not a Swift error, for any object it cannot encode, so canonicalizing an
/// unvalidated payload terminates the receiving process instead of rejecting
/// the transaction. NSXPC's default class list for a dictionary argument
/// accepts `NSDate`, `NSData` and `NSURL`, none of which are JSON-encodable,
/// so the transport list is narrowed and every payload is validated before it
/// reaches canonicalization.
public enum FullConfigPayloadPolicy {
    /// Recursive class allowlist for the full-config argument and reply.
    /// Bridging an `NSSet` is the only way to hand Objective-C class objects to
    /// `NSXPCInterface.setClasses`. It cannot fail, and an empty set would fail
    /// closed by rejecting every payload.
    public static let allowedClasses: Set<AnyHashable> =
        NSSet(array: [
            NSDictionary.self,
            NSArray.self,
            NSString.self,
            NSNumber.self,
            NSNull.self,
        ]) as? Set<AnyHashable> ?? []

    /// Whether the payload can be canonicalized and persisted as JSON.
    public static func isValidPayload(_ config: [String: Any]) -> Bool {
        JSONSerialization.isValidJSONObject(config)
    }

    /// Applies `allowedClasses` to the Agent's exported interface and the App's
    /// remote interface alike.
    public static func restrictPayloadClasses(on interface: NSXPCInterface) {
        interface.setClasses(
            allowedClasses,
            for: #selector(MacDNSXPCProtocol.saveFullConfig(config:withReply:)),
            argumentIndex: 0,
            ofReply: false
        )
        interface.setClasses(
            allowedClasses,
            for: #selector(MacDNSXPCProtocol.getFullConfig(withReply:)),
            argumentIndex: 0,
            ofReply: true
        )
    }
}

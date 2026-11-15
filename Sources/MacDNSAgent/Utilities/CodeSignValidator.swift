// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Security

// Private libxpc function.
// swift-format-ignore: AlwaysUseLowerCamelCase
@_silgen_name("xpc_connection_get_audit_token")
private func xpc_connection_get_audit_token(_ connection: OpaquePointer, _ token: UnsafeMutablePointer<audit_token_t>)

class CodeSignValidator {

    /// Team identifier extracted from the agent's own code signature at runtime.
    /// Clients must have the same Team ID to connect.
    private static let authorizedTeamIdentifier: String? = {
        var selfCode: SecStaticCode?
        guard
            SecStaticCodeCreateWithPath(
                Bundle.main.bundleURL as CFURL,
                SecCSFlags(),
                &selfCode
            ) == errSecSuccess, let selfCode = selfCode
        else {
            return nil
        }

        var info: CFDictionary?
        guard
            SecCodeCopySigningInformation(
                selfCode,
                SecCSFlags(rawValue: kSecCSSigningInformation),
                &info
            ) == errSecSuccess, let infoDict = info as? [String: Any]
        else {
            return nil
        }

        return infoDict[kSecCodeInfoTeamIdentifier as String] as? String
    }()

    private static let authorizedClientBundleIdentifier = "app.macdns"

    /// Accepts only a validly signed peer with the agent's Team ID and the App's
    /// bundle identifier.
    static func validateConnection(_ connection: NSXPCConnection) -> Bool {
        // Identify the peer by audit token, never by PID. The kernel recycles
        // PIDs, so a PID check races process replacement. The audit token
        // identifies the process at connection time and cannot be reused.
        guard let auditToken = getAuditToken(from: connection) else {
            AgentLogger.shared.error("Code signing validation failed: Could not get audit token")
            return false
        }

        guard let code = getCodeForAuditToken(auditToken) else {
            AgentLogger.shared.error("Code signing validation failed: Could not get code object")
            return false
        }

        guard validateCodeSignature(code: code) else {
            AgentLogger.shared.error("Code signing validation failed: Invalid or untrusted signature")
            return false
        }

        guard validateClientIdentity(code: code) else {
            AgentLogger.shared.error("Code signing validation failed: Unauthorized client identity")
            return false
        }

        AgentLogger.shared.debug("Code signing validation successful")
        return true
    }

    private static func getAuditToken(from connection: NSXPCConnection) -> audit_token_t? {
        // The private KVC key "_xpcConnection" is the only way to reach the
        // audit token before macOS 15. If Apple removes it, every XPC
        // connection is rejected (fail-secure). Recheck on OS updates.
        guard let xpcObject = connection.value(forKey: "_xpcConnection") else {
            return nil
        }

        // OS_xpc_object is toll-free bridged with xpc_object_t, so the object
        // pointer is the xpc_connection_t.
        let xpcConn = Unmanaged.passUnretained(xpcObject as AnyObject).toOpaque()

        var token = audit_token_t()
        withUnsafeMutablePointer(to: &token) { tokenPtr in
            xpc_connection_get_audit_token(OpaquePointer(xpcConn), tokenPtr)
        }
        return token
    }

    private static func getCodeForAuditToken(_ auditToken: audit_token_t) -> SecCode? {
        var code: SecCode?

        var token = auditToken
        let tokenData = Data(bytes: &token, count: MemoryLayout<audit_token_t>.size)

        let attributes: [CFString: Any] = [kSecGuestAttributeAudit: tokenData]

        let status = SecCodeCopyGuestWithAttributes(
            nil,
            attributes as CFDictionary,
            SecCSFlags(),
            &code
        )

        guard status == errSecSuccess, let code = code else {
            AgentLogger.shared.error("SecCodeCopyGuestWithAttributes failed: \(status)")
            return nil
        }

        return code
    }

    private static func validateCodeSignature(code: SecCode) -> Bool {
        // Never pass kSecCSStrictValidate. It rejects valid apps that load
        // dynamic libraries.
        let basicStatus = SecCodeCheckValidity(
            code,
            SecCSFlags(),
            nil
        )

        guard basicStatus == errSecSuccess else {
            AgentLogger.shared.error("SecCodeCheckValidity failed: \(basicStatus)")
            return false
        }

        return true
    }

    private static func validateClientIdentity(code: SecCode) -> Bool {
        guard let expectedTeamID = authorizedTeamIdentifier else {
            AgentLogger.shared.error("Could not determine agent's own Team ID")
            return false
        }

        let requirementString = clientRequirementString(expectedTeamID: expectedTeamID)
        var requirement: SecRequirement?
        let requirementStatus = SecRequirementCreateWithString(
            requirementString as CFString,
            SecCSFlags(),
            &requirement
        )

        guard requirementStatus == errSecSuccess, let requirement = requirement else {
            AgentLogger.shared.error("SecRequirementCreateWithString failed: \(requirementStatus)")
            return false
        }

        let status = SecCodeCheckValidity(code, SecCSFlags(), requirement)
        guard status == errSecSuccess else {
            AgentLogger.shared.error("Client code requirement check failed: \(status)")
            return false
        }

        return true
    }

    static func clientRequirementString(expectedTeamID: String) -> String {
        #"anchor apple generic and identifier "\#(authorizedClientBundleIdentifier)" and certificate leaf[subject.OU] = "\#(expectedTeamID)""#
    }

    /// Signing details of a peer, for diagnostic logs.
    static func getCodeSigningInfo(_ connection: NSXPCConnection) -> [String: String] {
        var result: [String: String] = [:]

        guard let auditToken = getAuditToken(from: connection),
            let code = getCodeForAuditToken(auditToken)
        else {
            result["error"] = "Could not get code object"
            return result
        }

        var staticCode: SecStaticCode?
        var status = SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode)

        guard status == errSecSuccess, let staticCode = staticCode else {
            result["error"] = "SecCodeCopyStaticCode failed: \(status)"
            return result
        }

        var codeInfo: CFDictionary?
        status = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &codeInfo
        )

        guard status == errSecSuccess, let info = codeInfo as? [String: Any] else {
            result["error"] = "SecCodeCopySigningInformation failed: \(status)"
            return result
        }

        if let bundleID = info[kSecCodeInfoIdentifier as String] as? String {
            result["bundleID"] = bundleID
        }

        if let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String {
            result["teamID"] = teamID
        }

        if let cdHash = info[kSecCodeInfoUnique as String] as? Data {
            result["cdHash"] = cdHash.map { String(format: "%02x", $0) }.joined()
        }

        return result
    }
}

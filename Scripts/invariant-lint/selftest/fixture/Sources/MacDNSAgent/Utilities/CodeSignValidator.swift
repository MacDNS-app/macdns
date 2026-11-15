import Foundation
import Security

// Peer identity comes from the connection's audit token.
//
// NEGATIVE CONTROL for J11: kSecCSStrictValidate is named here in a comment
// explaining why it is never used — it rejects valid apps that load dynamic
// libraries. Comments are stripped before matching, so this is not a violation.
final class CodeSignValidator {
    static let shared = CodeSignValidator()

    func validate(connection: NSXPCConnection) -> Bool {
        var token = xpc_connection_get_audit_token(connection)
        let tokenData = Data(bytes: &token, count: MemoryLayout.size(ofValue: token))
        let attributes = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        var guest: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess,
            let peer = guest
        else {
            return false
        }
        return SecCodeCheckValidity(peer, [], appRequirement) == errSecSuccess
    }
}

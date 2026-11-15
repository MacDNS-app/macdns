import Darwin
import Foundation

// NEGATIVE CONTROL for J12: the Content Filter must allow MacDNS's own binaries
// before it drops DoH/DoT, and Security framework process lookup fails from the
// sandbox — so the executable path is resolved with proc_pidpath from the flow's
// audit token. This is flow-source validation, not the proxy-control plane, and
// it is out of the rule's scope by construction.
enum ContentFilterProcessValidator {
    static func isOwnBinary(auditToken: audit_token_t) -> Bool {
        var buffer = [CChar](repeating: 0, count: 4096)
        let pid = audit_token_to_pid(auditToken)
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return false }
        return String(cString: buffer).hasSuffix("/MacDNSAgent")
    }
}

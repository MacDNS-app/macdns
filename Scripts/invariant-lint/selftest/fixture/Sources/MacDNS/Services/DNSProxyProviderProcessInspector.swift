import Darwin
import Foundation

// NEGATIVE CONTROL for J12: runs inside the unsandboxed App, where libproc is
// available. Deliberately outside the rule's scope — the proxy-control plane is
// what must never use proc_*, because the NE sandbox denies it there.
enum DNSProxyProviderProcessInspector {
    static func executablePath(forPID pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4096)
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        return String(cString: buffer)
    }
}

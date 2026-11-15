// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation

/// Locates the running DNS Proxy system-extension provider process. The App is
/// not sandboxed, so libproc is available here, unlike in the NE providers,
/// where the sandbox denies proc_* lookups.
enum DNSProxyProviderProcessInspector {
    static let providerExecutableName = "app.macdns.dnsproxy"

    static func isProviderExecutablePath(_ path: String) -> Bool {
        path.contains("/Library/SystemExtensions/")
            && (path as NSString).lastPathComponent == providerExecutableName
    }

    static func isProviderRunning() -> Bool {
        let capacity = 4096
        var pids = [pid_t](repeating: 0, count: capacity)
        let filled = proc_listallpids(&pids, Int32(capacity * MemoryLayout<pid_t>.size))
        guard filled > 0 else { return false }
        var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        for pid in pids.prefix(Int(filled)) where pid > 0 {
            let length = proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN))
            guard length > 0 else { continue }
            if isProviderExecutablePath(String(cString: pathBuffer)) { return true }
        }
        return false
    }

    /// Polls until the provider process is gone. Returns true when it exited
    /// within the timeout. Callers decide what a timeout means.
    static func waitForProviderExit(
        timeout: TimeInterval,
        pollInterval: TimeInterval = 0.5,
        isRunning: @escaping @Sendable () -> Bool = { isProviderRunning() }
    ) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            guard !Task.isCancelled else { return false }
            if !isRunning() { return true }
            do {
                try await Task.sleep(nanoseconds: UInt64(pollInterval * 1_000_000_000))
            } catch {
                return false
            }
        }
        return !Task.isCancelled && !isRunning()
    }
}

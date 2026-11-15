// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin

/// launchd starts the Agent with a soft limit of 256 descriptors. The resolver
/// admits thousands of UDP queries, and each one forwarded over UDP holds its
/// own upstream socket, so the limit must cover every query it admits plus its
/// TCP connections, databases and logs, or descriptors run out before the
/// resolver's own limits apply.
enum AgentFileDescriptorLimit {
    static let target: rlim_t = 8192

    /// Raises the soft limit to `target`, capped by the hard limit, and never
    /// lowers it. Returns the soft limit in force.
    @discardableResult
    static func raise() -> rlim_t {
        var limits = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &limits) == 0 else { return 0 }
        let wanted = min(target, limits.rlim_max)
        guard limits.rlim_cur < wanted else { return limits.rlim_cur }
        var raised = limits
        raised.rlim_cur = wanted
        return setrlimit(RLIMIT_NOFILE, &raised) == 0 ? wanted : limits.rlim_cur
    }
}

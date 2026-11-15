// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Terminates a provider process that was launched without a proxy session.
///
/// A bootstrap lookup on the proxy-control Mach endpoint demand-launches the
/// provider even while the DNS Proxy configuration is disabled. NetworkExtension
/// then never calls `startProxy`, so no `stopProxy` ever follows and the
/// deferred exit that a stop schedules cannot fire. The process idles, its
/// launchd job stays active, and that job keeps owning
/// `group.app.macdns.proxy-control`. The next system extension replacement then
/// fails activation with "Operation not permitted" and leaves the endpoint
/// unowned until reboot.
///
/// Exiting instead releases the job as soon as it is clear no session is coming.
/// A genuine launch reaches `startProxy` in well under the deadline: measured
/// NetworkExtension dispatch is under 200 ms after spawn.
final class ProviderStartWatchdog: @unchecked Sendable {

    /// Deadline for `startProxy` to arrive. Long enough to absorb a slow launch
    /// right after an update, short enough to exit well inside the App's
    /// replacement drain instead of making it time out.
    static let defaultDeadline: TimeInterval = 10

    static let shared = ProviderStartWatchdog()

    private let lock = NSLock()
    private var didStartProxy = false

    var hasStartedProxy: Bool {
        lock.lock()
        defer { lock.unlock() }
        return didStartProxy
    }

    /// Records that NetworkExtension asked this process to run a proxy. Called
    /// as the first statement of `startProxy` so a start racing the deadline
    /// always wins.
    func noteProxyStarted() {
        lock.lock()
        didStartProxy = true
        lock.unlock()
    }

    /// Arms the deadline. `terminate` runs only if no start was recorded by then.
    func arm(
        deadline: TimeInterval = ProviderStartWatchdog.defaultDeadline,
        queue: DispatchQueue = .main,
        terminate: @escaping @Sendable () -> Void
    ) {
        queue.asyncAfter(deadline: .now() + deadline) { [self] in
            guard !hasStartedProxy else { return }
            terminate()
        }
    }
}

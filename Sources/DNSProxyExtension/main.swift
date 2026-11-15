// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import NetworkExtension
import os.log

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

// A demand-launch on the proxy-control Mach endpoint starts this process without
// any proxy session. Such a process would idle forever, holding its launchd job
// and the proxy-control endpoint hostage against the next extension replacement.
ProviderStartWatchdog.shared.arm {
    Logger(subsystem: "app.macdns.dnsproxy", category: "lifecycle").notice(
        "No proxy session after launch — exiting so launchd releases the job"
    )
    exit(0)
}

dispatchMain()

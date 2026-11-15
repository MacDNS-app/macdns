// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import os.log

class AppLogger {
    static let shared = AppLogger()

    let xpc = Logger(subsystem: "app.macdns.app", category: "xpc")
    let viewModel = Logger(subsystem: "app.macdns.app", category: "viewmodel")

    private init() {}
}

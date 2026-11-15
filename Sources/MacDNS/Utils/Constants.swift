// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import Foundation
import SwiftUI

// MARK: - Font Extension for Menu Font
extension Font {
    static var menu: Font {
        Font(NSFont.menuFont(ofSize: 0))
    }
}

enum UIConstants {
    static let dockHideDelay: TimeInterval = 0.3

    static let shortDelay: TimeInterval = 0.05

    static let standardDelay: TimeInterval = 0.1

    static let flushSuccessDuration: TimeInterval = 2.0

    static let bannerDuration: TimeInterval = 3.0
}

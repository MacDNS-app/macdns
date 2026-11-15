// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import Shared
import SwiftUI

extension Color {
    static let brand = Color(nsColor: NSColor(srgbRed: 0x0D / 255, green: 0x61 / 255, blue: 0xAF / 255, alpha: 1))

    /// Brand blue for controls and text. Lighter in dark appearance to keep contrast.
    static let brandControl = dynamic(light: 0x0D61AF, dark: 0x4C9BE8)
    /// Brand blue for small text such as badges, lighter still in dark appearance.
    static let brandSmallText = dynamic(light: 0x0D61AF, dark: 0x8CC0F5)
    /// Switch track on a selected list row, where the brand blue would vanish into the selection.
    static let settingsSwitchOnSelection = dynamic(light: 0x0A3D73, dark: 0x0A3D73)

    static let settingsCard = dynamic(light: 0xFFFFFF, dark: 0x2A2A2D)
    static let settingsCardStroke = dynamic(light: 0x000000, lightAlpha: 0.11, dark: 0xFFFFFF, darkAlpha: 0.10)
    static let settingsSubtleFill = dynamic(light: 0x000000, lightAlpha: 0.05, dark: 0xFFFFFF, darkAlpha: 0.05)

    /// Helper and secondary text: clearly quieter than titles, still 4.5:1 on the card.
    static let settingsSecondaryText = dynamic(light: 0x75777C, dark: 0x9A9AA0)
    static let settingsTertiaryText = dynamic(light: 0x7D7F84, dark: 0x808086)

    /// The one fill every icon tile uses, so the sidebar and lists read as one set.
    static let settingsTileTop = dynamic(light: 0x2B80D6, dark: 0x3A8DE0)
    static let settingsTileBottom = dynamic(light: 0x0D61AF, dark: 0x1A6CC0)

    /// Status colors tuned for 4.5:1 text contrast on the card background in both appearances.
    static let statusHealthy = dynamic(light: 0x1E8E3E, dark: 0x32D74B)
    static let statusCaution = dynamic(light: 0xB25E00, dark: 0xFF9F0A)
    static let statusCritical = dynamic(light: 0xC5221F, dark: 0xFF6961)

    /// Lookups the cache answered, next to `brandControl` for the providers in history charts.
    /// Lighter than the provider blue in both appearances.
    static let historyCache = dynamic(light: 0x8CBCEC, dark: 0xA6CDF5)
    /// Lookups that failed, apart from the red of blocked ones. 4.5:1 text contrast on the card.
    static let historyFailed = dynamic(light: 0x8944AB, dark: 0xDA8FFF)
    /// Every other answer in history charts and bars: local records, forward zones, not found, failed.
    static let historyOther = Color.settingsTertiaryText.opacity(0.6)

    private static func dynamic(
        light: UInt32, lightAlpha: CGFloat = 1, dark: UInt32, darkAlpha: CGFloat = 1
    ) -> Color {
        Color(
            nsColor: NSColor(name: nil) { appearance in
                let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
                return isDark ? NSColor(hex: dark, alpha: darkAlpha) : NSColor(hex: light, alpha: lightAlpha)
            })
    }

    init(hex: UInt32) {
        self.init(nsColor: NSColor(hex: hex, alpha: 1))
    }
}

extension NSColor {
    convenience init(hex: UInt32, alpha: CGFloat) {
        self.init(
            srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255,
            alpha: alpha
        )
    }
}

extension SettingsStatusTone {
    /// Dot and text color for the status line.
    var indicatorColor: Color {
        switch self {
        case .active: return .statusHealthy
        case .degraded: return .statusCaution
        case .inactive, .waiting: return .settingsTertiaryText
        case .configurationError: return .statusCritical
        }
    }

    /// Gradient for the Overview status block. Both stops keep white text above 4.5:1.
    var blockGradient: [Color] {
        switch self {
        case .active: return [Color(hex: 0x1C7AD4), Color(hex: 0x0B4F91)]
        case .degraded: return [Color(hex: 0xB86200), Color(hex: 0x8A4300)]
        case .inactive, .waiting: return [Color(hex: 0x6B7079), Color(hex: 0x484C53)]
        case .configurationError: return [Color(hex: 0xC93A30), Color(hex: 0x921F18)]
        }
    }
}

extension LicenseStatus {
    var displayTitle: String {
        switch self {
        case .trial: return "Trial"
        case .valid: return "Licensed"
        case .trialExpired: return "Trial Expired"
        case .expired: return "Expired"
        case .invalid: return "Invalid"
        case .unknown: return "Unknown"
        }
    }

    var displaySymbol: String {
        switch self {
        case .trial: return "clock.fill"
        case .valid: return "checkmark.seal.fill"
        case .trialExpired, .expired: return "xmark.seal.fill"
        case .invalid: return "exclamationmark.triangle.fill"
        case .unknown: return "questionmark.circle.fill"
        }
    }

    var displayColor: Color {
        switch self {
        case .trial: return .statusCaution
        case .valid: return .statusHealthy
        case .trialExpired, .expired, .invalid: return .statusCritical
        case .unknown: return .settingsSecondaryText
        }
    }
}

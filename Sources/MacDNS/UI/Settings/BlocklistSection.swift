// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import SwiftUI

struct BlocklistSection: View {
    @ObservedObject var viewModel: AppViewModel

    var body: some View {
        SettingsPage(
            .blocklist,
            lede:
                "Block ads, trackers, and dangerous sites. Turn on a category and choose how much it blocks. Higher levels block more and may block something you need."
        ) {
            SettingsCard {
                SettingsRow("DNS Blocklist", detail: lastUpdatedText) {
                    SettingsIconTile(symbol: "nosign", size: 28)
                } control: {
                    HStack(spacing: 12) {
                        if viewModel.isUpdatingBlocklist {
                            ProgressView()
                                .controlSize(.small)
                        }
                        Button("Update Now") { viewModel.forceBlocklistUpdate() }
                            .disabled(
                                !viewModel.blocklistSettingsLoaded
                                    || !viewModel.blocklistEnabled
                                    || viewModel.isUpdatingBlocklist
                            )
                        SettingsSwitch(isOn: $viewModel.blocklistEnabled)
                            .disabled(!viewModel.blocklistSettingsLoaded)
                    }
                }
            }

            SettingsGroup("Categories") {
                ForEach(Array(BlocklistCategory.allCases.enumerated()), id: \.element) { index, category in
                    if index > 0 {
                        SettingsDivider(inset: 54)
                    }
                    BlocklistCategoryRow(category: category, viewModel: viewModel)
                }
            }
        }
        .requiresAgent(
            isActive: viewModel.agentInstalled,
            canTurnOn: viewModel.persistedStateAvailability.allowsUserEnable,
            onTurnOn: { viewModel.enableDNS() }
        )
        .onAppear {
            if viewModel.agentInstalled {
                viewModel.refreshBlocklistSettings()
            }
        }
        .onChange(of: viewModel.agentInstalled) { _, installed in
            if installed {
                viewModel.refreshBlocklistSettings()
            }
        }
    }

    private var lastUpdatedText: String {
        if let lastUpdated = viewModel.blocklistLastUpdated {
            return "Updated \(lastUpdated.formatted(date: .abbreviated, time: .shortened))"
        }
        return "Not updated yet"
    }
}

private struct BlocklistCategoryRow: View {
    let category: BlocklistCategory
    @ObservedObject var viewModel: AppViewModel

    var body: some View {
        let level = viewModel.getCategoryLevel(category)
        HStack(alignment: .center, spacing: 12) {
            SettingsIconTile(symbol: symbol, size: 28)

            VStack(alignment: .leading, spacing: 2) {
                Text(category.rawValue)
                    .font(.system(size: 13))
                Text(category.description)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.settingsSecondaryText)
                    .fixedSize(horizontal: false, vertical: true)
                if level != .disabled {
                    Label(levelDescription(level, for: category), systemImage: "checkmark.circle.fill")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(Color.statusHealthy)
                        .labelStyle(CompactLabelStyle())
                        .padding(.top, 2)
                } else {
                    Text("Not blocked")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(Color.settingsTertiaryText)
                        .padding(.top, 2)
                }
            }

            Spacer(minLength: 12)

            Picker(
                category.rawValue,
                selection: Binding(
                    get: { viewModel.getCategoryLevel(category) },
                    set: { viewModel.setCategoryLevel(category, level: $0) }
                )
            ) {
                ForEach(CategoryLevel.availableLevels(for: category), id: \.self) { level in
                    Text(levelDisplayName(level, for: category)).tag(level)
                }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .buttonStyle(.borderless)
            .fixedSize()
            .disabled(
                !viewModel.blocklistSettingsLoaded
                    || !viewModel.blocklistEnabled
            )
        }
        .padding(.horizontal, SettingsMetrics.rowHorizontalPadding)
        .padding(.vertical, 10)
    }

    private var symbol: String {
        switch category {
        case .adsTracking: return "megaphone.fill"
        case .malwareSecurity: return "ladybug.fill"
        case .adultContent: return "eye.slash.fill"
        case .gambling: return "dice.fill"
        case .socialMedia: return "person.2.fill"
        case .miscellaneous: return "ellipsis"
        }
    }

    private func levelDisplayName(_ level: CategoryLevel, for category: BlocklistCategory) -> String {
        if level == .disabled { return "Off" }
        if (category == .adultContent || category == .socialMedia) && level == .light {
            return "On"
        }
        return level.rawValue
    }

    private func levelDescription(_ level: CategoryLevel, for category: BlocklistCategory) -> String {
        switch (category, level) {
        case (.adsTracking, .light):
            return "Common ads, rarely blocks what you need"
        case (.adsTracking, .normal):
            return "Balanced for everyday use (Recommended)"
        case (.adsTracking, .pro):
            return "Also blocks more trackers"
        case (.adsTracking, .proPlus):
            return "Strict, a few sites may not work"
        case (.adsTracking, .ultimate):
            return "Strictest, some sites will break"

        case (.malwareSecurity, .light):
            return "Scam sites only"
        case (.malwareSecurity, .normal):
            return "Scams plus the most active malware and phishing"
        case (.malwareSecurity, .pro):
            return "Scams plus a wider malware and phishing list (Recommended)"
        case (.malwareSecurity, .ultimate):
            return "Scams plus the full malware and phishing list"

        case (.adultContent, .light):
            return "Adult and pornographic sites"

        case (.gambling, .light):
            return "The biggest gambling sites only"
        case (.gambling, .normal):
            return "Most gambling sites"
        case (.gambling, .pro):
            return "Every gambling site on the list"

        case (.socialMedia, .light):
            return "Facebook, Instagram, TikTok, X, Snapchat"

        case (.miscellaneous, .light):
            return "Pop-up ads only"
        case (.miscellaneous, .normal):
            return "Pop-up ads and link shorteners"
        case (.miscellaneous, .pro):
            return "Also blocks VPN and DNS services apps use to skip MacDNS"

        default:
            return ""
        }
    }
}

/// Icon and title with a tight gap, for the one-line level summary.
private struct CompactLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 4) {
            configuration.icon
            configuration.title
        }
    }
}

#Preview {
    BlocklistSection(viewModel: AppViewModel())
}

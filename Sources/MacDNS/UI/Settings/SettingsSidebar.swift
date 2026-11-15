// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import SwiftUI

struct SettingsSidebar: View {
    @ObservedObject var viewModel: AppViewModel
    @Binding var selection: SettingsSection?
    let query: String

    private let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"

    private var tone: SettingsStatusTone {
        SettingsStatusTone.tone(
            availability: viewModel.persistedStateAvailability,
            status: viewModel.protectionDisplayState.statusPolicy.status
        )
    }

    private var showsStatusItem: Bool {
        SettingsSection.overview.matches(query)
    }

    private var hasMatches: Bool {
        SettingsSection.allCases.contains { $0.matches(query) }
    }

    var body: some View {
        List(selection: $selection) {
            if showsStatusItem {
                statusItem
                    .tag(SettingsSection.overview)
            }

            ForEach(SettingsSectionGroup.allCases, id: \.self) { group in
                let sections = SettingsSection.sections(in: group).filter { $0.matches(query) }
                if !sections.isEmpty {
                    Section {
                        ForEach(sections) { section in
                            row(for: section)
                                .tag(section)
                        }
                    } header: {
                        // The default sidebar header gray is too faint in dark mode.
                        Text(group.title)
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .overlay {
            if !hasMatches {
                ContentUnavailableView.search(text: query)
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            Text("Version \(appVersion)")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 20)
                .padding(.vertical, 10)
        }
    }

    private var statusItem: some View {
        HStack(spacing: 10) {
            Image(tone == .active || tone == .degraded ? "StatusOn" : "StatusOff")
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 30, height: 30)

            VStack(alignment: .leading, spacing: 1) {
                Text("MacDNS")
                    .font(.system(size: 13, weight: .semibold))
                HStack(spacing: 5) {
                    if tone == .waiting {
                        ProgressView()
                            .controlSize(.mini)
                    } else {
                        // A white ring keeps the dot readable on the blue selection.
                        Circle()
                            .fill(tone.indicatorColor)
                            .frame(width: 8, height: 8)
                            .overlay(Circle().strokeBorder(.white, lineWidth: selection == .overview ? 1.5 : 0))
                    }
                    Text(viewModel.persistedStateAvailability.statusMessageOverride ?? viewModel.statusMessage)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
            }
        }
        .padding(.vertical, 5)
    }

    @ViewBuilder
    private func row(for section: SettingsSection) -> some View {
        let label = Label {
            Text(section.title)
        } icon: {
            SettingsIconTile(symbol: section.symbolName)
        }
        if section == .licenseUpdates {
            label.badge(
                LicenseAttentionPolicy.badge(
                    licenseStatus: viewModel.licenseInfo?.status,
                    updateAvailable: viewModel.updateInfo?.isUpdateAvailable == true
                ).map { Text($0) })
        } else {
            label
        }
    }
}

// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import SwiftUI

struct LicenseUpdatesSection: View {
    @ObservedObject var viewModel: AppViewModel
    @ObservedObject private var updater = UpdaterManager.shared
    @State private var licenseKeyInput = ""
    @State private var showLicenseKey = false
    @State private var lastUpdateCheckDate: Date?

    private let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"

    var body: some View {
        SettingsPage(.licenseUpdates) {
            VStack(spacing: 14) {
                appHeader
                updateBanner
            }
            SettingsGroup("License") {
                licenseCard
            }
            SettingsGroup("Updates") {
                updatesCard
            }
        } footer: {
            footer
                .frame(maxWidth: .infinity)
        }
        .onAppear {
            viewModel.loadLicenseInfo()
            viewModel.loadUpdateInfo()
            lastUpdateCheckDate = updater.lastUpdateCheckDate
        }
        .onChange(of: updater.canCheckForUpdates) { _, _ in
            lastUpdateCheckDate = updater.lastUpdateCheckDate
        }
    }

    // MARK: - Header

    private var appHeader: some View {
        VStack(spacing: 4) {
            Image("AppLogo")
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 64, height: 64)
                .shadow(color: .black.opacity(0.18), radius: 8, y: 4)
                .padding(.bottom, 4)
            Text("MacDNS")
                .font(.system(size: 20, weight: .bold))
            Text("Secure your Mac at the DNS level · Version \(appVersion)")
                .font(.system(size: 12))
                .foregroundStyle(Color.settingsSecondaryText)
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: - Update banner

    @ViewBuilder
    private var updateBanner: some View {
        if let update = viewModel.updateInfo, update.isUpdateAvailable {
            let shape = RoundedRectangle(cornerRadius: SettingsMetrics.cardCornerRadius, style: .continuous)
            HStack(spacing: 12) {
                Image(systemName: "arrow.down.circle.fill")
                    .font(.system(size: 22))
                    .foregroundStyle(Color.brandControl)

                VStack(alignment: .leading, spacing: 2) {
                    Text("MacDNS \(update.latestVersion) is available")
                        .font(.system(size: 13, weight: .semibold))
                    Text("You have \(update.currentVersion)")
                        .font(.system(size: 11))
                        .foregroundStyle(Color.settingsSecondaryText)
                }

                Spacer()

                Button("Update Now") {
                    updater.checkForUpdates()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!updater.canCheckForUpdates)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                shape.fill(
                    LinearGradient(
                        colors: [Color.brandControl.opacity(0.16), Color.brandControl.opacity(0.04)],
                        startPoint: .leading, endPoint: .trailing))
            )
            .overlay(shape.strokeBorder(Color.brandControl.opacity(0.35), lineWidth: 1))
        }
    }

    // MARK: - License

    @ViewBuilder
    private var licenseCard: some View {
        licenseStatusRow
        SettingsDivider()
        licenseKeyRow
        SettingsDivider()
        licenseFeedbackRow
    }

    private var licenseStatusRow: some View {
        HStack(spacing: 12) {
            Group {
                if viewModel.isLoadingLicense {
                    ProgressView()
                        .controlSize(.small)
                } else if let info = viewModel.licenseInfo {
                    SettingsIconTile(symbol: info.status.displaySymbol, size: 28)
                } else {
                    SettingsIconTile(symbol: "questionmark", size: 28)
                }
            }
            .frame(width: 28, height: 28)

            VStack(alignment: .leading, spacing: 2) {
                if let info = viewModel.licenseInfo {
                    Text(info.status.displayTitle)
                        .font(.system(size: 13, weight: .medium))
                    if info.statusDescription.caseInsensitiveCompare(info.status.displayTitle) != .orderedSame {
                        Text(info.statusDescription)
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle(info.status.displayColor)
                    }
                    if let blockReason = info.blockReason {
                        Text(blockReason)
                            .font(.system(size: 11))
                            .foregroundStyle(Color.statusCritical)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } else {
                    Text("Loading…")
                        .font(.system(size: 13))
                        .foregroundStyle(Color.settingsSecondaryText)
                }
            }

            Spacer()

            Button {
                viewModel.refreshLicenseStatus()
            } label: {
                Image(systemName: "arrow.clockwise")
            }
            .buttonStyle(.borderless)
            .disabled(viewModel.isLoadingLicense)
            .help("Refresh")
        }
        .padding(.horizontal, SettingsMetrics.rowHorizontalPadding)
        .padding(.vertical, 10)
    }

    private var licenseKeyRow: some View {
        HStack(spacing: 8) {
            Text("License Key")
                .font(.system(size: 13))
                .frame(width: 84, alignment: .leading)

            Group {
                if showLicenseKey {
                    TextField("XXXX-XXXX-XXXX-XXXX", text: $licenseKeyInput)
                } else {
                    SecureField("XXXX-XXXX-XXXX-XXXX", text: $licenseKeyInput)
                }
            }
            .textFieldStyle(.roundedBorder)
            .font(.system(size: 12, design: .monospaced))

            Button {
                showLicenseKey.toggle()
            } label: {
                Image(systemName: showLicenseKey ? "eye.slash" : "eye")
                    .foregroundStyle(Color.settingsSecondaryText)
                    .frame(width: 18)
            }
            .buttonStyle(.borderless)
            .help(showLicenseKey ? "Hide key" : "Show key")

            // Only Enable installs the Agent, and activation needs it running.
            Button("Activate") {
                viewModel.activateLicense(key: licenseKeyInput)
            }
            .buttonStyle(.borderedProminent)
            .disabled(
                licenseKeyInput.isEmpty || viewModel.isLoadingLicense
                    || !viewModel.agentInstalled
            )
        }
        .padding(.horizontal, SettingsMetrics.rowHorizontalPadding)
        .padding(.vertical, 10)
        .onAppear {
            if let key = viewModel.licenseInfo?.licenseKey {
                licenseKeyInput = key
            }
        }
        .onChange(of: viewModel.licenseInfo?.licenseKey) { _, newKey in
            if let key = newKey {
                licenseKeyInput = key
            }
        }
    }

    private var licenseFeedbackRow: some View {
        HStack(spacing: 8) {
            if let feedback = viewModel.licenseActivationFeedback {
                Label(
                    feedback.message,
                    systemImage: feedback.isSuccess ? "checkmark.circle.fill" : "exclamationmark.circle.fill"
                )
                .font(.system(size: 12))
                .foregroundStyle(feedback.isSuccess ? Color.statusHealthy : Color.statusCritical)
            } else if !viewModel.agentInstalled {
                Text("Turn on MacDNS first, then activate your key.")
                    .font(.system(size: 12))
                    .foregroundStyle(Color.settingsSecondaryText)
            } else {
                Text("Have a key? Paste it above and press Activate.")
                    .font(.system(size: 12))
                    .foregroundStyle(Color.settingsSecondaryText)
            }

            Spacer()

            Link(destination: URL(string: "https://macdns.app/buy")!) {
                Label("Get License", systemImage: "arrow.up.right")
                    .labelStyle(TrailingIconLabelStyle())
            }
            .font(.system(size: 12, weight: .medium))
        }
        .padding(.horizontal, SettingsMetrics.rowHorizontalPadding)
        .padding(.vertical, 10)
    }

    // MARK: - Updates

    private var updatesCard: some View {
        SettingsRow("Check for Updates", detail: lastCheckedDetail) {
            Button("Check Now") {
                updater.checkForUpdates()
            }
            .disabled(!updater.canCheckForUpdates)
        }
    }

    private var lastCheckedDetail: String {
        guard let lastUpdateCheckDate else { return "Never checked" }
        return "Last checked \(lastUpdateCheckDate.formatted(.relative(presentation: .numeric, unitsStyle: .wide)))"
    }

    // MARK: - Footer

    private var footer: some View {
        VStack(spacing: 6) {
            HStack(spacing: 18) {
                Link(destination: URL(string: "https://macdns.app")!) {
                    Label("Website", systemImage: "globe")
                }
                Link(destination: URL(string: "https://github.com/MacDNS-app/macdns")!) {
                    Label("GitHub", systemImage: "chevron.left.forwardslash.chevron.right")
                }
            }
            .font(.system(size: 12))
            Text("© 2025-2026 MacDNS.app")
                .font(.system(size: 11))
                .foregroundStyle(Color.settingsTertiaryText)
        }
    }
}

private struct TrailingIconLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 3) {
            configuration.title
            configuration.icon
                .imageScale(.small)
        }
    }
}

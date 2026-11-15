// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import SwiftUI

struct OverviewSection: View {
    @ObservedObject var viewModel: AppViewModel
    let onNavigate: (SettingsSection) -> Void
    @State private var isFlushingCache = false
    @State private var showFlushSuccess = false
    @State private var showFlushError = false

    private var tone: SettingsStatusTone {
        SettingsStatusTone.tone(
            availability: viewModel.persistedStateAvailability,
            status: viewModel.protectionDisplayState.statusPolicy.status
        )
    }

    private var enabledBlocklistCategoryCount: Int {
        BlocklistCategory.allCases.filter { viewModel.getCategoryLevel($0) != .disabled }.count
    }

    var body: some View {
        SettingsPage(.overview) {
            VStack(spacing: 12) {
                statusBlock
                notices
            }

            SettingsGroup("Health") {
                health
            }

            SettingsGroup("Quick Actions") {
                flushRow
            }
        }
    }

    // MARK: - Status

    private var statusBlock: some View {
        let shape = RoundedRectangle(cornerRadius: 14, style: .continuous)
        return VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center, spacing: 16) {
                statusIcon

                VStack(alignment: .leading, spacing: 3) {
                    Text(headline)
                        .font(.system(size: 20, weight: .bold))
                    if statusSubtitle.caseInsensitiveCompare(headline) != .orderedSame {
                        Text(statusSubtitle)
                            .font(.system(size: 12.5))
                            .foregroundStyle(.white.opacity(0.82))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .foregroundStyle(.white)

                Spacer(minLength: 12)

                statusControl
            }

            if viewModel.persistedStateAvailability == .loaded {
                chips
                    .opacity(isProtecting ? 1 : 0.6)
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            shape
                .fill(LinearGradient(colors: tone.blockGradient, startPoint: .topLeading, endPoint: .bottomTrailing))
                .overlay(alignment: .topTrailing) {
                    Circle()
                        .fill(
                            RadialGradient(
                                colors: [.white.opacity(0.20), .clear], center: .center, startRadius: 0,
                                endRadius: 130)
                        )
                        .frame(width: 260, height: 260)
                        .offset(x: 80, y: -110)
                }
                .clipShape(shape)
        )
        .overlay(shape.strokeBorder(.white.opacity(0.12), lineWidth: 1))
        .shadow(color: tone.blockGradient[1].opacity(0.25), radius: 10, y: 4)
    }

    private var isProtecting: Bool { tone == .active || tone == .degraded }

    private var headline: String {
        viewModel.persistedStateAvailability.protectionHeadlineOverride ?? viewModel.protectionDisplayState.headline
    }

    /// When protection is active the status message only repeats the headline, so the
    /// subtitle names the DNS providers instead.
    private var statusSubtitle: String {
        if let override = viewModel.persistedStateAvailability.statusMessageOverride {
            return override
        }
        guard tone == .active else { return viewModel.statusMessage }
        let providers = DoHProviderID.allCases.filter { viewModel.dohProviders.contains($0) }
        return "Encrypted lookups through " + providers.map(\.displayName).joined(separator: ", ")
    }

    @ViewBuilder
    private var statusIcon: some View {
        Group {
            switch tone {
            case .active, .inactive, .waiting:
                Image("AppLogo")
                    .resizable()
                    .aspectRatio(contentMode: .fit)
            case .degraded:
                symbol("exclamationmark.shield.fill")
            case .configurationError:
                symbol("exclamationmark.triangle.fill")
            }
        }
        .frame(width: 52, height: 52)
        .shadow(color: .black.opacity(0.2), radius: 4, y: 2)
    }

    private func symbol(_ name: String) -> some View {
        Image(systemName: name)
            .resizable()
            .scaledToFit()
            .fontWeight(.semibold)
            .foregroundStyle(.white)
            .padding(4)
    }

    @ViewBuilder
    private var statusControl: some View {
        if viewModel.persistedStateAvailability.showsProtectionToggle {
            Toggle(
                "",
                isOn: Binding(
                    get: { viewModel.isEnabled },
                    set: { _ in viewModel.toggleDNS() }
                )
            )
            .toggleStyle(.switch)
            .labelsHidden()
            .controlSize(.large)
            .tint(viewModel.isEnabled && !viewModel.isLicenseValid ? licenseWarningTint : Color(hex: 0x34C759))
            .help(viewModel.isEnabled ? "Turn protection off" : "Turn protection on")
        } else if viewModel.persistedStateAvailability.showsProgressIndicator {
            ProgressView()
                .controlSize(.small)
                .tint(.white)
                .frame(width: 32)
        }
    }

    // Orange would disappear on the burnt-orange degraded block.
    private var licenseWarningTint: Color {
        tone == .degraded ? .yellow : .orange
    }

    private var chips: some View {
        HStack(spacing: 6) {
            chip(
                viewModel.dnssecEnabled ? "DNSSEC" : "DNSSEC Off",
                isOn: viewModel.dnssecEnabled, destination: .resolver)
            chip(
                viewModel.blocklistEnabled ? blocklistChipTitle(enabledBlocklistCategoryCount) : "Blocklist Off",
                isOn: viewModel.blocklistEnabled, destination: .blocklist)
            chip(
                viewModel.blockDohDotEnabled ? "Other encrypted DNS blocked" : "Other encrypted DNS allowed",
                isOn: viewModel.blockDohDotEnabled, destination: .resolver)
        }
    }

    private func blocklistChipTitle(_ count: Int) -> String {
        count == 1 ? "Blocklist · 1 category" : "Blocklist · \(count) categories"
    }

    private func chip(_ title: String, isOn: Bool, destination: SettingsSection) -> some View {
        Button {
            onNavigate(destination)
        } label: {
            HStack(spacing: 5) {
                // With protection off nothing is applied, so no setting earns a check mark.
                if isProtecting {
                    Image(systemName: isOn ? "checkmark" : "minus")
                        .font(.system(size: 9, weight: .heavy))
                }
                Text(title)
                    .font(.system(size: 11, weight: .medium))
            }
            .foregroundStyle(.white)
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .background(Capsule().fill(.white.opacity(0.14)))
            .overlay(Capsule().strokeBorder(.white.opacity(0.18), lineWidth: 1))
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .help("Open \(destination.title)")
    }

    // MARK: - Notices

    @ViewBuilder
    private var notices: some View {
        if let permissionApprovalMessage = viewModel.permissionApprovalMessage {
            SettingsNotice(
                symbol: "exclamationmark.triangle.fill", title: "Approval needed",
                message: permissionApprovalMessage, color: .statusCaution)
        }

        if viewModel.showsCaptiveBypassApproval {
            SettingsNotice(
                symbol: "wifi.exclamationmark", title: "Wi-Fi sign-in",
                message:
                    "This Wi-Fi may need you to sign in. Protection stays on. Allow a full bypass only if the sign-in page won't load.",
                color: .statusCaution
            ) {
                Button("Allow Full Bypass") {
                    viewModel.approveCaptivePortalBypass()
                }
            }
        }

        if let configSaveFailureMessage = viewModel.configSaveFailureMessage {
            SettingsNotice(
                symbol: "exclamationmark.octagon.fill", title: "Settings not saved",
                message: configSaveFailureMessage, color: .statusCritical)
        }
    }

    // MARK: - Health

    @ViewBuilder
    private var health: some View {
        SettingsRow("System Extension") {
            switch HealthRowsPolicy.systemExtension(
                extensionActive: viewModel.extensionActive, viewModel.protectionDisplayState)
            {
            case .extensionActive: StatusIndicator("Active", color: .statusHealthy)
            case .installed: StatusIndicator("Installed", color: .secondary)
            case .inactive: StatusIndicator("Inactive", color: .secondary)
            }
        }
        SettingsDivider()
        SettingsRow("DNS Lookups", detail: "Whether this Mac's lookups reach MacDNS") {
            switch HealthRowsPolicy.interception(viewModel.protectionDisplayState) {
            case .off:
                StatusIndicator("Off", color: .secondary)
            case .intercepting:
                StatusIndicator("Through MacDNS", color: .statusHealthy)
            case .bypass(let reason):
                StatusIndicator(ProtectionStatusPolicy.pausedMessage(reason: reason), color: .statusCaution)
            case .unknown:
                StatusIndicator("Unknown", color: .secondary)
            }
        }
        if viewModel.persistedStateAvailability == .loaded {
            SettingsDivider()
            SettingsRow("Connection") {
                Text(HealthRowsPolicy.resolverMode(viewModel.protectionDisplayState, reported: viewModel.resolverMode))
                    .font(.system(size: 12.5))
                    .foregroundStyle(Color.settingsSecondaryText)
            }
        }
        SettingsDivider()
        Button {
            onNavigate(.licenseUpdates)
        } label: {
            SettingsRow("License") {
                HStack(spacing: 8) {
                    if let info = viewModel.licenseInfo {
                        StatusPill(licensePillText(info), color: info.status.displayColor)
                    } else {
                        Text("Loading…")
                            .foregroundStyle(Color.settingsSecondaryText)
                    }
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(Color.settingsTertiaryText)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func licensePillText(_ info: LicenseInfo) -> String {
        guard info.status == .trial, let days = info.trialDaysRemaining, days > 0 else {
            return info.status.displayTitle
        }
        return days == 1 ? "Trial · 1 day left" : "Trial · \(days) days left"
    }

    // MARK: - Quick Actions

    private var flushRow: some View {
        SettingsRow("Clear DNS Cache", detail: "Forgets saved answers and reconnects. Try it when a site won't load.") {
            HStack(spacing: 10) {
                if isFlushingCache {
                    ProgressView()
                        .controlSize(.small)
                } else if showFlushSuccess {
                    Label("Cleared", systemImage: "checkmark.circle.fill")
                        .font(.caption)
                        .foregroundStyle(Color.statusHealthy)
                } else if showFlushError {
                    Label("Failed", systemImage: "xmark.circle.fill")
                        .font(.caption)
                        .foregroundStyle(Color.statusCritical)
                }
                Button("Clear", action: flush)
                    .disabled(
                        isFlushingCache || !viewModel.isEnabled || !viewModel.agentInstalled
                            || !viewModel.servicesRunning
                    )
                    .help(
                        "Clears the answers MacDNS saved and reconnects to your DNS providers. macOS keeps its own cache. To clear it too, run in Terminal: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder"
                    )
            }
        }
    }

    private func flush() {
        isFlushingCache = true
        showFlushSuccess = false
        showFlushError = false
        viewModel.flushDNSCache { success in
            isFlushingCache = false
            if success {
                showFlushSuccess = true
            } else {
                showFlushError = true
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + UIConstants.flushSuccessDuration) {
                showFlushSuccess = false
                showFlushError = false
            }
        }
    }
}

#Preview {
    OverviewSection(viewModel: AppViewModel(), onNavigate: { _ in })
}

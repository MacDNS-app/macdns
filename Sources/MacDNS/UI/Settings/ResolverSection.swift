// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import SwiftUI

struct ResolverSection: View {
    @ObservedObject var viewModel: AppViewModel

    var body: some View {
        SettingsPage(.resolver) {
            SettingsGroup(
                "Providers", caption: "Your lookups go to these services, encrypted. Pick one or more."
            ) {
                HStack(spacing: 10) {
                    ForEach(DoHProviderID.allCases, id: \.self) { provider in
                        providerTile(provider)
                    }
                }
                .padding(14)
                SettingsDivider(inset: 0)
                SettingsRow("Query Mode", detail: dispatchDetail(viewModel.dohDispatchMode)) {
                    SegmentedPicker("Query Mode", selection: $viewModel.dohDispatchMode) {
                        ForEach(DoHDispatchMode.allCases, id: \.self) { mode in
                            Text(mode.displayName).tag(mode)
                        }
                    }
                    .labelsHidden()
                    // Segments share the width equally, so it must leave room around the longest label.
                    .frame(width: 240)
                    // The brand tint draws the selected segment as a block offset below the control.
                    .tint(nil)
                }
                // Without it the row keeps a one-line height and clips the wrapped description.
                .fixedSize(horizontal: false, vertical: true)
            }

            SettingsGroup("Validation") {
                SettingsRow(
                    "DNSSEC Validation",
                    detail: "Sites can sign their DNS answers. Discards answers whose signature fails the check."
                ) {
                    SettingsSwitch(
                        isOn: Binding(
                            get: { viewModel.dnssecEnabled },
                            set: { newValue in viewModel.setDNSSEC(enabled: newValue) }
                        ))
                }
                SettingsDivider()
                SettingsRow(
                    "Answer Refinement",
                    detail:
                        "When providers give different addresses for a site, later visits use the one that answers fastest."
                ) {
                    SettingsSwitch(isOn: $viewModel.dnsAnswerRefinementEnabled)
                }
            }

            SettingsGroup("Cache") {
                SettingsRow("Prefetch", detail: "Renews answers you used in the last few hours before they expire.") {
                    SettingsSwitch(isOn: $viewModel.prefetchEnabled)
                }
                SettingsDivider()
                PopularPrefetchRow(viewModel: viewModel)
                SettingsDivider()
                SettingsRow(
                    "Serve Expired",
                    detail: "Reuses an older answer when the providers are slow or can't be reached."
                ) {
                    SettingsSwitch(isOn: $viewModel.serveExpiredEnabled)
                }
            }

            SettingsGroup("Other Encrypted DNS") {
                SettingsRow(
                    "Block Other Encrypted DNS",
                    detail:
                        "Some apps send lookups through their own encrypted DNS and skip your blocklists. This blocks the common methods."
                ) {
                    SettingsSwitch(isOn: $viewModel.blockDohDotEnabled)
                }
                .help(
                    "Blocks every DNS over TLS (DoT) and DNS over QUIC (DoQ) connection, plus DNS over HTTPS (DoH) to well-known providers. DoH sent to an unknown server is not blocked."
                )
            }
        }
        .disabled(
            !viewModel.persistedStateAvailability.allowsConfigurationMutation
        )
        .requiresAgent(
            isActive: viewModel.agentInstalled,
            canTurnOn: viewModel.persistedStateAvailability.allowsUserEnable,
            onTurnOn: { viewModel.enableDNS() }
        )
    }

    @ViewBuilder
    private func providerTile(_ provider: DoHProviderID) -> some View {
        let isSelected = viewModel.dohProviders.contains(provider)
        // toggleDoHProvider refuses to remove the last provider, so the tooltip says so up front.
        let isLocked = isSelected && viewModel.dohProviders.count == 1
        let shape = RoundedRectangle(cornerRadius: 10, style: .continuous)
        Button {
            viewModel.toggleDoHProvider(provider)
        } label: {
            VStack(spacing: 7) {
                ProviderMark(provider: provider)
                VStack(spacing: 1) {
                    Text(provider.displayName)
                        .font(.system(size: 12.5, weight: .semibold))
                    Text(provider.endpointHost)
                        .font(.system(size: 10.5))
                        .foregroundStyle(Color.settingsSecondaryText)
                }
            }
            .padding(.top, 14)
            .padding(.bottom, 11)
            .frame(maxWidth: .infinity)
            .background(shape.fill(isSelected ? Color.brandControl.opacity(0.12) : Color.settingsSubtleFill))
            .overlay(alignment: .topTrailing) {
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 15))
                    .foregroundStyle(isSelected ? Color.brandControl : Color.secondary.opacity(0.6))
                    .padding(7)
            }
            .contentShape(shape)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(provider.displayName)
        .accessibilityValue(isSelected ? "Selected" : "Not selected")
        .help(isLocked ? "At least one provider stays selected." : "")
    }

    private func dispatchDetail(_ mode: DoHDispatchMode) -> String {
        switch mode {
        case .parallel:
            return "Asks every selected provider at once and uses the first answer."
        case .staggeredParallel:
            return "Asks the fastest provider first, then the others a few milliseconds later."
        case .sequentialTimeout:
            return "Asks one provider at a time and tries the next if it takes too long."
        }
    }
}

/// Sits under Prefetch: it widens what Prefetch renews, and it ranks hosts from the lookup history.
private struct PopularPrefetchRow: View {
    @ObservedObject var viewModel: AppViewModel

    private var settings: QueryHistorySettings { viewModel.queryHistorySettings }

    private var unavailableReason: String? {
        switch (viewModel.prefetchEnabled, settings.enabled) {
        case (true, true): return nil
        case (false, true): return "Needs Prefetch turned on."
        case (true, false): return "Needs lookup history, which is off in Advanced."
        case (false, false): return "Needs Prefetch, and lookup history in Advanced, turned on."
        }
    }

    private var dayChoices: [Int] {
        let choices = settings.popularDayChoicesWithinRetention
        return choices.contains(settings.popularDays) ? choices : choices + [settings.popularDays]
    }

    var body: some View {
        let reason = unavailableReason
        // Text doesn't dim when disabled, so it fades with the menus. The reason stays readable.
        let textOpacity = reason == nil ? 1 : 0.5
        VStack(alignment: .leading, spacing: 2) {
            Text("Keep Popular Hosts Fresh")
                .font(.system(size: 13))
                .opacity(textOpacity)
            Text(
                "Also renews the hosts this Mac looked up most, even if nothing asked for them recently. Uses your lookup history."
            )
            .font(.system(size: 11))
            .foregroundStyle(Color.settingsSecondaryText)
            .fixedSize(horizontal: false, vertical: true)
            .opacity(textOpacity)

            HStack(spacing: 6) {
                Text("Keep the")
                    .opacity(textOpacity)
                Picker("Hosts", selection: countBinding) {
                    ForEach(QueryHistorySettings.popularCountChoices, id: \.self) { count in
                        Text(count == 0 ? "Off" : count.formatted()).tag(count)
                    }
                }
                .labelsHidden()
                .fixedSize()
                Text("most looked-up hosts from the")
                    .opacity(textOpacity)
                Picker("Look back", selection: daysBinding) {
                    ForEach(dayChoices, id: \.self) { days in
                        Text(days == 1 ? "last day" : "last \(days) days").tag(days)
                    }
                }
                .labelsHidden()
                .fixedSize()
            }
            .font(.system(size: 12))
            .padding(.top, 6)

            Text(reason ?? QueriesFormat.popularPrefetchImpact(count: settings.popularCount))
                .font(.system(size: 11))
                .foregroundStyle(Color.settingsSecondaryText)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 4)
        }
        .disabled(reason != nil)
        .padding(.leading, 28)
        .padding(.trailing, SettingsMetrics.rowHorizontalPadding)
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var countBinding: Binding<Int> {
        Binding(
            get: { settings.popularCount },
            set: { viewModel.queryHistorySettings.popularCount = $0 }
        )
    }

    private var daysBinding: Binding<Int> {
        Binding(
            get: { settings.popularDays },
            set: { viewModel.queryHistorySettings.popularDays = $0 }
        )
    }
}

/// Lettered badge standing in for each provider, not the providers' own logos.
private struct ProviderMark: View {
    let provider: DoHProviderID

    var body: some View {
        RoundedRectangle(cornerRadius: 9, style: .continuous)
            .fill(
                LinearGradient(
                    colors: [.settingsTileTop, .settingsTileBottom], startPoint: .top, endPoint: .bottom)
            )
            .frame(width: 34, height: 34)
            .overlay(
                Text(letters)
                    .font(.system(size: 13, weight: .heavy, design: .rounded))
                    .foregroundStyle(.white)
            )
            .accessibilityHidden(true)
    }

    private var letters: String {
        switch provider {
        case .cloudflare: return "CF"
        case .google: return "G"
        case .quad9: return "Q9"
        }
    }
}

extension DoHProviderID {
    var endpointHost: String {
        switch self {
        case .cloudflare: return "one.one.one.one"
        case .google: return "dns.google"
        case .quad9: return "dns.quad9.net"
        }
    }
}

#Preview {
    ResolverSection(viewModel: AppViewModel())
}

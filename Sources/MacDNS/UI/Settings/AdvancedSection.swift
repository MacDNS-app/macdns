// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import Shared
import SwiftUI

struct AdvancedSection: View {
    @ObservedObject var viewModel: AppViewModel
    @State private var isPerformingCleanup = false
    @State private var showCleanupConfirmation = false
    @State private var cleanupFailures: [String]? = nil
    @State private var uninstallFinished = false
    @State private var showClearHistoryConfirmation = false

    var body: some View {
        SettingsPage(.advanced) {
            VStack(alignment: .leading, spacing: 8) {
                SettingsSectionHeader("Logging", caption: "For troubleshooting")
                    .padding(.horizontal, 2)
                SettingsCard {
                    SettingsRow("Log Lookups", detail: "Records every domain this Mac looks up.") {
                        SettingsSwitch(isOn: $viewModel.logQueriesEnabled)
                    }
                    SettingsDivider()
                    SettingsRow("Log Answers", detail: "Records the address returned for each lookup.") {
                        SettingsSwitch(isOn: $viewModel.logRepliesEnabled)
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

            VStack(alignment: .leading, spacing: 8) {
                SettingsSectionHeader("Lookup History", caption: "Stored only on this Mac")
                    .padding(.horizontal, 2)
                LookupHistoryCard(viewModel: viewModel, onClear: { showClearHistoryConfirmation = true })
                    .requiresAgent(
                        isActive: viewModel.agentInstalled,
                        canTurnOn: viewModel.persistedStateAvailability.allowsUserEnable,
                        onTurnOn: { viewModel.enableDNS() }
                    )
            }

            VStack(alignment: .leading, spacing: 8) {
                SettingsSectionHeader("Danger Zone")
                    .padding(.horizontal, 2)
                SettingsCard(stroke: Color.statusCritical.opacity(0.35)) {
                    dangerZone
                        .padding(.horizontal, SettingsMetrics.rowHorizontalPadding)
                        .padding(.vertical, 10)
                }
            }
        }
        .clearHistoryConfirmation(isPresented: $showClearHistoryConfirmation, viewModel: viewModel)
    }

    private var dangerZone: some View {
        VStack(spacing: 4) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Uninstall MacDNS")
                        .font(.system(size: 13))
                    Text(
                        "Removes the agent, the system extensions and the network settings that setup installed. Turn protection on again to reinstall."
                    )
                    .font(.system(size: 11))
                    .foregroundStyle(Color.settingsSecondaryText)
                    .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                if isPerformingCleanup {
                    ProgressView()
                        .controlSize(.small)
                }
                Button(role: .destructive) {
                    showCleanupConfirmation = true
                } label: {
                    Text(isPerformingCleanup ? "Uninstalling…" : "Uninstall…")
                        .foregroundStyle(Color.statusCritical)
                }
                .disabled(isPerformingCleanup)
            }

            if uninstallFinished {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(
                        "macOS keeps the notification and local network permissions. Remove them in System Settings > Notifications and Privacy & Security > Local Network."
                    )
                    .font(.caption)
                    .foregroundStyle(Color.settingsSecondaryText)
                    .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("Open Notifications") {
                        NSWorkspace.shared.open(
                            URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension")!)
                    }
                    .controlSize(.small)
                }
                .padding(.top, 4)
            }

            if viewModel.cleanupRequiresRestart {
                Text("Restart your Mac to finish removing extensions.")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 4)
            }

            if let failures = cleanupFailures, !failures.isEmpty {
                Text("Failed: \(failures.joined(separator: ", "))")
                    .font(.caption)
                    .foregroundColor(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 4)
            }
        }
        .alert("Uninstall MacDNS?", isPresented: $showCleanupConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Uninstall", role: .destructive) {
                isPerformingCleanup = true
                cleanupFailures = nil
                uninstallFinished = false
                Task {
                    let failures = await viewModel.performFullCleanup()
                    cleanupFailures = failures.isEmpty ? nil : failures
                    uninstallFinished = true
                    isPerformingCleanup = false

                    if cleanupFailures != nil {
                        DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                            cleanupFailures = nil
                        }
                    }
                }
            }
        } message: {
            Text(
                "This removes the agent, the system extensions, the DNS and filter configurations and the background item. Turn protection on again to reinstall them.\n\nYour settings and license stay on this Mac."
            )
        }
    }
}

/// History switch, retention, size on disk and Clear History.
private struct LookupHistoryCard: View {
    @ObservedObject var viewModel: AppViewModel
    let onClear: () -> Void

    private var settings: QueryHistorySettings { viewModel.queryHistorySettings }
    private var canChangeSettings: Bool { viewModel.persistedStateAvailability.allowsConfigurationMutation }

    var body: some View {
        SettingsCard {
            SettingsRow(
                "Keep Lookup History",
                detail:
                    "Powers Queries, Blocked and Keep Popular Hosts Fresh. Turning it off stops recording and keeps what is stored."
            ) {
                SettingsSwitch(isOn: enabledBinding)
            }
            .disabled(!canChangeSettings)
            SettingsDivider()
            SettingsRow(
                "Keep For",
                detail:
                    "Older lookups are deleted. A shorter period also shortens how far back Keep Popular Hosts Fresh looks."
            ) {
                Picker("Keep For", selection: retentionBinding) {
                    ForEach(QueryHistorySettings.retentionDayChoices, id: \.self) { days in
                        Text("\(days) days").tag(days)
                    }
                }
                .labelsHidden()
                .fixedSize()
            }
            .disabled(!canChangeSettings || !settings.enabled)
            SettingsDivider()
            SettingsRow("Size on Disk", detail: droppedDetail) {
                Text(sizeText)
                    .font(.system(size: 13).monospacedDigit())
                    .foregroundStyle(Color.settingsSecondaryText)
                    .help(unavailableReason ?? "")
            }
            SettingsDivider()
            SettingsRow("Clear History", detail: "Deletes every lookup stored so far, with history on or off.") {
                Button(viewModel.queryHistoryClear.isClearing ? "Clearing…" : "Clear History…", action: onClear)
                    .disabled(viewModel.queryHistoryClear.isClearing)
            }
        }
        .onAppear {
            if viewModel.agentInstalled { viewModel.loadQueryHistoryStatus() }
        }
        .onChange(of: viewModel.queryHistoryClear.finishedCount) { viewModel.loadQueryHistoryStatus() }
        .onChange(of: settings) { viewModel.loadQueryHistoryStatus() }
        .onChange(of: viewModel.agentInstalled) { _, installed in
            if installed { viewModel.loadQueryHistoryStatus() }
        }
    }

    private var enabledBinding: Binding<Bool> {
        Binding(
            get: { settings.enabled },
            set: { viewModel.queryHistorySettings.enabled = $0 }
        )
    }

    private var retentionBinding: Binding<Int> {
        Binding(
            get: { settings.retentionDays },
            set: { viewModel.setQueryHistoryRetentionDays($0) }
        )
    }

    private var sizeText: String {
        guard settings.enabled else { return "Off" }
        switch viewModel.queryHistoryStatus {
        case .loaded(let status):
            return ByteCountFormatter.string(fromByteCount: Int64(status.sizeBytes), countStyle: .file)
        case .unavailable:
            return "Unavailable"
        case .disabled, .failed, nil:
            return "—"
        }
    }

    private var unavailableReason: String? {
        if case .unavailable(let reason) = viewModel.queryHistoryStatus { return reason }
        return nil
    }

    private var droppedDetail: String? {
        guard case .loaded(let status) = viewModel.queryHistoryStatus, status.droppedEvents > 0 else { return nil }
        return "\(status.droppedEvents.formatted()) lookups weren't recorded because the Mac was busy."
    }
}

#Preview {
    AdvancedSection(viewModel: AppViewModel())
}

// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import SwiftUI

struct ActivitySection: View {
    @ObservedObject var viewModel: AppViewModel
    var onNavigate: (SettingsSection) -> Void = { _ in }
    @State private var showClearConfirmation = false
    @State private var selectedCategory: BlocklistCategory? = nil
    @State private var timer: Timer? = nil
    @State private var showSuccessBanner = false
    @State private var successMessage = ""
    @State private var bannerGeneration = 0

    private var filteredStats: [BlockedDomain] {
        let filtered = viewModel.blocklistStats.filter { stat in
            selectedCategory.map { stat.category == $0 } ?? true
        }
        return filtered.sorted {
            $0.blockCount != $1.blockCount ? $0.blockCount > $1.blockCount : $0.domain < $1.domain
        }
    }

    var body: some View {
        let stats = filteredStats
        let summary = ActivitySummary(domains: stats)
        ZStack(alignment: .top) {
            SettingsPage(.activity) {
                HStack {
                    Spacer()
                    QueryHistoryRangePicker(range: $viewModel.activityRange)
                }
                .padding(.bottom, -10)

                HStack(alignment: .top, spacing: 10) {
                    SettingsFigureTile(
                        title: "Blocked Domains", value: summary.domainCount.formatted(), caption: "in the top 100")
                    SettingsFigureTile(
                        title: "Total Blocks", value: summary.totalBlocks.formatted(), caption: "across these domains")
                    SettingsFigureTile(
                        title: "Top Category", value: summary.topCategory?.rawValue ?? "—", caption: "by blocks",
                        compact: true)
                }
                .fixedSize(horizontal: false, vertical: true)

                SettingsGroup("Top Blocked Domains") {
                    toolbar
                } content: {
                    if let issue = viewModel.blocklistStatsIssue {
                        QueryHistoryIssueView(load: issue, onOpenAdvanced: { onNavigate(.advanced) })
                    } else if viewModel.isLoadingStats && viewModel.blocklistStats.isEmpty {
                        ProgressView()
                            .frame(maxWidth: .infinity, minHeight: 140)
                    } else if stats.isEmpty {
                        EditableListEmptyState(
                            symbol: "chart.bar.fill",
                            message: "Nothing blocked in the last \(viewModel.activityRange.periodName)", onAdd: nil)
                    } else {
                        let maxCount = stats.map(\.blockCount).max() ?? 0
                        ForEach(Array(stats.enumerated()), id: \.element.id) { index, stat in
                            if index > 0 {
                                SettingsDivider()
                            }
                            ActivityRow(
                                stat: stat,
                                maxCount: maxCount,
                                canAllow: viewModel.persistedStateAvailability.allowsConfigurationMutation,
                                onAllow: { allow(stat) }
                            )
                        }
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
                    viewModel.loadBlocklistStats()
                    startAutoRefresh()
                }
            }
            .onDisappear {
                stopAutoRefresh()
            }
            .onChange(of: viewModel.activityRange) {
                if viewModel.agentInstalled { viewModel.loadBlocklistStats() }
            }
            .onChange(of: viewModel.queryHistoryClear.finishedCount) {
                if viewModel.agentInstalled { viewModel.loadBlocklistStats() }
            }
            .clearHistoryConfirmation(isPresented: $showClearConfirmation, viewModel: viewModel)
            .onChange(of: viewModel.agentInstalled) { _, installed in
                if installed {
                    viewModel.loadBlocklistStats()
                    startAutoRefresh()
                } else {
                    stopAutoRefresh()
                }
            }

            if showSuccessBanner {
                ActivitySuccessBanner(message: successMessage) {
                    withAnimation { showSuccessBanner = false }
                }
                .transition(.move(edge: .top).combined(with: .opacity))
                .zIndex(1)
            }
        }
    }

    private var toolbar: some View {
        HStack(spacing: 8) {
            Picker("Filter", selection: $selectedCategory) {
                Text("All Categories").tag(nil as BlocklistCategory?)
                ForEach(BlocklistCategory.allCases, id: \.self) { category in
                    Text(category.rawValue).tag(category as BlocklistCategory?)
                }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .buttonStyle(.borderless)
            .fixedSize()

            Button(action: { viewModel.loadBlocklistStats() }) {
                if viewModel.isLoadingStats {
                    ProgressView()
                        .scaleEffect(0.5)
                        .frame(width: 16, height: 16)
                } else {
                    Image(systemName: "arrow.clockwise")
                }
            }
            .buttonStyle(.borderless)
            .help("Refresh statistics")

            Button("Clear") { showClearConfirmation = true }
                .disabled(viewModel.blocklistStats.isEmpty || viewModel.queryHistoryClear.isClearing)
                .help("Delete all lookup history on this Mac")
        }
    }

    private func allow(_ stat: BlockedDomain) {
        // matchedRule is the actual blocklist rule, which may be a parent of the domain.
        let ruleToAllow = stat.matchedRule
        guard viewModel.addToAllowlist(domain: ruleToAllow) else { return }

        successMessage = "'\(ruleToAllow)' added to allowlist"
        bannerGeneration += 1
        let generation = bannerGeneration
        withAnimation(.spring(response: 0.3, dampingFraction: 0.7)) {
            showSuccessBanner = true
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + UIConstants.bannerDuration) {
            guard generation == bannerGeneration else { return }
            withAnimation {
                showSuccessBanner = false
            }
        }
    }

    private func startAutoRefresh() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak viewModel] _ in
            Task { @MainActor in
                viewModel?.loadBlocklistStats()
            }
        }
    }

    private func stopAutoRefresh() {
        timer?.invalidate()
        timer = nil
    }
}

struct SettingsFigureTile: View {
    let title: String
    let value: String
    let caption: String
    var compact = false

    var body: some View {
        SettingsCard {
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.settingsSecondaryText)
                Text(value)
                    .font(.system(size: compact ? 15 : 20, weight: .bold).monospacedDigit())
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
                    .frame(height: 24, alignment: .bottomLeading)
                Text(caption)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.settingsTertiaryText)
            }
            .padding(.horizontal, 11)
            .padding(.vertical, 11)
            // Fills the row's height, so tiles side by side match the tallest.
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }
}

private struct ActivityRow: View {
    let stat: BlockedDomain
    let maxCount: Int
    let canAllow: Bool
    let onAllow: () -> Void

    private var barFraction: CGFloat {
        guard maxCount > 0 else { return 0 }
        return CGFloat(stat.blockCount) / CGFloat(maxCount)
    }

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 3) {
                    Text(stat.domain)
                        .font(.system(size: 13))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .onTapGesture { Clipboard.copy(stat.domain) }

                    if stat.domain != stat.matchedRule {
                        Image(systemName: "arrow.up.right")
                            .font(.system(size: 8, weight: .bold))
                            .foregroundStyle(Color.settingsSecondaryText)
                    }
                }
                .help(
                    stat.domain != stat.matchedRule
                        ? "Blocked parent: \(stat.matchedRule)"
                        : "Blocked: \(stat.domain)"
                )

                GeometryReader { geometry in
                    ZStack(alignment: .leading) {
                        Capsule().fill(Color.settingsSubtleFill)
                        Capsule()
                            .fill(Color.brandControl.opacity(0.75))
                            .frame(width: max(geometry.size.width * barFraction, 3))
                    }
                }
                .frame(height: 3)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            Text(stat.category.rawValue)
                .font(.system(size: 11))
                .foregroundStyle(Color.settingsSecondaryText)
                .lineLimit(1)
                .frame(width: 128, alignment: .trailing)

            Text(stat.blockCount.formatted())
                .font(.system(size: 13, weight: .semibold).monospacedDigit())
                .frame(width: 54, alignment: .trailing)

            Button("Allow", action: onAllow)
                .disabled(!canAllow)
                .help("Add '\(stat.matchedRule)' to allowlist")
        }
        .padding(.horizontal, SettingsMetrics.rowHorizontalPadding)
        .padding(.vertical, 9)
    }
}

private struct ActivitySuccessBanner: View {
    let message: String
    let onDismiss: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .font(.system(size: 16))

            Text(message)
                .font(.system(size: 13))
                .foregroundStyle(.primary)

            Spacer()

            Button(action: onDismiss) {
                Image(systemName: "xmark.circle.fill")
                    .foregroundStyle(Color.settingsSecondaryText)
                    .font(.system(size: 14))
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.green.opacity(0.18))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.green.opacity(0.4), lineWidth: 1)
                )
        )
        .shadow(color: .black.opacity(0.1), radius: 4, x: 0, y: 2)
        .padding(.horizontal, 16)
        .padding(.top, 16)
    }
}

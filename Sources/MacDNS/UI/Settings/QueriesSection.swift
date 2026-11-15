// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import SwiftUI

/// Insights > Queries: what this Mac looked up, read from the lookup history.
struct QueriesSection: View {
    @ObservedObject var viewModel: AppViewModel
    let onNavigate: (SettingsSection) -> Void
    @StateObject private var model = QueriesModel()
    @State private var showClearConfirmation = false

    private struct ReloadKey: Equatable {
        let agentInstalled: Bool
        let mode: QueriesModel.Mode
        let range: QueryHistoryRange
        let zoom: QueryHistoryZoom?
        let clears: Int
    }

    private struct AutoRefreshKey: Equatable {
        let reload: ReloadKey
        let interval: Int
    }

    private var reloadKey: ReloadKey {
        ReloadKey(
            agentInstalled: viewModel.agentInstalled,
            mode: model.mode,
            range: model.range,
            zoom: model.zoom,
            clears: viewModel.queryHistoryClear.finishedCount
        )
    }

    var body: some View {
        SettingsPage(.queries, lede: "Every name this Mac looked up, what answered it, and what MacDNS blocked.") {
            QueriesHeader(
                mode: $model.mode, range: $model.range, zoom: $model.zoom,
                refreshInterval: $viewModel.queriesRefreshInterval,
                isHistoryOn: viewModel.queryHistorySettings.enabled)
            switch model.mode {
            case .summary:
                QueriesSummaryContent(model: model, viewModel: viewModel, onNavigate: onNavigate)
            case .log:
                QueriesLogGroup(
                    model: model, viewModel: viewModel, isHistoryOn: viewModel.queryHistorySettings.enabled,
                    onOpenAdvanced: { onNavigate(.advanced) })
            }
        } footer: {
            QueriesFooter(
                viewModel: viewModel,
                onOpenAdvanced: { onNavigate(.advanced) },
                onClear: { showClearConfirmation = true }
            )
        }
        .requiresAgent(
            isActive: viewModel.agentInstalled,
            canTurnOn: viewModel.persistedStateAvailability.allowsUserEnable,
            onTurnOn: { viewModel.enableDNS() }
        )
        .clearHistoryConfirmation(isPresented: $showClearConfirmation, viewModel: viewModel)
        .task(id: reloadKey) {
            guard viewModel.agentInstalled else { return }
            viewModel.loadQueryHistoryStatus()
            await model.refresh(isAutomatic: false)
        }
        .task(id: AutoRefreshKey(reload: reloadKey, interval: viewModel.queriesRefreshInterval)) {
            // A zoomed bar is a fixed period, so the page holds still until Reset.
            guard viewModel.agentInstalled, model.zoom == nil else { return }
            let interval = viewModel.queriesRefreshInterval
            // Runs only while the page is on screen. A new interval or reload
            // restarts the wait. A tick that finds a request still running is
            // skipped, so refreshes never overlap.
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(interval))
                guard !Task.isCancelled, !model.isLoading else { continue }
                viewModel.loadQueryHistoryStatus()
                await model.refresh(isAutomatic: true)
            }
        }
    }
}

private struct QueriesHeader: View {
    @Binding var mode: QueriesModel.Mode
    @Binding var range: QueryHistoryRange
    @Binding var zoom: QueryHistoryZoom?
    @Binding var refreshInterval: Int
    let isHistoryOn: Bool

    var body: some View {
        HStack {
            SegmentedPicker("View", selection: $mode) {
                ForEach(QueriesModel.Mode.allCases, id: \.self) { mode in
                    Text(mode.rawValue).tag(mode)
                }
            }
            .labelsHidden()
            .fixedSize()
            .tint(nil)
            Spacer()
            Group {
                // While zoomed, Reset is the way back. The page does not refresh.
                if let zoom {
                    QueriesZoomBadge(zoom: zoom, range: range, onReset: { self.zoom = nil })
                } else {
                    if mode == .summary {
                        QueryHistoryRangePicker(range: $range)
                    }
                    Picker("Refresh", selection: $refreshInterval) {
                        ForEach(QueriesAutoRefresh.intervalChoices, id: \.self) { seconds in
                            Text("\(seconds)s").tag(seconds)
                        }
                    }
                    .pickerStyle(.menu)
                    .fixedSize()
                    .help("How often this page reloads while it is open")
                }
            }
            .disabled(!isHistoryOn)
        }
        .padding(.bottom, -8)
    }
}

/// The zoomed bar and the way back to the whole range.
private struct QueriesZoomBadge: View {
    let zoom: QueryHistoryZoom
    let range: QueryHistoryRange
    let onReset: () -> Void

    var body: some View {
        HStack(spacing: 6) {
            Label(QueriesFormat.zoomTitle(zoom), systemImage: "plus.magnifyingglass")
                .font(.system(size: 12, weight: .medium))
                .lineLimit(1)
            Button("Reset", action: onReset)
                .controlSize(.small)
                .help("Back to the last \(range.periodName)")
        }
        .fixedSize()
    }
}

private struct QueriesSummaryContent: View {
    @ObservedObject var model: QueriesModel
    @ObservedObject var viewModel: AppViewModel
    let onNavigate: (SettingsSection) -> Void

    var body: some View {
        switch model.summary {
        case nil:
            ProgressView()
                .frame(maxWidth: .infinity, minHeight: 200)
        case .loaded(let summary) where summary.total == 0:
            SettingsCard {
                EditableListEmptyState(
                    symbol: "chart.bar.xaxis",
                    message: model.zoom == nil
                        ? "No lookups yet \(model.period.phrase)" : "No lookups \(model.period.phrase)",
                    onAdd: nil
                )
            }
        case .loaded(let summary):
            QueriesSummaryView(summary: summary, model: model, viewModel: viewModel, onNavigate: onNavigate)
        case .some(let issue):
            SettingsCard {
                QueryHistoryIssueView(load: issue, onOpenAdvanced: { onNavigate(.advanced) })
            }
        }
    }
}

private struct QueriesFooter: View {
    @ObservedObject var viewModel: AppViewModel
    let onOpenAdvanced: () -> Void
    let onClear: () -> Void

    private var settings: QueryHistorySettings { viewModel.queryHistorySettings }

    private var text: String {
        let kept = "Kept on this Mac for \(settings.retentionDays) days"
        guard case .loaded(let status) = viewModel.queryHistoryStatus else { return kept }
        let size = ByteCountFormatter.string(fromByteCount: Int64(status.sizeBytes), countStyle: .file)
        return "\(kept) · \(size)"
    }

    var body: some View {
        // With history off, the page's own card is the one way to Advanced.
        if settings.enabled {
            HStack(spacing: 8) {
                Text(text)
                    .font(.system(size: 11.5))
                    .foregroundStyle(Color.settingsSecondaryText)
                    .lineLimit(1)
                Button("Change in Advanced", action: onOpenAdvanced)
                    .buttonStyle(.link)
                    .font(.system(size: 11.5))
                    .fixedSize()
                Spacer(minLength: 8)
                Button(viewModel.queryHistoryClear.isClearing ? "Clearing…" : "Clear History…", action: onClear)
                    .disabled(viewModel.queryHistoryClear.isClearing)
                    .fixedSize()
            }
        }
    }
}

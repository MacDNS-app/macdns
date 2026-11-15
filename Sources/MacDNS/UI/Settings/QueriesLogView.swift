// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import SwiftUI

/// The Log view of Queries: single lookups from the last 7 days or from the
/// zoomed bar, newest first.
struct QueriesLogGroup: View {
    @ObservedObject var model: QueriesModel
    @ObservedObject var viewModel: AppViewModel
    let isHistoryOn: Bool
    let onOpenAdvanced: () -> Void
    @State private var isLoadingMore = false
    @State private var addingRecord: String?

    var body: some View {
        SettingsGroup("Lookups", caption: caption) {
            QueriesFilterControls(query: $model.logQuery, result: $model.logResult)
                .disabled(!isHistoryOn)
        } content: {
            switch model.log {
            case nil:
                ProgressView()
                    .frame(maxWidth: .infinity, minHeight: 200)
            case .loaded(let entries) where entries.isEmpty:
                QueriesCardNote(emptyNote)
            case .loaded(let entries):
                QueriesLogHeader()
                LazyVStack(spacing: 0) {
                    ForEach(entries) { entry in
                        SettingsDivider(inset: 0)
                        QueriesLogRow(entry: entry)
                            .contextMenu {
                                QueriesHostMenu(
                                    name: entry.name, blockRule: entry.blockRule, viewModel: viewModel,
                                    onAddLocalRecord: { addingRecord = String(entry.id) })
                            }
                            .queriesAddLocalRecordPopover(
                                host: entry.name, lookupType: QueriesFormat.recordType(entry.qtype),
                                presented: $addingRecord, id: String(entry.id), viewModel: viewModel)
                    }
                }
                if model.logHasMore {
                    SettingsDivider(inset: 0)
                    Button(isLoadingMore ? "Loading…" : "Show Older Lookups") {
                        isLoadingMore = true
                        Task {
                            await model.loadMoreLog()
                            isLoadingMore = false
                        }
                    }
                    .buttonStyle(.link)
                    .font(.system(size: 12))
                    .disabled(isLoadingMore)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
            case .some(let issue):
                QueryHistoryIssueView(load: issue, onOpenAdvanced: onOpenAdvanced)
            }
        }
    }
}

extension QueriesLogGroup {
    /// A zoomed log names its period in the page header.
    private var caption: String {
        model.zoom == nil ? "Last \(QueriesPeriod.singleLookupDays) days, newest first" : "Newest first"
    }

    private var emptyNote: String {
        let keptSince = Int(Date().timeIntervalSince1970) - QueriesPeriod.singleLookupDays * 86_400
        guard let zoom = model.zoom, zoom.start < keptSince else { return "No lookups match." }
        return "Single lookups are kept for \(QueriesPeriod.singleLookupDays) days, so this day has none left."
    }
}

/// Fixed columns sized to their longest common value, so the host keeps the rest of the row.
private enum QueriesLogColumns {
    static let spacing: CGFloat = 5
    static let time: CGFloat = 60
    static let type: CGFloat = 42
    static let result: CGFloat = 66
    static let answeredBy: CGFloat = 80
    static let milliseconds: CGFloat = 34
}

private struct QueriesLogHeader: View {
    var body: some View {
        HStack(spacing: QueriesLogColumns.spacing) {
            Text("Time").frame(width: QueriesLogColumns.time, alignment: .leading)
            Text("Host").frame(maxWidth: .infinity, alignment: .leading)
            Text("Type").frame(width: QueriesLogColumns.type, alignment: .leading)
            Text("Result").frame(width: QueriesLogColumns.result, alignment: .leading)
            Text("Answered By").frame(width: QueriesLogColumns.answeredBy, alignment: .leading)
            Text("ms").frame(width: QueriesLogColumns.milliseconds, alignment: .trailing)
        }
        .font(.system(size: 11, weight: .semibold))
        .foregroundStyle(Color.settingsSecondaryText)
        .padding(.horizontal, SettingsMetrics.rowHorizontalPadding)
        .padding(.vertical, 7)
    }
}

private struct QueriesLogRow: View {
    let entry: QueryHistoryLog.Entry

    var body: some View {
        HStack(spacing: QueriesLogColumns.spacing) {
            Text(QueriesFormat.time(entry.ts).formatted(date: .omitted, time: .standard))
                .foregroundStyle(Color.settingsSecondaryText)
                .monospacedDigit()
                .lineLimit(1)
                .frame(width: QueriesLogColumns.time, alignment: .leading)
            Text(entry.name)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: .infinity, alignment: .leading)
                .help(entry.name)
                .onTapGesture { Clipboard.copy(entry.name) }
            Text(QueriesFormat.recordType(entry.qtype))
                .font(.system(size: 10.5, weight: .semibold))
                .foregroundStyle(Color.brandSmallText)
                .padding(.horizontal, 3)
                .padding(.vertical, 1)
                .background(Capsule().fill(Color.brandControl.opacity(0.12)))
                .fixedSize()
                .frame(width: QueriesLogColumns.type, alignment: .leading)
            QueryOutcomePill(outcome: QueryOutcome(route: entry.route, rcode: entry.rcode))
                .frame(width: QueriesLogColumns.result, alignment: .leading)
            Text(QueriesFormat.answeredBy(route: entry.route, provider: entry.provider))
                .lineLimit(1)
                .frame(width: QueriesLogColumns.answeredBy, alignment: .leading)
                .help(entry.blockRule.isEmpty ? "" : "Blocked by \(entry.blockRule)")
            Text(QueriesFormat.logLatency(entry.latencyMs))
                .foregroundStyle(Color.settingsSecondaryText)
                .monospacedDigit()
                .lineLimit(1)
                .fixedSize()
                .frame(width: QueriesLogColumns.milliseconds, alignment: .trailing)
        }
        .font(.system(size: 12))
        .padding(.horizontal, SettingsMetrics.rowHorizontalPadding)
        .padding(.vertical, 6)
    }
}

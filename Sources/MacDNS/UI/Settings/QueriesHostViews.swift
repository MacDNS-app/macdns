// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Charts
import Shared
import SwiftUI

/// Top Hosts with its filters. A click on a host opens its detail below it.
struct QueriesTopHostsGroup: View {
    @ObservedObject var model: QueriesModel
    @ObservedObject var viewModel: AppViewModel
    @State private var addingRecord: String?

    var body: some View {
        SettingsGroup("Top Hosts") {
            QueriesFilterControls(query: $model.hostQuery, result: $model.hostResult)
        } content: {
            switch model.hosts {
            case nil:
                ProgressView()
                    .frame(maxWidth: .infinity, minHeight: 120)
            case .loaded(let top) where top.hosts.isEmpty:
                QueriesCardNote("No hosts match.")
            case .loaded(let top):
                hostRows(top)
            case .some:
                QueriesCardNote("Couldn't load the hosts. This page tries again on its own.")
            }
        }
    }

    @ViewBuilder
    private func hostRows(_ top: QueryHistoryTopHosts) -> some View {
        let maxCount = top.hosts.map(\.count).max() ?? 0
        ForEach(Array(top.hosts.enumerated()), id: \.element.name) { index, host in
            if index > 0 {
                SettingsDivider()
            }
            let isExpanded = model.expandedHost == host.name
            QueriesHostRow(host: host, maxCount: maxCount, isExpanded: isExpanded)
                .onTapGesture { model.expandedHost = isExpanded ? nil : host.name }
                .contextMenu {
                    QueriesHostMenu(
                        name: host.name, blockRule: host.blockRule, viewModel: viewModel,
                        onAddLocalRecord: { addingRecord = host.name })
                }
                .queriesAddLocalRecordPopover(
                    host: host.name, lookupType: nil, presented: $addingRecord, id: host.name, viewModel: viewModel)
            if isExpanded {
                QueriesHostDetail(host: host, detail: model.hostDetail, period: model.period, viewModel: viewModel)
            }
        }
        if top.totalHosts > top.hosts.count {
            SettingsDivider(inset: 0)
            HStack {
                Text("Showing \(top.hosts.count.formatted()) of \(top.totalHosts.formatted()) hosts")
                    .foregroundStyle(Color.settingsSecondaryText)
                Spacer()
                if let next = QueriesPaging.nextHostLimit(shown: top.hosts.count, totalHosts: top.totalHosts) {
                    Button("Show \(min(next, top.totalHosts) - top.hosts.count) More") { model.hostLimit = next }
                        .buttonStyle(.link)
                }
            }
            .font(.system(size: 12))
            .padding(.horizontal, SettingsMetrics.rowHorizontalPadding)
            .padding(.vertical, 8)
        }
    }
}

/// Name filter and result menu, shared by Top Hosts and the Log.
struct QueriesFilterControls: View {
    @Binding var query: String
    @Binding var result: QueryHistoryResultFilter

    var body: some View {
        HStack(spacing: 8) {
            TextField("Filter hosts", text: $query)
                .textFieldStyle(.roundedBorder)
                .controlSize(.small)
                .frame(width: 150)
            Picker("Result", selection: $result) {
                ForEach(QueryHistoryResultFilter.allCases, id: \.self) { filter in
                    Text(filter.title).tag(filter)
                }
            }
            .labelsHidden()
            .controlSize(.small)
            .fixedSize()
        }
    }
}

private struct QueriesHostRow: View {
    let host: QueryHistoryTopHosts.Host
    let maxCount: Int
    let isExpanded: Bool

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 5) {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundStyle(Color.settingsSecondaryText)
                        .frame(width: 10)
                    Text(host.name)
                        .font(.system(size: 13))
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                QueriesHostBar(host: host, maxCount: maxCount)
                    .padding(.leading, 15)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            QueryOutcomePill(outcome: QueryOutcome.dominant(in: host))
                .frame(width: 76, alignment: .leading)
            Text(host.count.formatted())
                .font(.system(size: 13, weight: .semibold).monospacedDigit())
                .frame(width: 58, alignment: .trailing)
            Text(
                QueriesFormat.time(host.lastSeen).formatted(.relative(presentation: .numeric, unitsStyle: .abbreviated))
            )
            .font(.system(size: 11))
            .foregroundStyle(Color.settingsSecondaryText)
            .lineLimit(1)
            .frame(width: 76, alignment: .trailing)
        }
        .padding(.horizontal, SettingsMetrics.rowHorizontalPadding)
        .padding(.vertical, 8)
        .contentShape(Rectangle())
        .accessibilityAddTraits(.isButton)
        .accessibilityHint(isExpanded ? "Hides details" : "Shows details")
    }
}

/// How the host's lookups were answered, scaled to the busiest host.
private struct QueriesHostBar: View {
    let host: QueryHistoryTopHosts.Host
    let maxCount: Int

    private var segments: [(color: Color, count: Int)] {
        let other = max(0, host.count - host.cache - host.provider - host.blocked)
        return [
            (.historyCache, host.cache), (.brandControl, host.provider), (.statusCritical, host.blocked),
            (.historyOther, other),
        ]
    }

    var body: some View {
        GeometryReader { geometry in
            HStack(spacing: 0) {
                ForEach(Array(segments.enumerated()), id: \.offset) { _, segment in
                    Rectangle()
                        .fill(segment.color)
                        .frame(width: width(segment.count, in: geometry.size.width))
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.settingsSubtleFill)
            .clipShape(Capsule())
        }
        .frame(height: 3)
    }

    private func width(_ count: Int, in total: CGFloat) -> CGFloat {
        guard maxCount > 0 else { return 0 }
        return total * CGFloat(count) / CGFloat(maxCount)
    }
}

private struct QueriesHostDetail: View {
    let host: QueryHistoryTopHosts.Host
    let detail: QueryHistoryLoad<QueryHistoryHostDetail>?
    let period: QueriesPeriod
    @ObservedObject var viewModel: AppViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            switch detail {
            case nil:
                ProgressView()
                    .controlSize(.small)
                    .frame(maxWidth: .infinity)
            case .loaded(let detail):
                QueriesHostFacts(detail: detail, period: period)
            case .some:
                Text("Couldn't load details for this host.")
                    .font(.system(size: 12))
                    .foregroundStyle(Color.settingsSecondaryText)
            }
            QueriesHostActions(host: host, viewModel: viewModel)
        }
        .padding(.horizontal, SettingsMetrics.rowHorizontalPadding)
        .padding(.vertical, 12)
        .background(Color.settingsSubtleFill)
    }
}

private struct QueriesHostFacts: View {
    let detail: QueryHistoryHostDetail
    let period: QueriesPeriod

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                QueriesFactLabel("Lookups \(period.phrase)")
                QueriesSparkline(series: detail.series)
            }
            Grid(alignment: .topLeading, horizontalSpacing: 18, verticalSpacing: 8) {
                GridRow {
                    QueriesFact("First seen", value: detail.firstSeen.map(dateText) ?? "—")
                    QueriesFact("Last seen", value: detail.lastSeen.map(dateText) ?? "—")
                }
                GridRow {
                    QueriesFact(
                        "Answered by",
                        value: QueriesFormat.answerSources(routes: detail.routes, providers: detail.providers))
                    QueriesFact(
                        "Record types",
                        value: detail.qtypes.map { QueriesFormat.recordType($0.qtype) }.joined(separator: ", "))
                }
                if !detail.blockRule.isEmpty {
                    GridRow {
                        QueriesFact("Blocked by", value: blockedBy)
                            .gridCellColumns(2)
                    }
                }
            }
        }
    }

    private var blockedBy: String {
        guard let category = BlocklistCategory.fromIdentifier(detail.blockCategory) else { return detail.blockRule }
        return "\(detail.blockRule) · \(category.rawValue)"
    }

    private func dateText(_ seconds: Int) -> String {
        QueriesFormat.time(seconds).formatted(.dateTime.month(.abbreviated).day().hour().minute())
    }
}

private struct QueriesHostActions: View {
    let host: QueryHistoryTopHosts.Host
    @ObservedObject var viewModel: AppViewModel
    @State private var addingRecord: String?

    var body: some View {
        HStack(spacing: 8) {
            if !host.blockRule.isEmpty {
                QueriesAllowButton(blockRule: host.blockRule, viewModel: viewModel)
                    .buttonStyle(.borderedProminent)
            }
            QueriesBlockButton(name: host.name, viewModel: viewModel)
            Button("Add Local Record…") { addingRecord = host.name }
                .disabled(!viewModel.persistedStateAvailability.allowsConfigurationMutation)
                .queriesAddLocalRecordPopover(
                    host: host.name, lookupType: nil, presented: $addingRecord, id: host.name, viewModel: viewModel)
            Button("Copy Name") { Clipboard.copy(host.name) }
        }
        .controlSize(.small)
    }
}

private struct QueriesSparkline: View {
    let series: [QueryHistoryHostDetail.Bucket]

    var body: some View {
        Chart(Array(series.enumerated()), id: \.offset) { index, bucket in
            AreaMark(x: .value("Bucket", index), y: .value("Lookups", bucket.count))
                .foregroundStyle(Color.brandControl.opacity(0.15))
            LineMark(x: .value("Bucket", index), y: .value("Lookups", bucket.count))
                .foregroundStyle(Color.brandControl)
                .lineStyle(StrokeStyle(lineWidth: 1.5))
        }
        .chartXAxis(.hidden)
        .chartYAxis(.hidden)
        .frame(height: 38)
    }
}

private struct QueriesFact: View {
    let title: String
    let value: String

    init(_ title: String, value: String) {
        self.title = title
        self.value = value
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            QueriesFactLabel(title)
            Text(value.isEmpty ? "—" : value)
                .font(.system(size: 12))
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct QueriesFactLabel: View {
    let text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(.system(size: 11))
            .foregroundStyle(Color.settingsSecondaryText)
    }
}

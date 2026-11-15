// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Charts
import Shared
import SwiftUI

/// The Summary view of Queries for one range that has lookups.
struct QueriesSummaryView: View {
    let summary: QueryHistorySummary
    @ObservedObject var model: QueriesModel
    @ObservedObject var viewModel: AppViewModel
    let onNavigate: (SettingsSection) -> Void

    var body: some View {
        // A Group, so each card keeps the page's spacing.
        Group {
            QueriesFigureTiles(summary: summary, period: model.period)
            SettingsGroup("Lookups Over Time") {
                QueriesChartLegend()
            } content: {
                QueriesLookupsChart(series: summary.series, period: model.period, onZoom: model.zoomIn(at:))
                    .padding(12)
            }
            QueriesTopHostsGroup(model: model, viewModel: viewModel)
            HStack(alignment: .top, spacing: 10) {
                QueriesProvidersGroup(providers: summary.providers)
                QueriesAnswersGroup(answers: summary.answers)
            }
            .fixedSize(horizontal: false, vertical: true)
            if let keptFresh = summary.keptFresh {
                QueriesKeptFreshGroup(
                    keptFresh: keptFresh,
                    days: viewModel.queryHistorySettings.popularDays,
                    onChange: { onNavigate(.resolver) }
                )
            }
            if !summary.firstSeen.isEmpty {
                QueriesFirstSeenGroup(names: summary.firstSeen, range: model.period.bucketRange)
            }
        }
    }
}

private struct QueriesFigureTiles: View {
    let summary: QueryHistorySummary
    let period: QueriesPeriod

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            SettingsFigureTile(
                title: "Lookups", value: summary.total.formatted(),
                caption: QueriesFormat.periodChange(
                    total: summary.total, previous: summary.previousTotal, period: period))
            SettingsFigureTile(
                title: "Blocked", value: summary.blocked.formatted(),
                caption: "\(QueriesFormat.share(summary.blocked, of: summary.total)) of lookups")
            SettingsFigureTile(
                title: "From Cache", value: QueriesFormat.share(summary.cache, of: summary.total),
                caption: "no network wait")
            SettingsFigureTile(
                title: "Response Time", value: QueriesFormat.milliseconds(summary.avgLatencyMs),
                caption: summary.provider > 0
                    ? "providers: \(QueriesFormat.milliseconds(summary.avgProviderLatencyMs))"
                    : "all from this Mac")
        }
        .fixedSize(horizontal: false, vertical: true)
    }
}

/// The four ways a lookup is counted in the chart, stacked bottom to top.
private enum QueriesChartSource: String, CaseIterable {
    case cache = "Cache"
    case provider = "Provider"
    case blocked = "Blocked"
    case other = "Other"

    var color: Color {
        switch self {
        case .cache: return .historyCache
        case .provider: return .brandControl
        case .blocked: return .statusCritical
        case .other: return .historyOther
        }
    }

    func count(in bucket: QueryHistorySummary.Bucket) -> Int {
        switch self {
        case .cache: return bucket.cache
        case .provider: return bucket.provider
        case .blocked: return bucket.blocked
        case .other: return bucket.other
        }
    }
}

private struct QueriesChartLegend: View {
    var body: some View {
        HStack(spacing: 12) {
            ForEach(QueriesChartSource.allCases, id: \.self) { source in
                HStack(spacing: 4) {
                    RoundedRectangle(cornerRadius: 2).fill(source.color).frame(width: 8, height: 8)
                    Text(source.rawValue)
                }
            }
        }
        .font(.system(size: 11))
        .foregroundStyle(Color.settingsSecondaryText)
        .help("Other: local records, forward zones, built-in answers and failed lookups.")
    }
}

/// Stacked bars per bucket, with the bucket's numbers on hover. A click
/// zooms into the bar when it has a finer view.
private struct QueriesLookupsChart: View {
    let series: [QueryHistorySummary.Bucket]
    let period: QueriesPeriod
    let onZoom: (Int) -> Void
    @State private var selectedLabel: String?

    private struct Bar: Identifiable {
        let label: String
        let source: QueriesChartSource
        let count: Int
        var id: String { label + source.rawValue }
    }

    private var labels: [String] { series.map { label(for: $0.start) } }

    private var bars: [Bar] {
        zip(series, labels).flatMap { bucket, label in
            QueriesChartSource.allCases.map { Bar(label: label, source: $0, count: $0.count(in: bucket)) }
        }
    }

    /// About eight labels on the axis, whatever the range.
    private var axisLabels: [String] {
        let step = max(1, Int((Double(labels.count) / 8).rounded(.up)))
        return labels.enumerated().filter { $0.offset % step == 0 }.map(\.element)
    }

    var body: some View {
        Chart {
            ForEach(bars) { bar in
                BarMark(x: .value("Time", bar.label), y: .value("Lookups", bar.count), width: .ratio(0.75))
                    .foregroundStyle(by: .value("Answered by", bar.source.rawValue))
            }
            if let selectedLabel, let index = labels.firstIndex(of: selectedLabel) {
                RuleMark(x: .value("Time", selectedLabel))
                    .foregroundStyle(Color.settingsSecondaryText.opacity(0.35))
                    .annotation(position: .top, overflowResolution: .init(x: .fit(to: .chart), y: .fit(to: .chart))) {
                        QueriesChartTooltip(
                            label: selectedLabel, bucket: series[index], zoomHint: zoomHint(series[index].start))
                    }
            }
        }
        .chartForegroundStyleScale(
            domain: QueriesChartSource.allCases.map(\.rawValue),
            range: QueriesChartSource.allCases.map(\.color)
        )
        .chartLegend(.hidden)
        .chartXSelection(value: $selectedLabel)
        // Simultaneous, so the chart's own selection keeps working.
        .simultaneousGesture(
            TapGesture().onEnded {
                guard let selectedLabel, let index = labels.firstIndex(of: selectedLabel) else { return }
                onZoom(series[index].start)
            }
        )
        .chartXAxis {
            AxisMarks(values: axisLabels) { _ in
                AxisValueLabel()
            }
        }
        .chartYAxis {
            AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) { _ in
                AxisGridLine()
                AxisValueLabel()
            }
        }
        .frame(height: 150)
    }

    private func zoomHint(_ start: Int) -> String? {
        switch period.zoom(into: start, now: Int(Date().timeIntervalSince1970))?.span {
        case nil: return nil
        case .day: return "Click to see this day"
        case .hour: return "Click to see this hour"
        }
    }

    private func label(for start: Int) -> String {
        let date = QueriesFormat.time(start)
        switch period.bucketRange {
        case .hour: return date.formatted(date: .omitted, time: .shortened)
        case .day: return date.formatted(.dateTime.hour())
        case .week: return date.formatted(.dateTime.weekday(.abbreviated).day())
        case .month: return date.formatted(.dateTime.month(.abbreviated).day())
        }
    }
}

private struct QueriesChartTooltip: View {
    let label: String
    let bucket: QueryHistorySummary.Bucket
    let zoomHint: String?

    private var total: Int { QueriesChartSource.allCases.reduce(0) { $0 + $1.count(in: bucket) } }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 12, weight: .semibold))
            Text("\(total.formatted()) lookups")
            Text(
                QueriesChartSource.allCases
                    .filter { $0 != .other || bucket.other > 0 }
                    .map { "\($0.rawValue) \($0.count(in: bucket).formatted())" }
                    .joined(separator: " · ")
            )
            .foregroundStyle(Color.settingsSecondaryText)
            if let zoomHint {
                Text(zoomHint)
                    .foregroundStyle(Color.settingsTertiaryText)
            }
        }
        .font(.system(size: 11))
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 7).fill(Color.settingsCard)
                .shadow(color: .black.opacity(0.15), radius: 6, y: 2)
        )
        .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Color.settingsCardStroke))
    }
}

private struct QueriesProvidersGroup: View {
    let providers: [QueryHistorySummary.Provider]

    private var totalAnswers: Int { providers.reduce(0) { $0 + $1.answers } }

    var body: some View {
        SettingsGroup("Providers") {
            if providers.isEmpty {
                QueriesCardNote("No provider answered a lookup in this period.")
            } else {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                    GridRow {
                        Text("Provider")
                        Text("Answered").gridColumnAlignment(.trailing)
                        Text("Average").gridColumnAlignment(.trailing)
                    }
                    .font(.system(size: 11))
                    .foregroundStyle(Color.settingsSecondaryText)
                    ForEach(providers, id: \.name) { provider in
                        GridRow {
                            Text(provider.name)
                            Text(QueriesFormat.share(provider.answers, of: totalAnswers))
                            Text(QueriesFormat.milliseconds(provider.avgLatencyMs))
                        }
                        .font(.system(size: 12).monospacedDigit())
                    }
                }
                .padding(.horizontal, 12)
                .padding(.top, 10)
                QueriesCardNote("Answered: the share of provider answers that came from each one.")
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }
}

private struct QueriesAnswersGroup: View {
    let answers: QueryHistorySummary.Answers

    private func count(_ outcome: QueryOutcome) -> Int {
        switch outcome {
        case .answered: return answers.answered
        case .blocked: return answers.blocked
        case .notFound: return answers.notFound
        case .failed: return answers.failed
        }
    }

    private var total: Int { QueryOutcome.allCases.reduce(0) { $0 + count($1) } }

    var body: some View {
        SettingsGroup("Answers") {
            GeometryReader { geometry in
                HStack(spacing: 0) {
                    ForEach(QueryOutcome.allCases, id: \.self) { outcome in
                        Rectangle()
                            .fill(outcome.color)
                            .frame(
                                width: total > 0 ? geometry.size.width * CGFloat(count(outcome)) / CGFloat(total) : 0)
                    }
                }
            }
            .frame(height: 8)
            .clipShape(Capsule())
            .padding(.horizontal, 12)
            .padding(.top, 12)

            Grid(alignment: .leading, horizontalSpacing: 8, verticalSpacing: 4) {
                ForEach(QueryOutcome.allCases, id: \.self) { outcome in
                    GridRow {
                        RoundedRectangle(cornerRadius: 2).fill(outcome.color).frame(width: 8, height: 8)
                        Text(outcome.title)
                        Text("\(count(outcome).formatted()) · \(QueriesFormat.share(count(outcome), of: total))")
                            .monospacedDigit()
                            .frame(maxWidth: .infinity, alignment: .trailing)
                    }
                }
            }
            .font(.system(size: 12))
            .padding(12)
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }
}

private struct QueriesKeptFreshGroup: View {
    let keptFresh: QueryHistorySummary.KeptFresh
    let days: Int
    let onChange: () -> Void

    var body: some View {
        SettingsGroup("Kept Fresh") {
            Button("Change in DNS Providers", action: onChange)
                .buttonStyle(.link)
                .font(.system(size: 12))
        } content: {
            Text(
                "Prefetch keeps the top \(keptFresh.popularCount.formatted()) hosts from the \(days == 1 ? "last day" : "last \(days) days") ready, even when nothing asked for them recently."
            )
            .font(.system(size: 12))
            .foregroundStyle(Color.settingsSecondaryText)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 12)
            .padding(.top, 10)
            HStack(spacing: 10) {
                QueriesMiniFigure(
                    title: "Ready now", value: keptFresh.inCache.formatted(),
                    suffix: " / \(keptFresh.popularCount.formatted())")
                QueriesMiniFigure(title: "Answered instantly", value: keptFresh.cacheAnswers.formatted(), suffix: nil)
                QueriesMiniFigure(
                    title: "Extra provider traffic", value: String(format: "%.1f", keptFresh.refreshesPerSecond),
                    suffix: "/s")
            }
            .padding(12)
        }
    }
}

private struct QueriesMiniFigure: View {
    let title: String
    let value: String
    let suffix: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.system(size: 11))
                .foregroundStyle(Color.settingsSecondaryText)
            (Text(value).font(.system(size: 17, weight: .bold))
                + Text(suffix ?? "").font(.system(size: 11, weight: .medium)).foregroundStyle(
                    Color.settingsTertiaryText))
                .monospacedDigit()
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.settingsSubtleFill))
    }
}

private struct QueriesFirstSeenGroup: View {
    let names: [QueryHistorySummary.FirstSeen]
    let range: QueryHistoryRange

    var body: some View {
        SettingsGroup("First Seen in This Period", caption: "Names this Mac never looked up before") {
            ForEach(Array(names.enumerated()), id: \.element.name) { index, name in
                if index > 0 { SettingsDivider() }
                HStack(spacing: 10) {
                    Text(name.name)
                        .font(.system(size: 13))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    QueryOutcomePill(outcome: name.blocked ? .blocked : .answered)
                        .frame(width: 76, alignment: .leading)
                    Text(name.count.formatted())
                        .font(.system(size: 13, weight: .semibold).monospacedDigit())
                        .frame(width: 58, alignment: .trailing)
                    Text("first \(firstSeen(name.firstSeen))")
                        .font(.system(size: 11))
                        .foregroundStyle(Color.settingsSecondaryText)
                        .frame(width: 110, alignment: .trailing)
                }
                .padding(.horizontal, SettingsMetrics.rowHorizontalPadding)
                .padding(.vertical, 8)
            }
        }
    }

    private func firstSeen(_ seconds: Int) -> String {
        let date = QueriesFormat.time(seconds)
        switch range {
        case .hour, .day: return date.formatted(date: .omitted, time: .shortened)
        case .week, .month: return date.formatted(.dateTime.month(.abbreviated).day().hour().minute())
        }
    }
}

/// Quiet one-line note inside a Queries card.
struct QueriesCardNote: View {
    let text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(.system(size: 11))
            .foregroundStyle(Color.settingsSecondaryText)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
    }
}

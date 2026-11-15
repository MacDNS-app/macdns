// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import SwiftUI

/// 1H / 24H / 7D / 30D, shared by Queries and Blocked.
struct QueryHistoryRangePicker: View {
    @Binding var range: QueryHistoryRange

    var body: some View {
        SegmentedPicker("Period", selection: $range) {
            ForEach(QueryHistoryRange.allCases, id: \.self) { range in
                Text(range.shortTitle)
                    .help("Last \(range.periodName)")
                    .tag(range)
            }
        }
        .labelsHidden()
        .fixedSize()
        // The brand tint draws the selected segment as a block offset below the control.
        .tint(nil)
    }
}

/// Stands in for a page's data when the history gave none.
struct QueryHistoryIssueView<Payload: Equatable>: View {
    let load: QueryHistoryLoad<Payload>
    let onOpenAdvanced: () -> Void

    var body: some View {
        VStack(spacing: 10) {
            SettingsIconTile(symbol: symbol, size: 36)
            Text(title)
                .font(.system(size: 13, weight: .semibold))
            Text(message)
                .font(.system(size: 12))
                .foregroundStyle(Color.settingsSecondaryText)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            if case .disabled = load {
                Button("Open Advanced", action: onOpenAdvanced)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 150)
        .padding(16)
    }

    private var symbol: String {
        switch load {
        case .disabled: return "clock.badge.xmark"
        default: return "exclamationmark.triangle.fill"
        }
    }

    private var title: String {
        switch load {
        case .disabled: return "Lookup history is off"
        case .unavailable: return "Lookup history is unavailable"
        case .loaded, .failed: return "Couldn't load lookup history"
        }
    }

    private var message: String {
        switch load {
        case .disabled:
            return "Turn on Keep Lookup History in Advanced to see what this Mac looks up."
        case .unavailable(let reason):
            // The reason goes on its own line, so it doesn't break inside a file name.
            return "Lookups still work.\nDetails: \(reason)"
        case .loaded, .failed:
            return "MacDNS didn't answer. This page tries again on its own."
        }
    }
}

/// Small rounded label that names a lookup's result.
struct QueryOutcomePill: View {
    let outcome: QueryOutcome

    var body: some View {
        Text(outcome.title)
            .font(.system(size: 10.5, weight: .semibold))
            .foregroundStyle(outcome.color)
            .lineLimit(1)
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(Capsule().fill(outcome.color.opacity(0.13)))
            .fixedSize()
    }
}

extension View {
    /// The one Clear History confirmation, plus the alert that reports a clear
    /// the agent did not confirm.
    func clearHistoryConfirmation(isPresented: Binding<Bool>, viewModel: AppViewModel) -> some View {
        modifier(ClearHistoryConfirmation(isPresented: isPresented, viewModel: viewModel))
    }
}

private struct ClearHistoryConfirmation: ViewModifier {
    @Binding var isPresented: Bool
    @ObservedObject var viewModel: AppViewModel

    private var failurePresented: Binding<Bool> {
        Binding(
            get: { viewModel.queryHistoryClear.failureMessage != nil },
            set: { if !$0 { viewModel.dismissQueryHistoryClearFailure() } }
        )
    }

    func body(content: Content) -> some View {
        content
            .alert("Clear Lookup History?", isPresented: $isPresented) {
                Button("Cancel", role: .cancel) {}
                Button("Clear History", role: .destructive) { viewModel.clearQueryHistory() }
            } message: {
                Text("Delete all lookup history on this Mac? This can't be undone.")
            }
            .alert("Lookup History Not Cleared", isPresented: failurePresented) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(viewModel.queryHistoryClear.failureMessage ?? "")
            }
    }
}

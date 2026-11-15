// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import SwiftUI

/// The right-click menu of a host in Top Hosts and the Log.
struct QueriesHostMenu: View {
    let name: String
    let blockRule: String
    @ObservedObject var viewModel: AppViewModel
    let onAddLocalRecord: () -> Void

    var body: some View {
        Button("Copy Name") { Clipboard.copy(name) }
        Divider()
        if !blockRule.isEmpty {
            QueriesAllowButton(blockRule: blockRule, viewModel: viewModel)
        }
        QueriesBlockButton(name: name, viewModel: viewModel)
        Button("Add Local Record…", action: onAddLocalRecord)
            .disabled(!viewModel.persistedStateAvailability.allowsConfigurationMutation)
    }
}

struct QueriesAllowButton: View {
    let blockRule: String
    @ObservedObject var viewModel: AppViewModel

    private var isAllowed: Bool {
        viewModel.allowedDomains.contains { $0.domain.caseInsensitiveCompare(blockRule) == .orderedSame }
    }

    var body: some View {
        Button(isAllowed ? "Allowed" : "Allow \(blockRule)") {
            viewModel.addToAllowlist(domain: blockRule)
        }
        .disabled(isAllowed || !viewModel.persistedStateAvailability.allowsConfigurationMutation)
        .help("Add '\(blockRule)' to the allowlist")
    }
}

/// Block or Unblock through Local Records that answer 0.0.0.0 and ::.
struct QueriesBlockButton: View {
    let name: String
    @ObservedObject var viewModel: AppViewModel

    var body: some View {
        let canMutate = viewModel.persistedStateAvailability.allowsConfigurationMutation
        switch LocalRecordShortcut.block(for: name, in: viewModel.dnsOverrides) {
        case .available:
            Button("Block") { viewModel.blockWithLocalRecords(host: name) }
                .disabled(!canMutate)
                .help("Answer 0.0.0.0 and :: for \(name) with Local Records")
        case .blocked:
            Button("Unblock") { viewModel.unblockLocalRecords(host: name) }
                .disabled(!canMutate)
                .help("Remove the Local Records that block \(name)")
        case .unavailable(let reason):
            Button("Block") {}
                .disabled(true)
                .help(reason)
        }
    }
}

/// Adds one Local Record for a host in place, checked like the Local Records editor.
struct QueriesAddLocalRecordForm: View {
    let host: String
    @ObservedObject var viewModel: AppViewModel
    @Binding var isPresented: Bool
    @State private var qtype: String
    @State private var value = ""
    @FocusState private var valueFocused: Bool

    init(host: String, lookupType: String?, viewModel: AppViewModel, isPresented: Binding<Bool>) {
        self.host = host
        self.viewModel = viewModel
        _isPresented = isPresented
        _qtype = State(initialValue: LocalRecordShortcut.initialType(forLookupType: lookupType))
    }

    private var error: String? {
        LocalRecordShortcut.addError(host: host, qtype: qtype, value: value, in: viewModel.dnsOverrides)
    }

    private var canAdd: Bool {
        !value.isEmpty && error == nil && viewModel.persistedStateAvailability.allowsConfigurationMutation
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Add Local Record")
                    .font(.system(size: 13, weight: .semibold))
                Text(host)
                    .font(.system(size: 12))
                    .foregroundStyle(Color.settingsSecondaryText)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            HStack(spacing: 8) {
                Picker("Type", selection: $qtype) {
                    ForEach(LocalRecordShortcut.recordTypes, id: \.self) { Text($0).tag($0) }
                }
                .labelsHidden()
                .frame(width: 84)
                TextField(DNSOverride.valuePlaceholder(for: qtype), text: $value)
                    .textFieldStyle(.roundedBorder)
                    .focused($valueFocused)
                    .onSubmit(add)
            }
            if let error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel") { isPresented = false }
                    .keyboardShortcut(.cancelAction)
                Button("Add", action: add)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canAdd)
            }
        }
        .controlSize(.regular)
        .padding(14)
        .frame(width: 340)
        // The field is not focusable until the popover is in its window.
        .onAppear { DispatchQueue.main.async { valueFocused = true } }
    }

    private func add() {
        guard canAdd, viewModel.addLocalRecord(host: host, qtype: qtype, value: value) else { return }
        isPresented = false
    }
}

extension View {
    /// The add form as a popover on this view while `host` is the one being added to.
    func queriesAddLocalRecordPopover(
        host: String, lookupType: String?, presented: Binding<String?>, id: String, viewModel: AppViewModel
    ) -> some View {
        let isPresented = Binding(
            get: { presented.wrappedValue == id },
            set: { if !$0, presented.wrappedValue == id { presented.wrappedValue = nil } }
        )
        return popover(isPresented: isPresented, arrowEdge: .bottom) {
            QueriesAddLocalRecordForm(
                host: host, lookupType: lookupType, viewModel: viewModel, isPresented: isPresented)
        }
    }
}

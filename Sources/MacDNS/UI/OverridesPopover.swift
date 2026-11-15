// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import Shared
import SwiftUI

struct OverridesPopover: View {
    @ObservedObject var viewModel: AppViewModel
    @Environment(\.colorScheme) private var colorScheme
    @FocusState private var isDomainFocused: Bool
    @State private var showAddForm = false
    @State private var domain = ""
    @State private var value = ""
    @State private var qtype = "A"
    @State private var validationError: String?

    private let qtypes = ["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "NS"]

    private var textColor: Color {
        colorScheme == .dark ? .white : .black
    }

    var body: some View {
        VStack(spacing: 0) {
            if showAddForm {
                addFormView
            } else {
                listView
            }
        }
        .padding(8)
        .frame(width: showAddForm ? 260 : 220)
        .foregroundColor(textColor)
        .disabled(
            !viewModel.persistedStateAvailability.allowsConfigurationMutation
        )
        .animation(.easeInOut(duration: 0.15), value: showAddForm)
        .contentShape(Rectangle())
    }

    // MARK: - List View
    private var listView: some View {
        VStack(spacing: 0) {
            if viewModel.dnsOverrides.isEmpty {
                Text("No local records yet")
                    .font(.menu)
                    .foregroundColor(.secondary)
                    .padding(.vertical, 8)
            } else {
                ForEach(viewModel.dnsOverrides.prefix(7)) { override in
                    OverrideMenuRow(override: override, viewModel: viewModel, textColor: textColor)
                }

                if viewModel.dnsOverrides.count > 7 {
                    Text("+ \(viewModel.dnsOverrides.count - 7) more...")
                        .font(.menu)
                        .foregroundColor(textColor)
                        .padding(.vertical, 4)
                }
            }

            Divider()
                .padding(.vertical, 4)

            AddOverrideMenuButton(textColor: textColor) {
                showAddForm = true
            }
        }
    }

    // MARK: - Add Form View
    private var addFormView: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Domain")
                    .font(.menu)
                    .foregroundColor(textColor)
                TextField("example.com or *.test", text: $domain)
                    .textFieldStyle(.roundedBorder)
                    .font(.menu)
                    .focused($isDomainFocused)
                    .onChange(of: domain) { _, _ in
                        validateOverride()
                    }
                if let error = validationError {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                } else if let warning = DomainValidator.publicTLDWarning(forOverrideDomain: domain) {
                    Text(warning)
                        .font(.caption)
                        .foregroundColor(.orange)
                }
            }

            HStack(spacing: 8) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Type")
                        .font(.menu)
                        .foregroundColor(textColor)
                    Picker("", selection: $qtype) {
                        ForEach(qtypes, id: \.self) { Text($0) }
                    }
                    .labelsHidden()
                    .frame(width: 70)
                    .onChange(of: qtype) { _, _ in
                        validateOverride()
                    }
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text("Value")
                        .font(.menu)
                        .foregroundColor(textColor)
                    TextField(DNSOverride.valuePlaceholder(for: qtype), text: $value)
                        .textFieldStyle(.roundedBorder)
                        .font(.menu)
                        .onChange(of: value) { _, _ in
                            validateOverride()
                        }
                }
            }

            HStack {
                Spacer()
                Button("Cancel") {
                    resetForm()
                }
                .buttonStyle(.bordered)
                .keyboardShortcut(.cancelAction)
                Button("Add") {
                    addOverride()
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(!canAdd)
            }
            .padding(.top, 4)
        }
        .padding(.horizontal, 8)
        .foregroundColor(textColor)
        .onAppear {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                isDomainFocused = true
            }
        }
    }

    private var canAdd: Bool {
        !domain.isEmpty && !value.isEmpty && validationError == nil
    }

    @discardableResult
    private func validateOverride() -> Bool {
        guard
            DomainValidator.validateWithErrorBinding(
                domain, allowsSingleLabelHost: true, errorBinding: &validationError
            )
        else {
            return false
        }
        if let conflict = DomainValidator.validateCNAMEExclusivity(
            domain: domain,
            qtype: qtype,
            existingOverrides: viewModel.dnsOverrides
        ) {
            validationError = conflict
            return false
        }
        guard
            DomainValidator.validateOverrideValueWithErrorBinding(
                value, forType: qtype, errorBinding: &validationError
            )
        else {
            return false
        }
        return true
    }

    private func addOverride() {
        guard validateOverride() else { return }
        viewModel.dnsOverrides.append(
            DNSOverride(domain: domain, value: value, qtype: qtype)
        )
        resetForm()
    }

    private func resetForm() {
        showAddForm = false
        domain = ""
        value = ""
        qtype = "A"
        validationError = nil
    }
}

struct OverrideMenuRow: View {
    let override: DNSOverride
    @ObservedObject var viewModel: AppViewModel
    let textColor: Color
    @State private var isHovered = false

    private var cnameConflictMessage: String? {
        guard !override.enabled else { return nil }
        return DomainValidator.validateCNAMEExclusivity(
            domain: override.domain,
            qtype: override.qtype,
            existingOverrides: viewModel.dnsOverrides,
            excludeId: override.id
        )
    }

    var body: some View {
        HStack(spacing: 8) {
            Toggle("", isOn: .constant(override.enabled))
                .toggleStyle(.checkbox)
                .labelsHidden()
                .allowsHitTesting(false)
                .focusable(false)

            Text(override.domain)
                .font(.menu)
                .lineLimit(1)
                .truncationMode(.middle)

            Spacer()

            Text(override.qtype)
                .font(.caption2.weight(.medium))
                .padding(.horizontal, 4)
                .padding(.vertical, 2)
                .background(Color.accentColor.opacity(0.2))
                .cornerRadius(4)
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 8)
        .background(isHovered ? Color.accentColor : Color.clear)
        .foregroundColor(isHovered ? .white : textColor)
        .cornerRadius(4)
        .opacity(override.enabled ? 1.0 : (cnameConflictMessage != nil ? 0.3 : 0.5))
        .contentShape(Rectangle())
        .onTapGesture {
            guard cnameConflictMessage == nil else { return }
            if let index = viewModel.dnsOverrides.firstIndex(where: { $0.id == override.id }) {
                viewModel.dnsOverrides[index].enabled.toggle()
            }
        }
        .onHover { hovering in
            isHovered = hovering
        }
        .help(cnameConflictMessage ?? "")
    }

}

struct AddOverrideMenuButton: View {
    let textColor: Color
    let onTap: () -> Void
    @State private var isHovered = false

    var body: some View {
        Button(action: onTap) {
            HStack {
                Text("Add Local Record...")
                    .font(.menu)
                Spacer()
            }
            .padding(.vertical, 4)
            .padding(.horizontal, 8)
            .background(isHovered ? Color.accentColor : Color.clear)
            .foregroundColor(isHovered ? .white : textColor)
            .cornerRadius(4)
        }
        .buttonStyle(.plain)
        .focusable(false)
        .onHover { hovering in
            isHovered = hovering
        }
    }
}

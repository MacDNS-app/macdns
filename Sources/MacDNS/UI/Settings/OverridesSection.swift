// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import SwiftUI

struct OverridesSection: View {
    @ObservedObject var viewModel: AppViewModel
    @State private var selection: UUID?
    @State private var edit = ListEditState()
    @State private var draftDomain = ""
    @State private var draftValue = ""
    @State private var draftQType = "A"
    @State private var validationError: String?
    @FocusState private var domainFieldFocused: Bool

    private let qtypes = ["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "NS"]
    private let typeColumnWidth: CGFloat = 84

    var body: some View {
        SettingsPage(
            .overrides,
            lede:
                "Give a domain the address you choose, on this Mac only. *.test covers test, a.test and a.b.test."
        ) {
            SettingsCard {
                if viewModel.dnsOverrides.isEmpty && !edit.isAddingNew {
                    EditableListEmptyState(
                        symbol: "arrow.triangle.swap",
                        message: "No local records yet",
                        onAdd: beginAdd
                    )
                } else {
                    EditableListColumnHeader {
                        Text("Domain")
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Text("Type")
                            .frame(width: typeColumnWidth, alignment: .leading)
                        Text("Value")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    Divider()
                    overrideList
                    Divider()
                    EditableListBar(
                        note: EditableListBar.note(
                            count: viewModel.dnsOverrides.count,
                            active: viewModel.dnsOverrides.filter(\.enabled).count,
                            noun: "record", plural: "records", hint: "Double-click to edit"),
                        canRemove: selection != nil && !edit.isEditing,
                        onAdd: beginAdd,
                        onRemove: removeSelected
                    )
                }
            }
        }
        .onDisappear { finishEditing() }
        .disabled(
            !viewModel.persistedStateAvailability.allowsConfigurationMutation
        )
        .requiresAgent(
            isActive: viewModel.agentInstalled,
            canTurnOn: viewModel.persistedStateAvailability.allowsUserEnable,
            onTurnOn: { viewModel.enableDNS() }
        )
    }

    private var overrideList: some View {
        ScrollViewReader { proxy in
            List(selection: $selection) {
                ForEach(viewModel.dnsOverrides) { override in
                    Group {
                        if edit.editingID == override.id {
                            editingRow
                        } else {
                            overrideRow(override)
                        }
                    }
                    .editableListRow()
                }
                if edit.isAddingNew {
                    editingRow
                        .editableListRow()
                        .id(EditableListLayout.newRowID)
                }
            }
            .editableListStyle(
                rows: viewModel.dnsOverrides.count + (edit.isAddingNew ? 1 : 0), editing: edit.isEditing
            )
            .contextMenu(forSelectionType: UUID.self, menu: { _ in }) { ids in
                if let id = ids.first { beginEdit(id) }
            }
            .onKeyPress(.return) {
                guard !edit.isEditing, let id = selection else { return .ignored }
                beginEdit(id)
                return .handled
            }
            .onKeyPress(.space) {
                guard !edit.isEditing, let id = selection,
                    let override = viewModel.dnsOverrides.first(where: { $0.id == id }),
                    cnameConflictMessage(for: override) == nil
                else { return .ignored }
                enabledBinding(for: id).wrappedValue.toggle()
                return .handled
            }
            .onDeleteCommand {
                guard !edit.isEditing else { return }
                removeSelected()
            }
            .onChange(of: edit) { _, newValue in
                if newValue.isAddingNew { proxy.scrollTo(EditableListLayout.newRowID) }
            }
            .onChange(of: viewModel.dnsOverrides) { _, overrides in
                if let id = edit.editingID, !overrides.contains(where: { $0.id == id }) { finishEditing() }
                if let id = selection, !overrides.contains(where: { $0.id == id }) { selection = nil }
            }
        }
    }

    private func overrideRow(_ override: DNSOverride) -> some View {
        let conflict = cnameConflictMessage(for: override)
        return HStack(spacing: 8) {
            Group {
                Text(override.domain)
                    .font(.system(size: 13))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: .infinity, alignment: .leading)
                RecordTypeBadge(qtype: override.qtype)
                    .frame(width: typeColumnWidth, alignment: .leading)
                EditableListValue(text: override.value)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .opacity(override.enabled ? 1.0 : (conflict != nil ? 0.3 : 0.5))
            SettingsSwitch(isOn: enabledBinding(for: override.id))
                .disabled(conflict != nil)
                .frame(width: EditableListLayout.onColumnWidth)
        }
        .help(conflict ?? "")
    }

    private var editingRow: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                TextField("example.com or *.test", text: $draftDomain)
                    .focused($domainFieldFocused)
                    .frame(maxWidth: .infinity)
                Picker("", selection: $draftQType) {
                    ForEach(qtypes, id: \.self) { qtype in
                        Text(qtype).tag(qtype)
                    }
                }
                .labelsHidden()
                .pickerStyle(.menu)
                .frame(width: typeColumnWidth)
                TextField(DNSOverride.valuePlaceholder(for: draftQType), text: $draftValue)
                    .frame(maxWidth: .infinity)
                EditableListSaveButton(canSave: canSave, onSave: save)
            }
            .textFieldStyle(.roundedBorder)
            if let error = validationError {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            } else if let warning = DomainValidator.publicTLDWarning(forOverrideDomain: draftDomain) {
                Text(warning)
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
        .onSubmit(save)
        .onExitCommand { finishEditing() }
        // The field is not focusable until the row is in the window.
        .onAppear { DispatchQueue.main.async { domainFieldFocused = true } }
        .onChange(of: draftDomain) { _, _ in validateDraft() }
        .onChange(of: draftQType) { _, _ in validateDraft() }
        .onChange(of: draftValue) { _, _ in validateDraft() }
    }

    private var canSave: Bool {
        !draftDomain.isEmpty && !draftValue.isEmpty && validationError == nil
    }

    /// Non-nil only for a disabled entry that would conflict if enabled, so it cannot be turned on.
    private func cnameConflictMessage(for override: DNSOverride) -> String? {
        guard !override.enabled else { return nil }
        return DomainValidator.validateCNAMEExclusivity(
            domain: override.domain,
            qtype: override.qtype,
            existingOverrides: viewModel.dnsOverrides,
            excludeId: override.id
        )
    }

    private func enabledBinding(for id: UUID) -> Binding<Bool> {
        Binding(
            get: { viewModel.dnsOverrides.first { $0.id == id }?.enabled ?? false },
            set: { newValue in
                if let index = viewModel.dnsOverrides.firstIndex(where: { $0.id == id }) {
                    viewModel.dnsOverrides[index].enabled = newValue
                }
            }
        )
    }

    private func beginAdd() {
        edit.beginAdd()
        draftDomain = ""
        draftValue = ""
        draftQType = "A"
        validationError = nil
    }

    private func beginEdit(_ id: UUID) {
        guard edit.editingID != id,
            let override = viewModel.dnsOverrides.first(where: { $0.id == id })
        else { return }
        edit.beginEdit(id)
        // The blue selection would sit behind the fields and the save button.
        selection = nil
        draftDomain = override.domain
        draftValue = override.value
        draftQType = override.qtype
        validationError = nil
    }

    private func finishEditing() {
        if let id = edit.editingID { selection = id }
        edit.finish()
        validationError = nil
    }

    private func save() {
        guard validateDraft() else { return }
        if let id = edit.editingID {
            if let index = viewModel.dnsOverrides.firstIndex(where: { $0.id == id }) {
                var override = viewModel.dnsOverrides[index]
                override.domain = draftDomain
                override.value = draftValue
                override.qtype = draftQType
                viewModel.dnsOverrides[index] = override
            }
        } else if edit.isAddingNew {
            let override = DNSOverride(domain: draftDomain, value: draftValue, qtype: draftQType)
            viewModel.dnsOverrides.append(override)
            selection = override.id
        }
        finishEditing()
    }

    private func removeSelected() {
        guard let id = selection else { return }
        viewModel.dnsOverrides.removeAll { $0.id == id }
        selection = nil
    }

    /// `excludeId` is the edited entry, or nil while adding.
    @discardableResult
    private func validateDraft() -> Bool {
        guard
            DomainValidator.validateWithErrorBinding(
                draftDomain, allowsSingleLabelHost: true, errorBinding: &validationError
            )
        else {
            return false
        }
        if let conflict = DomainValidator.validateCNAMEExclusivity(
            domain: draftDomain,
            qtype: draftQType,
            existingOverrides: viewModel.dnsOverrides,
            excludeId: edit.editingID
        ) {
            validationError = conflict
            return false
        }
        guard
            DomainValidator.validateOverrideValueWithErrorBinding(
                draftValue, forType: draftQType, errorBinding: &validationError
            )
        else {
            return false
        }
        return true
    }
}

private struct RecordTypeBadge: View {
    let qtype: String
    @Environment(\.backgroundProminence) private var prominence

    var body: some View {
        let onSelection = prominence == .increased
        Text(qtype)
            .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
            .foregroundStyle(onSelection ? Color.white : Color.brandSmallText)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(
                RoundedRectangle(cornerRadius: 5, style: .continuous)
                    .fill(onSelection ? Color.white.opacity(0.22) : Color.brandControl.opacity(0.13)))
    }
}

#Preview {
    OverridesSection(viewModel: AppViewModel())
}

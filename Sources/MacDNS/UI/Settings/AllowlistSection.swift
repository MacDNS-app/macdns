// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import SwiftUI

struct AllowlistSection: View {
    @ObservedObject var viewModel: AppViewModel
    @State private var selection: UUID?
    @State private var edit = ListEditState()
    @State private var draftDomain = ""
    @State private var validationError: String?
    @FocusState private var domainFieldFocused: Bool

    var body: some View {
        SettingsPage(
            .allowlist,
            lede: "Exceptions for domains you need. They load even when a blocklist includes them."
        ) {
            SettingsCard {
                if viewModel.allowedDomains.isEmpty && !edit.isAddingNew {
                    EditableListEmptyState(
                        symbol: "checkmark.shield.fill",
                        message: "No exceptions yet",
                        onAdd: beginAdd
                    )
                } else {
                    EditableListColumnHeader {
                        Text("Domain")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    Divider()
                    domainList
                    Divider()
                    EditableListBar(
                        note: EditableListBar.note(
                            count: viewModel.allowedDomains.count,
                            active: viewModel.allowedDomains.filter(\.enabled).count,
                            noun: "domain", plural: "domains"),
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
        .onAppear {
            if viewModel.agentInstalled {
                viewModel.refreshAllowlist()
            }
        }
        .onChange(of: viewModel.agentInstalled) { _, installed in
            if installed {
                viewModel.refreshAllowlist()
            }
        }
    }

    private var domainList: some View {
        ScrollViewReader { proxy in
            List(selection: $selection) {
                ForEach(viewModel.allowedDomains) { allowedDomain in
                    domainRow(allowedDomain)
                        .editableListRow()
                }
                if edit.isAddingNew {
                    editingRow
                        .editableListRow()
                        .id(EditableListLayout.newRowID)
                }
            }
            .editableListStyle(
                rows: viewModel.allowedDomains.count + (edit.isAddingNew ? 1 : 0), editing: edit.isEditing
            )
            .onKeyPress(.space) {
                guard !edit.isEditing, let id = selection else { return .ignored }
                viewModel.toggleAllowlistDomain(id: id)
                return .handled
            }
            .onDeleteCommand {
                guard !edit.isEditing else { return }
                removeSelected()
            }
            .onChange(of: edit) { _, newValue in
                if newValue.isAddingNew { proxy.scrollTo(EditableListLayout.newRowID) }
            }
            .onChange(of: viewModel.allowedDomains) { _, domains in
                if let id = selection, !domains.contains(where: { $0.id == id }) { selection = nil }
            }
        }
    }

    private func domainRow(_ allowedDomain: AllowedDomain) -> some View {
        HStack(spacing: 8) {
            Text(allowedDomain.domain)
                .font(.system(size: 13))
                .lineLimit(1)
                .truncationMode(.middle)
                .opacity(allowedDomain.enabled ? 1.0 : 0.5)
                .frame(maxWidth: .infinity, alignment: .leading)
            SettingsSwitch(isOn: enabledBinding(for: allowedDomain))
                .frame(width: EditableListLayout.onColumnWidth)
        }
    }

    private var editingRow: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                TextField("example.com", text: $draftDomain)
                    .focused($domainFieldFocused)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: .infinity)
                EditableListSaveButton(canSave: canSave, onSave: save)
            }
            if let error = validationError {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(Color.statusCritical)
            }
        }
        .onSubmit(save)
        .onExitCommand { finishEditing() }
        // The field is not focusable until the row is in the window.
        .onAppear { DispatchQueue.main.async { domainFieldFocused = true } }
        .onChange(of: draftDomain) { _, _ in validateDraft() }
    }

    private var canSave: Bool {
        !draftDomain.isEmpty && validationError == nil
    }

    // The row toggle only fires an action, so the state shown always comes from the view model.
    private func enabledBinding(for allowedDomain: AllowedDomain) -> Binding<Bool> {
        Binding(
            get: { viewModel.allowedDomains.first { $0.id == allowedDomain.id }?.enabled ?? false },
            set: { _ in viewModel.toggleAllowlistDomain(id: allowedDomain.id) }
        )
    }

    private func beginAdd() {
        edit.beginAdd()
        draftDomain = ""
        validationError = nil
    }

    private func finishEditing() {
        edit.finish()
        validationError = nil
    }

    private func save() {
        guard validateDraft(), viewModel.addToAllowlist(domain: draftDomain) else { return }
        finishEditing()
    }

    private func removeSelected() {
        guard let id = selection else { return }
        viewModel.removeFromAllowlist(id: id)
        selection = nil
    }

    @discardableResult
    private func validateDraft() -> Bool {
        DomainValidator.validateWithErrorBinding(draftDomain, errorBinding: &validationError)
    }
}

#Preview {
    AllowlistSection(viewModel: AppViewModel())
}

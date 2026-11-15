// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import SwiftUI

struct ForwardZonesSection: View {
    @ObservedObject var viewModel: AppViewModel
    @State private var selection: UUID?
    @State private var edit = ListEditState()
    @State private var draftDomain = ""
    @State private var draftServer = ""
    @State private var validationError: String?
    @FocusState private var domainFieldFocused: Bool

    private let serverColumnWidth: CGFloat = 170

    var body: some View {
        SettingsPage(
            .forwardZones,
            lede: "Send private domains, such as your company's or your home lab's, to the DNS server that knows them."
        ) {
            SettingsCard {
                if viewModel.customZones.isEmpty && !edit.isAddingNew {
                    EditableListEmptyState(
                        symbol: "globe",
                        message: "No forward zones yet",
                        onAdd: beginAdd
                    )
                } else {
                    EditableListColumnHeader {
                        Text("Domain")
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Text("DNS Server")
                            .frame(width: serverColumnWidth, alignment: .leading)
                    }
                    Divider()
                    zoneList
                    Divider()
                    EditableListBar(
                        note: EditableListBar.note(
                            count: viewModel.customZones.count,
                            active: viewModel.customZones.filter(\.enabled).count,
                            noun: "zone", plural: "zones", hint: "Double-click to edit"),
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

    private var zoneList: some View {
        ScrollViewReader { proxy in
            List(selection: $selection) {
                ForEach(viewModel.customZones) { zone in
                    Group {
                        if edit.editingID == zone.id {
                            editingRow
                        } else {
                            zoneRow(zone)
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
                rows: viewModel.customZones.count + (edit.isAddingNew ? 1 : 0), editing: edit.isEditing
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
                guard !edit.isEditing, let id = selection else { return .ignored }
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
            .onChange(of: viewModel.customZones) { _, zones in
                if let id = edit.editingID, !zones.contains(where: { $0.id == id }) { finishEditing() }
                if let id = selection, !zones.contains(where: { $0.id == id }) { selection = nil }
            }
        }
    }

    private func zoneRow(_ zone: ForwardZone) -> some View {
        HStack(spacing: 8) {
            Group {
                Text(zone.domain)
                    .font(.system(size: 13))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: .infinity, alignment: .leading)
                EditableListValue(text: zone.forwardIP)
                    .frame(width: serverColumnWidth, alignment: .leading)
            }
            .opacity(zone.enabled ? 1.0 : 0.5)
            SettingsSwitch(isOn: enabledBinding(for: zone.id))
                .frame(width: EditableListLayout.onColumnWidth)
        }
    }

    private var editingRow: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                TextField("example.local", text: $draftDomain)
                    .focused($domainFieldFocused)
                    .frame(maxWidth: .infinity)
                TextField("8.8.8.8", text: $draftServer)
                    .frame(width: serverColumnWidth)
                EditableListSaveButton(canSave: canSave, onSave: save)
            }
            .textFieldStyle(.roundedBorder)
            if let error = validationError {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
        .onSubmit(save)
        .onExitCommand { finishEditing() }
        // The field is not focusable until the row is in the window.
        .onAppear { DispatchQueue.main.async { domainFieldFocused = true } }
        .onChange(of: draftDomain) { _, _ in validateDraft() }
        .onChange(of: draftServer) { _, _ in validateDraft() }
    }

    private var canSave: Bool {
        !draftDomain.isEmpty && !draftServer.isEmpty && validationError == nil
    }

    private func enabledBinding(for id: UUID) -> Binding<Bool> {
        Binding(
            get: { viewModel.customZones.first { $0.id == id }?.enabled ?? false },
            set: { newValue in
                if let index = viewModel.customZones.firstIndex(where: { $0.id == id }) {
                    viewModel.customZones[index].enabled = newValue
                }
            }
        )
    }

    private func beginAdd() {
        edit.beginAdd()
        draftDomain = ""
        draftServer = ""
        validationError = nil
    }

    private func beginEdit(_ id: UUID) {
        guard edit.editingID != id,
            let zone = viewModel.customZones.first(where: { $0.id == id })
        else { return }
        edit.beginEdit(id)
        // The blue selection would sit behind the fields and the save button.
        selection = nil
        draftDomain = zone.domain
        draftServer = zone.forwardIP
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
            if let index = viewModel.customZones.firstIndex(where: { $0.id == id }) {
                var zone = viewModel.customZones[index]
                zone.domain = draftDomain
                zone.forwardIP = draftServer
                viewModel.customZones[index] = zone
            }
        } else if edit.isAddingNew {
            let zone = ForwardZone(domain: draftDomain, forwardIP: draftServer)
            viewModel.customZones.append(zone)
            selection = zone.id
        }
        finishEditing()
    }

    private func removeSelected() {
        guard let id = selection else { return }
        viewModel.customZones.removeAll { $0.id == id }
        selection = nil
    }

    @discardableResult
    private func validateDraft() -> Bool {
        guard
            DomainValidator.validateWithErrorBinding(
                draftDomain, errorBinding: &validationError
            )
        else {
            return false
        }
        guard
            DomainValidator.validateIPWithErrorBinding(
                draftServer, errorBinding: &validationError
            )
        else {
            return false
        }
        return true
    }
}

#Preview {
    ForwardZonesSection(viewModel: AppViewModel())
}

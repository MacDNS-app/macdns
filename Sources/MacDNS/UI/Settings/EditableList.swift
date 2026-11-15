// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import SwiftUI

/// Which row of an editable settings list is in edit mode. Only one row edits at a time:
/// starting an add or a row edit replaces whatever edit was in progress.
struct ListEditState: Equatable {
    private(set) var editingID: UUID?
    private(set) var isAddingNew = false

    var isEditing: Bool { editingID != nil || isAddingNew }

    mutating func beginAdd() {
        editingID = nil
        isAddingNew = true
    }

    mutating func beginEdit(_ id: UUID) {
        editingID = id
        isAddingNew = false
    }

    mutating func finish() {
        editingID = nil
        isAddingNew = false
    }
}

enum EditableListLayout {
    static let rowHeight: CGFloat = 36
    static let maxListHeight: CGFloat = 360
    static let onColumnWidth: CGFloat = 44
    static let horizontalPadding: CGFloat = 14
    /// The plain list already insets rows by 8pt. This tops them up to the card's 14pt.
    static let rowContentPadding: CGFloat = 6
    static let newRowID = "editable-list-new-row"

    /// Grows with the rows so short lists leave no empty block, then scrolls.
    /// An editing row gets room for its validation message.
    static func listHeight(rows: Int, editing: Bool) -> CGFloat {
        let extra: CGFloat = editing ? 22 : 0
        return min(CGFloat(max(rows, 1)) * rowHeight + extra + 4, maxListHeight)
    }
}

/// Styling shared by the editable lists: native selection and keyboard, card look.
struct EditableListStyle: ViewModifier {
    let rows: Int
    let editing: Bool

    func body(content: Content) -> some View {
        content
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .environment(\.defaultMinListRowHeight, EditableListLayout.rowHeight)
            .frame(height: EditableListLayout.listHeight(rows: rows, editing: editing))
    }
}

extension View {
    func editableListRow() -> some View {
        padding(.horizontal, EditableListLayout.rowContentPadding)
    }

    func editableListStyle(rows: Int, editing: Bool = false) -> some View {
        modifier(EditableListStyle(rows: rows, editing: editing))
    }
}

struct EditableListColumnHeader<Columns: View>: View {
    let columns: Columns

    init(@ViewBuilder columns: () -> Columns) {
        self.columns = columns()
    }

    var body: some View {
        HStack(spacing: 8) {
            columns
            Text("On")
                .frame(width: EditableListLayout.onColumnWidth)
        }
        .font(.system(size: 11, weight: .semibold))
        .foregroundStyle(Color.settingsSecondaryText)
        .padding(.horizontal, EditableListLayout.horizontalPadding)
        .padding(.vertical, 7)
        .background(Color.settingsSubtleFill)
    }
}

struct EditableListBar: View {
    let note: String
    let canRemove: Bool
    let onAdd: (() -> Void)?
    let onRemove: () -> Void

    var body: some View {
        HStack(spacing: 2) {
            if let onAdd {
                Button(action: onAdd) {
                    Image(systemName: "plus")
                        .font(.system(size: 12, weight: .medium))
                        .frame(width: 24, height: 20)
                        .contentShape(Rectangle())
                }
                .help("Add")
            }
            Button(action: onRemove) {
                Image(systemName: "minus")
                    .font(.system(size: 12, weight: .medium))
                    .frame(width: 24, height: 20)
                    .contentShape(Rectangle())
            }
            .help("Remove the selected entry")
            .disabled(!canRemove)
            Spacer()
            Text(note)
                .font(.system(size: 11))
                .foregroundStyle(Color.settingsSecondaryText)
                .monospacedDigit()
                .padding(.trailing, 6)
        }
        .buttonStyle(.borderless)
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(Color.settingsSubtleFill)
    }

    static func note(count: Int, active: Int, noun: String, plural: String, hint: String? = nil) -> String {
        let counted = count == 1 ? "1 \(noun)" : "\(count) \(plural)"
        let summary = active == count ? counted : "\(counted) · \(active) on"
        return [hint, summary].compactMap { $0 }.joined(separator: " · ")
    }
}

struct EditableListEmptyState: View {
    let symbol: String
    let message: String
    let onAdd: (() -> Void)?

    var body: some View {
        VStack(spacing: 10) {
            SettingsIconTile(symbol: symbol, size: 36)
            Text(message)
                .font(.system(size: 12.5))
                .foregroundStyle(Color.settingsSecondaryText)
            if let onAdd {
                Button("Add", action: onAdd)
                    .buttonStyle(.borderedProminent)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 150)
        .padding(12)
    }
}

/// Inline save control for an editing row. Return does the same.
struct EditableListSaveButton: View {
    let canSave: Bool
    let onSave: () -> Void

    var body: some View {
        Button(action: onSave) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 16))
                .foregroundStyle(canSave ? Color.brandControl : Color.secondary)
        }
        .buttonStyle(.borderless)
        .disabled(!canSave)
        .help("Save (Return). Escape cancels.")
        .frame(width: EditableListLayout.onColumnWidth)
    }
}

/// Monospaced value cell used for addresses and record data.
struct EditableListValue: View {
    let text: String
    @Environment(\.backgroundProminence) private var prominence

    var body: some View {
        Text(text)
            .font(.system(size: 12, design: .monospaced))
            .foregroundStyle(prominence == .increased ? Color.white.opacity(0.85) : Color.settingsSecondaryText)
            .lineLimit(1)
            .truncationMode(.middle)
    }
}

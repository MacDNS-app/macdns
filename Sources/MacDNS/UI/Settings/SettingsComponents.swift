// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import SwiftUI

enum SettingsMetrics {
    static let rowHorizontalPadding: CGFloat = 14
    static let rowMinHeight: CGFloat = 44
    static let cardCornerRadius: CGFloat = 10
}

/// Scrolling page for one section. The section title lives in the window toolbar.
/// A footer sits at the bottom of the visible area, or below the content when it is taller.
struct SettingsPage<Content: View, Footer: View>: View {
    let section: SettingsSection
    let lede: String?
    let content: Content
    let footer: Footer

    init(
        _ section: SettingsSection, lede: String? = nil, @ViewBuilder content: () -> Content,
        @ViewBuilder footer: () -> Footer
    ) {
        self.section = section
        self.lede = lede
        self.content = content()
        self.footer = footer()
    }

    var body: some View {
        GeometryReader { viewport in
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    if let lede {
                        Text(lede)
                            .font(.system(size: 12.5))
                            .foregroundStyle(Color.settingsSecondaryText)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(.horizontal, 2)
                            .padding(.bottom, -6)
                    }
                    content
                    Spacer(minLength: 0)
                    footer
                }
                .padding(.horizontal, 24)
                .padding(.top, 18)
                .padding(.bottom, Footer.self == EmptyView.self ? 28 : 14)
                .frame(maxWidth: 720, alignment: .leading)
                .frame(maxWidth: .infinity, minHeight: viewport.size.height, alignment: .top)
            }
        }
        .navigationTitle(section.title)
    }
}

extension SettingsPage where Footer == EmptyView {
    init(_ section: SettingsSection, lede: String? = nil, @ViewBuilder content: () -> Content) {
        self.init(section, lede: lede, content: content, footer: { EmptyView() })
    }
}

/// A titled group: header above one card.
struct SettingsGroup<Content: View, Accessory: View>: View {
    let title: String
    let caption: String?
    let accessory: Accessory
    let content: Content

    init(
        _ title: String, caption: String? = nil,
        @ViewBuilder accessory: () -> Accessory = { EmptyView() },
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.caption = caption
        self.accessory = accessory()
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .center, spacing: 8) {
                SettingsSectionHeader(title, caption: caption)
                Spacer(minLength: 8)
                accessory
            }
            .padding(.horizontal, 2)
            SettingsCard { content }
        }
    }
}

struct SettingsSectionHeader: View {
    let title: String
    let caption: String?

    init(_ title: String, caption: String? = nil) {
        self.title = title
        self.caption = caption
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(title)
                .font(.system(size: 13, weight: .semibold))
            if let caption {
                Text(caption)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.settingsSecondaryText)
                    .lineLimit(1)
            }
        }
    }
}

struct SettingsCard<Content: View>: View {
    var stroke: Color = .settingsCardStroke
    let content: Content

    init(stroke: Color = .settingsCardStroke, @ViewBuilder content: () -> Content) {
        self.stroke = stroke
        self.content = content()
    }

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: SettingsMetrics.cardCornerRadius, style: .continuous)
        VStack(alignment: .leading, spacing: 0) {
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(shape.fill(Color.settingsCard))
        .clipShape(shape)
        .overlay(shape.strokeBorder(stroke, lineWidth: 1))
        .shadow(color: .black.opacity(0.04), radius: 1, y: 1)
    }
}

/// Hairline between the rows of a card.
struct SettingsDivider: View {
    var inset: CGFloat = SettingsMetrics.rowHorizontalPadding

    var body: some View {
        Divider().padding(.leading, inset)
    }
}

struct SettingsRow<Leading: View, Control: View>: View {
    let title: String
    let detail: String?
    let leading: Leading
    let control: Control

    init(
        _ title: String, detail: String? = nil,
        @ViewBuilder leading: () -> Leading = { EmptyView() },
        @ViewBuilder control: () -> Control
    ) {
        self.title = title
        self.detail = detail
        self.leading = leading()
        self.control = control()
    }

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            leading
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 13))
                if let detail {
                    Text(detail)
                        .font(.system(size: 11))
                        .foregroundStyle(Color.settingsSecondaryText)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 12)
            control
        }
        .padding(.horizontal, SettingsMetrics.rowHorizontalPadding)
        .padding(.vertical, 9)
        .frame(minHeight: SettingsMetrics.rowMinHeight)
    }
}

/// The switch every settings row uses.
struct SettingsSwitch: View {
    @Binding var isOn: Bool
    @Environment(\.backgroundProminence) private var prominence

    var body: some View {
        Toggle("", isOn: $isOn)
            .toggleStyle(.switch)
            .labelsHidden()
            .controlSize(.small)
            // A blue track disappears on a selected list row.
            .tint(prominence == .increased ? Color.settingsSwitchOnSelection : Color.brandControl)
    }
}

/// Rounded brand-blue square with a white glyph, as in the macOS System Settings sidebar.
struct SettingsIconTile: View {
    let symbol: String
    var size: CGFloat = 22

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
            .fill(
                LinearGradient(
                    colors: [.settingsTileTop, .settingsTileBottom], startPoint: .top, endPoint: .bottom)
            )
            // Keeps the tile distinct on the blue sidebar selection.
            .overlay(
                RoundedRectangle(cornerRadius: size * 0.27, style: .continuous)
                    .strokeBorder(.white.opacity(0.35), lineWidth: 0.75)
            )
            .overlay(
                // A fixed glyph box: the sidebar list scales symbol images up otherwise.
                Image(systemName: symbol)
                    .resizable()
                    .scaledToFit()
                    .fontWeight(.semibold)
                    .foregroundStyle(.white)
                    .frame(width: size * 0.56, height: size * 0.56)
            )
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }
}

/// Colored dot followed by a status word.
struct StatusIndicator: View {
    let text: String
    let color: Color

    init(_ text: String, color: Color) {
        self.text = text
        self.color = color
    }

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(color)
                .frame(width: 7, height: 7)
                .background(Circle().fill(color.opacity(0.22)).frame(width: 13, height: 13))
            Text(text)
                .font(.system(size: 12.5, weight: .medium))
                .foregroundStyle(color)
        }
    }
}

struct StatusPill: View {
    let text: String
    let color: Color

    init(_ text: String, color: Color) {
        self.text = text
        self.color = color
    }

    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(Capsule().fill(color.opacity(0.15)))
    }
}

/// Inline notice with a tinted background, used for warnings and errors.
struct SettingsNotice<Action: View>: View {
    let symbol: String
    let title: String
    let message: String?
    let color: Color
    let action: Action

    init(
        symbol: String, title: String, message: String? = nil, color: Color,
        @ViewBuilder action: () -> Action = { EmptyView() }
    ) {
        self.symbol = symbol
        self.title = title
        self.message = message
        self.color = color
        self.action = action()
    }

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: SettingsMetrics.cardCornerRadius, style: .continuous)
        HStack(alignment: .center, spacing: 10) {
            Image(systemName: symbol)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(color)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 12.5, weight: .semibold))
                if let message {
                    Text(message)
                        .font(.system(size: 12))
                        .foregroundStyle(Color.settingsSecondaryText)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 8)
            action
        }
        .padding(.horizontal, 13)
        .padding(.vertical, 11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(shape.fill(color.opacity(0.10)))
        .overlay(shape.strokeBorder(color.opacity(0.35), lineWidth: 1))
    }
}

/// Native sidebar search field. `.searchable(placement: .sidebar)` keeps its field out of the
/// Tab loop on macOS 14, and `searchFocused` needs macOS 15.
struct SettingsSearchField: NSViewRepresentable {
    @Binding var text: String

    func makeNSView(context: Context) -> NSSearchField {
        let field = SidebarSearchField()
        field.placeholderString = "Search"
        field.sendsSearchStringImmediately = true
        field.delegate = context.coordinator
        field.target = context.coordinator
        field.action = #selector(Coordinator.searchChanged(_:))
        return field
    }

    func updateNSView(_ field: NSSearchField, context: Context) {
        if field.stringValue != text { field.stringValue = text }
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    /// AppKit gives initial focus to the first key view, which is this field. System Settings
    /// opens with the sidebar list focused instead, so the field hands that focus to the list.
    final class SidebarSearchField: NSSearchField {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            DispatchQueue.main.async { [weak self] in
                guard let self, let window, let editor = currentEditor(), window.firstResponder === editor,
                    let list = sidebarList()
                else { return }
                window.makeFirstResponder(list)
            }
        }

        private func sidebarList() -> NSTableView? {
            var column: NSView? = self
            while let view = column, !(view.superview is NSSplitView) { column = view.superview }
            return column.flatMap { Self.firstTable(in: $0) }
        }

        private static func firstTable(in view: NSView) -> NSTableView? {
            if let table = view as? NSTableView { return table }
            return view.subviews.lazy.compactMap { firstTable(in: $0) }.first
        }
    }

    final class Coordinator: NSObject, NSSearchFieldDelegate {
        private let text: Binding<String>

        init(text: Binding<String>) { self.text = text }

        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSSearchField else { return }
            text.wrappedValue = field.stringValue
        }

        // The clear button and Escape change the value without a text-change notification.
        @objc func searchChanged(_ field: NSSearchField) {
            text.wrappedValue = field.stringValue
        }
    }
}

// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import SwiftUI

/// A segmented `Picker` for a value an `ObservableObject` publishes.
///
/// On macOS the segmented control writes its binding while SwiftUI is still
/// updating the view, so binding it straight to a `@Published` property logs
/// "Publishing changes from within view updates" as a fault on every click.
/// The control selects into local state and `onChange` forwards the value
/// after the update. Changes from the model come back the same way.
struct SegmentedPicker<Value: Hashable, Content: View>: View {
    private let title: String
    @Binding private var selection: Value
    private let content: Content
    @State private var shown: Value

    init(_ title: String, selection: Binding<Value>, @ViewBuilder content: () -> Content) {
        self.title = title
        _selection = selection
        self.content = content()
        _shown = State(initialValue: selection.wrappedValue)
    }

    var body: some View {
        Picker(title, selection: $shown) { content }
            .pickerStyle(.segmented)
            .onChange(of: shown) { _, value in
                if selection != value { selection = value }
            }
            .onChange(of: selection) { _, value in
                if shown != value { shown = value }
            }
    }
}

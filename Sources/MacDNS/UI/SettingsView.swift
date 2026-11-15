// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import Shared
import SwiftUI

struct SettingsView: View {
    @ObservedObject var viewModel: AppViewModel
    @State private var current = SettingsNavigationMemory.lastSection
    @State private var query = ""

    private var selection: Binding<SettingsSection?> {
        Binding(
            get: { current },
            set: { section in
                guard let section else { return }
                current = section
                SettingsNavigationMemory.lastSection = section
            }
        )
    }

    var body: some View {
        NavigationSplitView {
            SettingsSidebar(viewModel: viewModel, selection: selection, query: query)
                .safeAreaInset(edge: .top, spacing: 6) {
                    SettingsSearchField(text: $query)
                        .padding(.horizontal, 10)
                }
                .navigationSplitViewColumnWidth(min: 215, ideal: 220, max: 280)
                .frame(minWidth: 215)
                .toolbar(removing: .sidebarToggle)
        } detail: {
            detail(for: current)
                // The toolbar shows the page color, so it does not read as a white band over the sidebar.
                .toolbarBackground(.hidden, for: .windowToolbar)
        }
        .toolbar {
            ToolbarItemGroup(placement: .navigation) {
                // Steps through the sidebar in order, so every section is one click away.
                Button {
                    selection.wrappedValue = current.previous
                } label: {
                    Label("Previous", systemImage: "chevron.left")
                }
                .help(current.previous.map { "Previous: \($0.title)" } ?? "Previous")
                .keyboardShortcut("[", modifiers: .command)
                .disabled(current.previous == nil)

                Button {
                    selection.wrappedValue = current.next
                } label: {
                    Label("Next", systemImage: "chevron.right")
                }
                .help(current.next.map { "Next: \($0.title)" } ?? "Next")
                .keyboardShortcut("]", modifiers: .command)
                .disabled(current.next == nil)
            }
        }
        .tint(.brandControl)
        .frame(minWidth: 760, minHeight: 540)
        .background(UnifiedToolbarWindow())
        .disabled(viewModel.softwareUpdateSuspended)
        .onAppear {
            current = SettingsNavigationMemory.lastSection
            SettingsWindowController.shared.settingsDidAppear()
            viewModel.checkServicesStatus()
            viewModel.loadUpdateInfo()
            viewModel.loadLicenseInfo()
        }
    }

    @ViewBuilder
    private func detail(for section: SettingsSection) -> some View {
        switch section {
        case .overview:
            OverviewSection(viewModel: viewModel, onNavigate: { selection.wrappedValue = $0 })
        case .resolver:
            ResolverSection(viewModel: viewModel)
        case .advanced:
            AdvancedSection(viewModel: viewModel)
        case .forwardZones:
            ForwardZonesSection(viewModel: viewModel)
        case .overrides:
            OverridesSection(viewModel: viewModel)
        case .blocklist:
            BlocklistSection(viewModel: viewModel)
        case .allowlist:
            AllowlistSection(viewModel: viewModel)
        case .queries:
            QueriesSection(viewModel: viewModel, onNavigate: { selection.wrappedValue = $0 })
        case .activity:
            ActivitySection(viewModel: viewModel, onNavigate: { selection.wrappedValue = $0 })
        case .licenseUpdates:
            LicenseUpdatesSection(viewModel: viewModel)
        }
    }
}

/// The Settings scene opens with the centered `.preference` toolbar, which ignores the
/// split view's title and back/forward placement. The unified style matches System Settings.
private struct UnifiedToolbarWindow: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView { WindowObserver() }
    func updateNSView(_ nsView: NSView, context: Context) {}

    private final class WindowObserver: NSView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            window?.toolbarStyle = .unified
        }
    }
}

#Preview {
    SettingsView(viewModel: AppViewModel())
}

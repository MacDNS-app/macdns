// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import SwiftUI

@main
struct MacDNSApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        MenuBarExtra {
            MenuBarPopup(viewModel: appDelegate.viewModel)
        } label: {
            Image("MenuBarIcon")
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView(viewModel: appDelegate.viewModel)
        }
    }
}

// MARK: - App Delegate
@MainActor
class AppDelegate: NSObject, NSApplicationDelegate {
    lazy var viewModel = AppViewModel()

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        UpdaterManager.shared.startUpdater()

        // Observe Agent updates even when no menu or settings view has been rendered.
        _ = viewModel

        Task { await FirstRunWindowController.shared.presentIfNeeded(viewModel: viewModel) }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        SettingsWindowController.shared.openSettings()
        return true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // Quitting from the first-run window before setup starts, or right
        // after closing it, waits until the trial request is sent.
        let firstRunTrialStep = FirstRunWindowController.shared.exitTrialStepForQuit()
        let updatePending = UpdaterManager.shared.installationPending
        guard firstRunTrialStep != nil || updatePending else { return .terminateNow }
        Task { @MainActor in
            await firstRunTrialStep?.value
            var ready = true
            if updatePending {
                ready = await UpdaterManager.shared.prepareForUpdateTermination()
            }
            sender.reply(toApplicationShouldTerminate: ready)
        }
        return .terminateLater
    }
}

// MARK: - Settings Window Controller
class SettingsWindowController: ObservableObject {
    static let shared = SettingsWindowController()

    @Published private(set) var isOnScreen = false
    private var settingsWindowObserver: NSObjectProtocol?
    private var settingsWindowKeyObserver: NSObjectProtocol?

    init() {
        isOnScreen = NSApp.windows.contains { isSettingsWindow($0) && $0.occlusionState.contains(.visible) }
        NotificationCenter.default.publisher(for: NSWindow.didChangeOcclusionStateNotification)
            .compactMap { [weak self] notification -> Bool? in
                guard let window = notification.object as? NSWindow, self?.isSettingsWindow(window) == true else {
                    return nil
                }
                return window.occlusionState.contains(.visible)
            }
            .removeDuplicates()
            .assign(to: &$isOnScreen)

        // SwiftUI keeps the Settings view alive after its window closes, so
        // onAppear does not fire on reopen. The window becoming key does.
        settingsWindowKeyObserver = NotificationCenter.default.addObserver(
            forName: NSWindow.didBecomeKeyNotification,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let window = notification.object as? NSWindow else { return }
            if self?.isSettingsWindow(window) == true {
                self?.settingsDidAppear()
            }
        }

        settingsWindowObserver = NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let window = notification.object as? NSWindow else { return }
            if self?.isSettingsWindow(window) == true {
                // Delay to let window close animation finish
                DispatchQueue.main.asyncAfter(deadline: .now() + UIConstants.dockHideDelay) {
                    self?.hideFromDockIfNoWindows()
                }
            }
        }
    }

    /// Show in the Dock only when Settings actually appears.
    func settingsDidAppear() {
        guard NSApp.activationPolicy() != .regular else { return }
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// AppKit path for the app delegate, which has no SwiftUI `openSettings` action.
    func openSettings() {
        NSApp.activate(ignoringOtherApps: true)

        // Let activation finish before requesting the settings window.
        DispatchQueue.main.asyncAfter(deadline: .now() + UIConstants.shortDelay) {
            // macOS 14+ names the action showSettingsWindow:, earlier releases showPreferencesWindow:.
            if !NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil) {
                NSApp.sendAction(Selector(("showPreferencesWindow:")), to: nil, from: nil)
            }

            DispatchQueue.main.asyncAfter(deadline: .now() + UIConstants.standardDelay) {
                for window in NSApp.windows where self.isSettingsWindow(window) {
                    window.makeKeyAndOrderFront(nil)
                    NSApp.activate(ignoringOtherApps: true)
                    break
                }
            }
        }
    }

    private func isSettingsWindow(_ window: NSWindow) -> Bool {
        let identifier = window.identifier?.rawValue ?? ""
        let title = window.title
        return identifier.lowercased().contains("settings") || identifier.lowercased().contains("preferences")
            || title.contains("Settings") || title.contains("Preferences")
            || window.contentView?.subviews.first is NSHostingView<SettingsView>
    }

    private func hideFromDockIfNoWindows() {
        let hasVisibleSettings = NSApp.windows.contains { window in
            isSettingsWindow(window) && window.isVisible
        }

        if !hasVisibleSettings {
            NSApp.setActivationPolicy(.accessory)
        }
    }
}

// MARK: - Menu Bar Popup View (Tailscale-style)
struct MenuBarPopup: View {
    @ObservedObject var viewModel: AppViewModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openSettings) private var openSettings

    @State private var showConfigPopover = false
    @State private var isMouseInConfigPopover = false
    @State private var showOverridesPopover = false
    @State private var isMouseInPopover = false

    var body: some View {
        VStack(spacing: 0) {
            headerSection

            Divider()
                .padding(.vertical, 4)

            configButton

            overridesButton

            Divider()
                .padding(.vertical, 4)

            SettingsMenuButton {
                dismiss()
                // An inactive accessory app opens Settings behind other apps and
                // never makes it key, so activate first. The Dock switch waits
                // for the window.
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                    NSApp.activate(ignoringOtherApps: true)
                    openSettings()
                }
            }

            Divider()
                .padding(.vertical, 4)

            QuitCompletelyButton(viewModel: viewModel)
            QuitMenuButton()
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .frame(width: 240)
        .background(MenuMaterialBackground().ignoresSafeArea())
        .disabled(viewModel.softwareUpdateSuspended)
        .onAppear {
            viewModel.checkServicesStatus()
        }
    }

    // MARK: - Configuration Button
    private var configButton: some View {
        ConfigurationMenuButton(
            isPopoverPresented: $showConfigPopover,
            isMouseInPopover: $isMouseInConfigPopover
        )
        .popover(isPresented: $showConfigPopover, arrowEdge: .trailing) {
            ConfigurationPopover(viewModel: viewModel, isPresented: $showConfigPopover)
                .onHover { isMouseInConfigPopover = $0 }
        }
    }

    // MARK: - DNS Overrides Button
    private var overridesButton: some View {
        OverridesMenuButton(
            count: viewModel.dnsOverrides.count,
            isPopoverPresented: $showOverridesPopover,
            isMouseInPopover: $isMouseInPopover
        )
        .popover(isPresented: $showOverridesPopover, arrowEdge: .trailing) {
            OverridesPopover(viewModel: viewModel)
                .onHover { hovering in
                    isMouseInPopover = hovering
                }
        }
    }

    // MARK: - Header Section (Tailscale style)
    private var headerSection: some View {
        HStack(spacing: 10) {
            if viewModel.persistedStateAvailability == .loaded {
                Image(viewModel.protectionDisplayState.iconName)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .frame(width: 32, height: 32)
            } else if viewModel.persistedStateAvailability == .invalidConfiguration {
                Image(systemName: "exclamationmark.triangle.fill")
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .foregroundStyle(.orange)
                    .frame(width: 32, height: 32)
            } else {
                Image("StatusOff")
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .frame(width: 32, height: 32)
            }

            VStack(alignment: .leading, spacing: 0) {
                Text("MacDNS")
                    .font(.menu)
                    .fontWeight(.semibold)
                Text(
                    viewModel.persistedStateAvailability.statusMessageOverride
                        ?? viewModel.statusMessage
                )
                .font(.subheadline)
                .foregroundColor(.secondary)
                .lineLimit(1)
                .truncationMode(.tail)
            }
            .frame(maxWidth: 120, alignment: .leading)

            Spacer()

            if viewModel.persistedStateAvailability.showsProtectionToggle {
                Toggle(
                    "",
                    isOn: Binding(
                        get: { viewModel.isEnabled },
                        set: { _ in viewModel.toggleDNS() }
                    )
                )
                .toggleStyle(.switch)
                .labelsHidden()
                .scaleEffect(0.8)
                .tint(viewModel.isEnabled && !viewModel.isLicenseValid ? .orange : .accentColor)
                .focusable(false)
            } else if viewModel.persistedStateAvailability.showsProgressIndicator {
                ProgressView()
                    .controlSize(.small)
                    .frame(width: 32)
            } else {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .frame(width: 32)
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Settings Menu Button
struct SettingsMenuButton: View {
    let onTap: () -> Void
    @State private var isHovered = false

    var body: some View {
        Button(action: {
            onTap()
        }) {
            HStack {
                Text("Settings...")
                    .font(.menu)
                Spacer()
                Text("⌘,")
                    .font(.menu)
                    .foregroundColor(isHovered ? .white.opacity(0.7) : .secondary)
            }
            .padding(.vertical, 4)
            .padding(.horizontal, 8)
            .background(isHovered ? Color.accentColor : Color.clear)
            .foregroundColor(isHovered ? .white : .primary)
            .cornerRadius(4)
        }
        .buttonStyle(.plain)
        .focusable(false)
        .onHover { hovering in
            isHovered = hovering
        }
    }
}

// MARK: - Quit Menu Button
struct QuitMenuButton: View {
    @State private var isHovered = false

    var body: some View {
        Button(action: {
            NSApplication.shared.terminate(nil)
        }) {
            HStack {
                Text("Quit MacDNS")
                    .font(.menu)
                Spacer()
                Text("⌘Q")
                    .font(.menu)
                    .foregroundColor(isHovered ? .white.opacity(0.7) : .secondary)
            }
            .padding(.vertical, 4)
            .padding(.horizontal, 8)
            .background(isHovered ? Color.accentColor : Color.clear)
            .foregroundColor(isHovered ? .white : .primary)
            .cornerRadius(4)
        }
        .buttonStyle(.plain)
        .focusable(false)
        .onHover { hovering in
            isHovered = hovering
        }
    }
}

// MARK: - Quit Completely Menu Button
struct QuitCompletelyButton: View {
    @ObservedObject var viewModel: AppViewModel
    @State private var isHovered = false

    var body: some View {
        Button(action: {
            Task { await viewModel.quitCompletely() }
        }) {
            HStack {
                Text("Quit and Remove Services")
                    .font(.menu)
                Spacer()
            }
            .padding(.vertical, 4)
            .padding(.horizontal, 8)
            .background(isHovered ? Color.accentColor : Color.clear)
            .foregroundColor(isHovered ? .white : .primary)
            .cornerRadius(4)
        }
        .buttonStyle(.plain)
        .focusable(false)
        .onHover { hovering in
            isHovered = hovering
        }
    }
}

// MARK: - DNS Overrides Menu Button
struct OverridesMenuButton: View {
    let count: Int
    @Binding var isPopoverPresented: Bool
    @Binding var isMouseInPopover: Bool
    @State private var isHovered = false
    @State private var closeTask: DispatchWorkItem?

    private var isHighlighted: Bool {
        isHovered || isPopoverPresented
    }

    var body: some View {
        HStack {
            Text("Local Records")
                .font(.menu)
            Spacer()
            if count > 0 {
                Text("(\(count))")
                    .font(.menu)
                    .foregroundColor(isHighlighted ? .white.opacity(0.7) : .secondary)
            }
            Image(systemName: "chevron.right")
                .font(.system(size: 10))
                .foregroundColor(isHighlighted ? .white.opacity(0.7) : .secondary)
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 8)
        .background(isHighlighted ? Color.accentColor : Color.clear)
        .foregroundColor(isHighlighted ? .white : .primary)
        .cornerRadius(4)
        .contentShape(Rectangle())
        .onTapGesture {
            isPopoverPresented.toggle()
        }
        .onHover { hovering in
            isHovered = hovering
            if hovering {
                closeTask?.cancel()
                closeTask = nil
                isPopoverPresented = true
            } else {
                scheduleClose()
            }
        }
        .onChange(of: isPopoverPresented) { _, newValue in
            if !newValue {
                isMouseInPopover = false
            }
        }
        .onChange(of: isMouseInPopover) { _, inPopover in
            if inPopover {
                closeTask?.cancel()
                closeTask = nil
            } else if !isHovered {
                scheduleClose()
            }
        }
    }

    private func scheduleClose() {
        closeTask?.cancel()
        let task = DispatchWorkItem { [self] in
            if !isHovered && !isMouseInPopover {
                isPopoverPresented = false
            }
        }
        closeTask = task
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05, execute: task)
    }
}

// MARK: - Configuration Menu Button
struct ConfigurationMenuButton: View {
    @Binding var isPopoverPresented: Bool
    @Binding var isMouseInPopover: Bool
    @State private var isHovered = false
    @State private var closeTask: DispatchWorkItem?

    private var isHighlighted: Bool {
        isHovered || isPopoverPresented
    }

    var body: some View {
        HStack {
            Text("Configuration")
                .font(.menu)
            Spacer()
            Image(systemName: "chevron.right")
                .font(.system(size: 10))
                .foregroundColor(isHighlighted ? .white.opacity(0.7) : .secondary)
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 8)
        .background(isHighlighted ? Color.accentColor : Color.clear)
        .foregroundColor(isHighlighted ? .white : .primary)
        .cornerRadius(4)
        .contentShape(Rectangle())
        .onTapGesture {
            isPopoverPresented.toggle()
        }
        .onHover { hovering in
            isHovered = hovering
            if hovering {
                closeTask?.cancel()
                closeTask = nil
                isPopoverPresented = true
            } else {
                scheduleClose()
            }
        }
        .onChange(of: isPopoverPresented) { _, newValue in
            if !newValue {
                isMouseInPopover = false
            }
        }
        .onChange(of: isMouseInPopover) { _, inPopover in
            if inPopover {
                closeTask?.cancel()
                closeTask = nil
            } else if !isHovered {
                scheduleClose()
            }
        }
    }

    private func scheduleClose() {
        closeTask?.cancel()
        let task = DispatchWorkItem { [self] in
            if !isHovered && !isMouseInPopover {
                isPopoverPresented = false
            }
        }
        closeTask = task
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05, execute: task)
    }
}

#Preview {
    MenuBarPopup(viewModel: AppViewModel())
        .frame(width: 240)
}

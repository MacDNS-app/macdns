// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit

/// The only first-run message the app shows itself, for the two outcomes
/// macOS does not explain. Each alert runs after the current event returns,
/// with the menu bar app activated first.
@MainActor
enum FreshInstallSetupAlert {
    static func presentRestartRequired() {
        let alert = NSAlert()
        alert.messageText = "Restart to finish setting up MacDNS"
        alert.informativeText =
            "macOS finishes installing MacDNS after a restart. Then open MacDNS and turn it on in the menu bar."
        alert.addButton(withTitle: "OK")
        present(alert) { _ in }
    }

    static func presentFailure(
        message: String,
        completion: @escaping @MainActor (_ tryAgain: Bool) -> Void
    ) {
        let alert = NSAlert()
        alert.messageText = "MacDNS didn't start"
        alert.informativeText = message
        alert.addButton(withTitle: "Try Again")
        alert.addButton(withTitle: "Close")
        present(alert) { response in
            completion(response == .alertFirstButtonReturn)
        }
    }

    private static func present(
        _ alert: NSAlert,
        completion: @escaping @MainActor (NSApplication.ModalResponse) -> Void
    ) {
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.main.async {
            MainActor.assumeIsolated {
                completion(alert.runModal())
            }
        }
    }
}

// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

/// One-shot gate that holds the fresh install Enable before a macOS request
/// until the first-run window answers with "Continue", "Skip" or a close.
@MainActor
final class FirstRunContinueGate {
    private var opened = false
    private var continuation: CheckedContinuation<Void, Never>?

    /// Without the window nothing could open the gate. A done step needs no
    /// request, and the step answered by the click that started setup needs
    /// no second click.
    nonisolated static func waits(stepDone: Bool, windowOpen: Bool, approved: Bool) -> Bool {
        windowOpen && !stepDone && !approved
    }

    /// Returns when `open()` is called, at once if it already was.
    func wait() async {
        guard !opened else { return }
        await withCheckedContinuation { continuation in
            self.continuation = continuation
        }
    }

    func open() {
        guard !opened else { return }
        opened = true
        continuation?.resume()
        continuation = nil
    }
}

// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

/// One-shot gate for the first-run notification request. A request the user
/// never answers stays in Notification Center, so "Skip" and closing the
/// window end the wait without the answer.
@MainActor
final class FirstRunNotificationWait {
    private var ended = false
    private var continuation: CheckedContinuation<Void, Never>?

    enum Request: Equatable {
        /// Ask and wait for the answer before the resolver starts.
        case beforeResolver
        /// Ask once protection starts, as for every other Enable.
        case afterProtectionStarts
        /// "Skip" was clicked. Asking after protection starts could show the
        /// request together with the local network request, so the setup does
        /// not ask. The next launch asks once protection is on.
        case skipped
    }

    /// When the setup asks for notifications. Without the window nothing could
    /// end the wait, so the request stays after protection starts.
    nonisolated static func request(notificationsDecided: Bool, skipped: Bool, windowOpen: Bool) -> Request {
        if skipped { return .skipped }
        return !notificationsDecided && windowOpen ? .beforeResolver : .afterProtectionStarts
    }

    /// Returns when `answer` returns or `end()` is called, whichever is first.
    /// Returns at once, without calling `answer`, once ended.
    func wait(for answer: @escaping () async -> Void) async {
        guard !ended else { return }
        await withCheckedContinuation { continuation in
            self.continuation = continuation
            Task { @MainActor [weak self] in
                await answer()
                self?.end()
            }
        }
    }

    func end() {
        guard !ended else { return }
        ended = true
        continuation?.resume()
        continuation = nil
    }
}

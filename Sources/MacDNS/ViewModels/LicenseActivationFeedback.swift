// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared

/// What the About tab shows after an activation attempt. Success comes from the
/// result case, never from the message text.
struct LicenseActivationFeedback: Equatable {
    let message: String
    let isSuccess: Bool

    init(outcome: Result<LicenseActivationResult, XPCError>) {
        switch outcome {
        case .success(let result):
            self.init(result: result)
        // The agent may still finish the activation after the App stops waiting.
        case .failure(.timeout):
            self.init(
                message: "MacDNS did not answer in time. Press Refresh to see if the key was activated.",
                isSuccess: false
            )
        case .failure:
            self.init(message: "Failed to connect to agent", isSuccess: false)
        }
    }

    private init(result: LicenseActivationResult) {
        switch result {
        case .success(let message):
            self.init(message: message, isSuccess: true)
        case .alreadyActivated:
            self.init(message: "License already activated on this machine", isSuccess: true)
        case .error(let message):
            self.init(message: message, isSuccess: false)
        case .machineLimit(let limit):
            self.init(message: "Machine limit reached (\(limit) machines)", isSuccess: false)
        case .invalidKey:
            self.init(message: "Invalid license key", isSuccess: false)
        case .networkError(let message):
            self.init(message: "Network error: \(message)", isSuccess: false)
        }
    }

    private init(message: String, isSuccess: Bool) {
        self.message = message
        self.isSuccess = isSuccess
    }
}

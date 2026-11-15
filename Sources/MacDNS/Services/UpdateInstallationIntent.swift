// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

/// Tracks whether quitting can let Sparkle replace the bundle, even after its UI closes.
struct UpdateInstallationIntent {
    enum Event {
        case extractionStarted
        case readyToInstall
        case dismissed
        case skipped
        case installationFailed
        case discoveryFinished
        case downloadedUpdateResumed
    }

    private(set) var requiresPreparation = false

    mutating func receive(_ event: Event) {
        switch event {
        case .extractionStarted, .readyToInstall:
            requiresPreparation = true
        case .skipped, .installationFailed, .downloadedUpdateResumed:
            requiresPreparation = false
        case .dismissed, .discoveryFinished:
            break
        }
    }
}

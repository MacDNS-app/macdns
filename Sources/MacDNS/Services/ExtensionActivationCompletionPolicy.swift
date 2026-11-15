// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

struct ExtensionActivationCompletionPolicy: Equatable {
    let hadWaitingContinuations: Bool
    let providerConfigured: Bool
    let registrationDeferred: Bool

    var shouldRegisterProviderAfterCompletion: Bool {
        !hadWaitingContinuations && !providerConfigured && !registrationDeferred
    }
}

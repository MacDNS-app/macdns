// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

/// Bridges the synchronous XPC exported-object handlers to the async license
/// actor.
///
/// Apple serializes calls to an exported object, so a handler that blocks on a
/// semaphore removes the entire App control channel until it returns. These
/// handlers start a task and reply asynchronously instead, with the XPC
/// protocol signature unchanged.
struct LicenseXPCDispatch: Sendable {
    let validate: @Sendable () async -> Bool
    let info: @Sendable () async -> LicenseInfo

    static let live = LicenseXPCDispatch(
        validate: { await LicenseManager.shared.ensureValidLicense() },
        info: { await LicenseManager.shared.getLicenseInfo() }
    )

    func ensureValidLicense(reply: @escaping @Sendable (Bool) -> Void) {
        Task { [validate] in
            reply(await validate())
        }
    }

    func licenseInfo(reply: @escaping @Sendable (LicenseInfo) -> Void) {
        Task { [info] in
            reply(await info())
        }
    }
}

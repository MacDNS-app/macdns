// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import ServiceManagement
import SystemExtensions

enum CleanupOutcome {
    static func isExpectedAbsence(_ error: Error) -> Bool {
        if case AgentError.unregistrationFailed(let underlying) = error {
            return isExpectedAbsence(underlying)
        }
        let error = error as NSError
        return (error.domain == "SMAppServiceErrorDomain" && error.code == kSMErrorJobNotFound)
            || (error.domain == OSSystemExtensionErrorDomain
                && error.code == OSSystemExtensionError.extensionNotFound.rawValue)
    }

    static func needsReboot(_ result: OSSystemExtensionRequest.Result) -> Bool {
        result == .willCompleteAfterReboot
    }
}

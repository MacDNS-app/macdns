// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

/// Explains a license block that the license status alone cannot, so the user
/// knows what to do instead of seeing a valid license that does not work.
enum LicenseBlockReason {
    /// `operationInterrupted` means a license operation journal is still on
    /// disk. The next license check finishes it. `machineIdentityUnavailable`
    /// means the last hardware read gave no fingerprint, so no license check
    /// could run. `checkUnanswered` means the last check got no answer from the
    /// license server and denied service, while the status still reads as a
    /// license that works or is being checked.
    static func message(
        latch: LicenseFailClosedReason?,
        clockTrusted: Bool,
        licenseFileExists: Bool = true,
        operationInterrupted: Bool = false,
        machineIdentityUnavailable: Bool = false,
        checkUnanswered: Bool = false
    ) -> String? {
        switch latch {
        case nil where machineIdentityUnavailable,
            .networkGraceExpired where machineIdentityUnavailable:
            return
                "MacDNS can't read this Mac's hardware ID, which your license is tied to. Press Refresh to try again."
        case .stateLoadFailed where !licenseFileExists:
            return "Turn MacDNS on again to restore your license. If you bought a license, enter your key again."
        case .statePersistenceFailed where operationInterrupted:
            return "A license check was interrupted. Turn MacDNS on again to finish it."
        case .stateLoadFailed:
            let folder = (PathResolver.applicationSupportDir.path as NSString)
                .abbreviatingWithTildeInPath
            return
                "MacDNS can't read license.json. Delete it from \(folder) and turn MacDNS on again. If you bought a license, enter your key again."
        case .statePersistenceFailed:
            return "MacDNS can't save license.json. Free up disk space and turn MacDNS on again."
        case .networkGraceExpired:
            return "MacDNS needs to check your license online. Connect to the internet and it checks again."
        case nil where !clockTrusted:
            return
                "Your Mac's clock is behind. Turn on \"Set time and date automatically\" in System Settings."
        case nil:
            return checkUnanswered
                ? "MacDNS couldn't check your license. Connect to the internet and it tries again."
                : nil
        }
    }
}

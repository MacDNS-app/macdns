// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import NetworkExtension

// Registers ContentFilterProvider with the ObjC runtime before
// NEProvider.startSystemExtensionMode() looks it up. Without this reference the
// lookup can fail with "No such class".
_ = ContentFilterProvider.self

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()

// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// How long the Agent may spend on Keygen. The App waits for a license answer
/// longer than `operation`, so it never reports a failure the Agent did not
/// have.
public enum LicenseRequestBudget {
    /// One Keygen request, from connecting to the last byte.
    public static let perRequest: TimeInterval = 10

    /// The longest chain of requests one license operation sends: validate the
    /// key, activate the machine, find the seat that already exists, and
    /// validate again for a receipt. A new trial sends three: lookup, create
    /// and lookup again.
    public static let maxRequestsPerOperation = 4

    /// Hardware identity reads one operation makes: one before each request,
    /// and one more to match the stored answer when the last request fails.
    public static let maxIdentityReadsPerOperation = maxRequestsPerOperation + 1

    /// Reading the hardware identity, which takes up to 2 s each time on a Mac
    /// without a serial number, verifying answers and saving state.
    public static let localWork: TimeInterval = 15

    /// The longest one license operation takes in the Agent, and so the
    /// longest one waits for another to finish.
    public static let operation =
        perRequest * TimeInterval(maxRequestsPerOperation) + localWork
}

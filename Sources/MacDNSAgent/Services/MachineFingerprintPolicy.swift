// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import CryptoKit
import Foundation

/// What one read of the platform expert and `hw.model` reported.
///
/// A reader returns nil when any read fails, so `Serial.absent` only ever
/// comes from a read that succeeded without a serial number.
struct HardwareIdentityReading: Equatable, Sendable {
    enum Serial: Equatable, Sendable {
        case present(String)
        case absent
    }

    let platformUUID: String
    let serial: Serial
    let modelIdentifier: String
}

enum MachineIdentityResolution: Equatable, Sendable {
    case fingerprint(String)
    /// A hardware read failed.
    case unreadable
    /// The serial number was missing and then came back, so neither value can
    /// be trusted as this Mac's identity.
    case unstable
}

/// Derives the machine identity used as the Keygen trial key and machine
/// fingerprint.
///
/// The identity is derived from the hardware on every use and never stored:
/// `license.json` is user-writable, and a stored fingerprint would let anyone
/// mint a new trial by editing it. The formula is the one 1.x used, so a later
/// change cannot migrate through a stored value and has to try this formula
/// before allocating a trial or a seat.
enum MachineFingerprintPolicy {
    static let serialAbsenceSamples = 3
    static let serialAbsenceSampleInterval: TimeInterval = 1

    /// `sha256` of the components IOKit returned, verbatim, joined by `|`. An
    /// absent serial is skipped, exactly as 1.x did, so a Mac without one keeps
    /// the trial and seat it already holds.
    static func fingerprint(for reading: HardwareIdentityReading) -> String? {
        guard !reading.platformUUID.isEmpty, !reading.modelIdentifier.isEmpty else {
            return nil
        }
        var components = [reading.platformUUID]
        if case .present(let serial) = reading.serial {
            components.append(serial)
        }
        components.append(reading.modelIdentifier)

        let data = Data(components.joined(separator: "|").utf8)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Reads the hardware identity once, or several times when the serial is
    /// absent. A misread absence would create a trial or take a seat under
    /// another identity, so it counts only when every sample agrees.
    static func resolve(
        read: () async -> HardwareIdentityReading?,
        sleep: (TimeInterval) async -> Void
    ) async -> MachineIdentityResolution {
        guard let first = await read() else { return .unreadable }
        if first.serial == .absent {
            for _ in 1..<serialAbsenceSamples {
                await sleep(serialAbsenceSampleInterval)
                guard let sample = await read() else { return .unreadable }
                guard sample == first else { return .unstable }
            }
        }
        guard let fingerprint = fingerprint(for: first) else { return .unreadable }
        return .fingerprint(fingerprint)
    }
}

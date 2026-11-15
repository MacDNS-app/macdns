// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import CryptoKit
import Foundation
import Shared
import XCTest

@testable import MacDNSAgent

final class LicenseMachineFingerprintTests: XCTestCase {

    // MARK: - Derivation

    /// The fingerprint is the Keygen trial key and machine fingerprint since
    /// 1.x, so it must hash exactly what 1.1.22 hashed: every component IOKit
    /// returned, verbatim, joined by `|`.
    func testFullIdentityMatchesTheVersionOneHash() {
        XCTAssertEqual(
            MachineFingerprintPolicy.fingerprint(
                for: reading(serial: .present("serial-1"))
            ),
            sha256("uuid-1|serial-1|MacBookPro18,1")
        )
    }

    /// 1.1.22 skipped a serial IOKit did not return. Hashing the same string
    /// keeps the trial and seat such a Mac already holds.
    func testAbsentSerialMatchesTheVersionOneHash() {
        XCTAssertEqual(
            MachineFingerprintPolicy.fingerprint(for: reading(serial: .absent)),
            sha256("uuid-1|MacBookPro18,1")
        )
    }

    func testEmptySerialMatchesTheVersionOneHash() {
        XCTAssertEqual(
            MachineFingerprintPolicy.fingerprint(for: reading(serial: .present(""))),
            sha256("uuid-1||MacBookPro18,1")
        )
    }

    /// 1.1.22 never trimmed, so trimming would move such a Mac to a new identity.
    func testComponentsAreHashedVerbatim() {
        XCTAssertEqual(
            MachineFingerprintPolicy.fingerprint(
                for: reading(serial: .present(" serial-1 "))
            ),
            sha256("uuid-1| serial-1 |MacBookPro18,1")
        )
    }

    /// UUID and model are always present on a working Mac. Losing one means the
    /// read failed, and hashing the rest would change the identity.
    func testMissingUUIDOrModelIsRefused() {
        XCTAssertNil(
            MachineFingerprintPolicy.fingerprint(
                for: HardwareIdentityReading(
                    platformUUID: "",
                    serial: .present("serial-1"),
                    modelIdentifier: "MacBookPro18,1"
                )
            )
        )
        XCTAssertNil(
            MachineFingerprintPolicy.fingerprint(
                for: HardwareIdentityReading(
                    platformUUID: "uuid-1",
                    serial: .present("serial-1"),
                    modelIdentifier: ""
                )
            )
        )
    }

    // MARK: - Resolution

    func testFailedReadIsUnreadable() async {
        let reader = ScriptedReader([nil])

        let resolution = await resolve(reader)

        XCTAssertEqual(resolution, .unreadable)
    }

    func testPresentSerialNeedsASingleRead() async {
        let reader = ScriptedReader([reading(serial: .present("serial-1"))])

        let resolution = await resolve(reader)

        XCTAssertEqual(resolution, .fingerprint(sha256("uuid-1|serial-1|MacBookPro18,1")))
        XCTAssertEqual(reader.reads, 1)
        XCTAssertEqual(reader.sleeps, 0)
    }

    func testAbsentSerialIsConfirmedByConsistentReads() async {
        let reader = ScriptedReader(
            Array(
                repeating: reading(serial: .absent),
                count: MachineFingerprintPolicy.serialAbsenceSamples
            )
        )

        let resolution = await resolve(reader)

        XCTAssertEqual(resolution, .fingerprint(sha256("uuid-1|MacBookPro18,1")))
        XCTAssertEqual(reader.reads, MachineFingerprintPolicy.serialAbsenceSamples)
        XCTAssertEqual(reader.sleeps, MachineFingerprintPolicy.serialAbsenceSamples - 1)
    }

    /// A serial that comes back means the first read was wrong. Using either
    /// value could create a trial or take a seat under the wrong identity.
    func testSerialThatReappearsIsUnstable() async {
        let reader = ScriptedReader([
            reading(serial: .absent),
            reading(serial: .present("serial-1")),
        ])

        let resolution = await resolve(reader)

        XCTAssertEqual(resolution, .unstable)
    }

    func testReadFailureWhileConfirmingAbsenceIsUnreadable() async {
        let reader = ScriptedReader([reading(serial: .absent), nil])

        let resolution = await resolve(reader)

        XCTAssertEqual(resolution, .unreadable)
    }

    // MARK: - Persistence

    /// A fingerprint stored in the user-writable license file would let anyone
    /// mint a new trial by editing it, so it is never written or read back.
    func testLicenseStateNeverCarriesAFingerprint() throws {
        let encoded = try JSONCoding.encoder.encode(
            LicenseState(licenseKey: "key", status: .valid)
        )
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )

        XCTAssertNil(object["machineFingerprint"])
        XCTAssertNil(object["machineFingerprintVersion"])
    }

    func testStateWrittenWithAPinnedFingerprintStillDecodes() throws {
        let pinned = Data(
            #"{"status":"valid","licenseKey":"key","machineFingerprint":"forged","machineFingerprintVersion":1}"#
                .utf8
        )

        let decoded = try JSONCoding.decoder.decode(LicenseState.self, from: pinned)

        XCTAssertEqual(decoded.status, .valid)
        XCTAssertEqual(decoded.licenseKey, "key")
    }

    // MARK: - Helpers

    private func reading(serial: HardwareIdentityReading.Serial) -> HardwareIdentityReading {
        HardwareIdentityReading(
            platformUUID: "uuid-1",
            serial: serial,
            modelIdentifier: "MacBookPro18,1"
        )
    }

    private func resolve(_ reader: ScriptedReader) async -> MachineIdentityResolution {
        await MachineFingerprintPolicy.resolve(
            read: { reader.next() },
            sleep: { _ in reader.recordSleep() }
        )
    }

    private func sha256(_ input: String) -> String {
        SHA256.hash(data: Data(input.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

private final class ScriptedReader: @unchecked Sendable {
    private let lock = NSLock()
    private var script: [HardwareIdentityReading?]
    private var readCount = 0
    private var sleepCount = 0

    init(_ script: [HardwareIdentityReading?]) {
        self.script = script
    }

    var reads: Int { lock.withLock { readCount } }
    var sleeps: Int { lock.withLock { sleepCount } }

    func next() -> HardwareIdentityReading? {
        lock.withLock {
            readCount += 1
            return script.isEmpty ? nil : script.removeFirst()
        }
    }

    func recordSleep() {
        lock.withLock { sleepCount += 1 }
    }
}

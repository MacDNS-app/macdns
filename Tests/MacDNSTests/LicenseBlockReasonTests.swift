// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNSAgent

final class LicenseBlockReasonTests: XCTestCase {
    /// A corrupt license file blocks the Mac until the user removes it, so the
    /// reason must name the file and where it lives.
    func testUnreadableLicenseFileTellsTheUserWhichFileToRemove() throws {
        let message = try XCTUnwrap(
            LicenseBlockReason.message(latch: .stateLoadFailed, clockTrusted: true)
        )

        XCTAssertTrue(message.contains("license.json"))
        XCTAssertTrue(message.contains("~/Library/Application Support/MacDNS"))
    }

    func testRemovedLicenseFileNoLongerAsksToDeleteIt() throws {
        let message = try XCTUnwrap(
            LicenseBlockReason.message(
                latch: .stateLoadFailed,
                clockTrusted: true,
                licenseFileExists: false
            )
        )

        XCTAssertFalse(message.contains("Delete"))
        XCTAssertTrue(message.contains("Turn MacDNS on"))
    }

    /// An interrupted license operation is finished by the next check. Disk
    /// space has nothing to do with it.
    func testInterruptedOperationDoesNotBlameDiskSpace() throws {
        let message = try XCTUnwrap(
            LicenseBlockReason.message(
                latch: .statePersistenceFailed,
                clockTrusted: true,
                operationInterrupted: true
            )
        )

        XCTAssertFalse(message.contains("disk space"))
        XCTAssertTrue(message.contains("Turn MacDNS on"))
    }

    /// Without a hardware identity the license cannot be checked at all, which
    /// the 72-hour "connect to the internet" advice would misdescribe.
    func testUnreadableHardwareIdentityExplainsTheBlock() throws {
        for latch in [nil, LicenseFailClosedReason.networkGraceExpired] {
            let message = try XCTUnwrap(
                LicenseBlockReason.message(
                    latch: latch,
                    clockTrusted: true,
                    machineIdentityUnavailable: true
                )
            )

            XCTAssertTrue(message.contains("hardware ID"), "\(String(describing: latch))")
            XCTAssertFalse(message.contains("internet"), "\(String(describing: latch))")
            // Activation arms no retry, so only Refresh is a promise that holds.
            XCTAssertTrue(message.contains("Refresh"), "\(String(describing: latch))")
        }
    }

    func testEveryLatchReasonExplainsTheBlock() {
        for reason in [
            LicenseFailClosedReason.stateLoadFailed, .statePersistenceFailed, .networkGraceExpired,
        ] {
            XCTAssertNotNil(
                LicenseBlockReason.message(latch: reason, clockTrusted: true),
                reason.rawValue
            )
        }
    }

    func testDistrustedClockExplainsTheBlock() throws {
        let message = try XCTUnwrap(
            LicenseBlockReason.message(latch: nil, clockTrusted: false)
        )

        XCTAssertTrue(message.contains("clock"))
    }

    /// A license that could not be checked keeps a status that reads as fine
    /// while protection is off, so the reason says what brings it back.
    func testUnansweredLicenseCheckAsksForAConnection() throws {
        let message = try XCTUnwrap(
            LicenseBlockReason.message(latch: nil, clockTrusted: true, checkUnanswered: true)
        )

        XCTAssertTrue(message.contains("couldn't check your license"))
        XCTAssertTrue(message.contains("internet"))
    }

    func testUnansweredLicenseCheckNeverReplacesAMoreSpecificReason() throws {
        let clock = try XCTUnwrap(
            LicenseBlockReason.message(latch: nil, clockTrusted: false, checkUnanswered: true)
        )
        let hardware = try XCTUnwrap(
            LicenseBlockReason.message(
                latch: nil,
                clockTrusted: true,
                machineIdentityUnavailable: true,
                checkUnanswered: true
            )
        )
        let grace = try XCTUnwrap(
            LicenseBlockReason.message(
                latch: .networkGraceExpired,
                clockTrusted: true,
                checkUnanswered: true
            )
        )

        XCTAssertTrue(clock.contains("clock"))
        XCTAssertTrue(hardware.contains("hardware ID"))
        XCTAssertTrue(grace.contains("check your license online"))
    }

    /// The grace latch also blocks a license with no stored answer, and one
    /// whose stored answer reached the license expiry first, so the reason
    /// never claims that 72 hours passed.
    func testGraceReasonClaimsNoDuration() throws {
        let grace = try XCTUnwrap(
            LicenseBlockReason.message(latch: .networkGraceExpired, clockTrusted: true)
        )

        XCTAssertFalse(grace.contains("72 hours"))
        XCTAssertTrue(grace.contains("internet"))
    }

    func testNoReasonWhenNothingBlocks() {
        XCTAssertNil(LicenseBlockReason.message(latch: nil, clockTrusted: true))
    }

    /// An App newer than the Agent, or the reverse, must still decode the info.
    func testLicenseInfoDecodesWithoutABlockReason() throws {
        let legacy = try JSONCoding.encoder.encode(
            LicenseInfo(from: LicenseState(status: .trial), isServiceAllowed: true)
        )
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: legacy) as? [String: Any]
        )
        object.removeValue(forKey: "blockReason")
        let data = try JSONSerialization.data(withJSONObject: object)

        let info = try JSONCoding.decoder.decode(LicenseInfo.self, from: data)

        XCTAssertNil(info.blockReason)
    }

    func testLicenseInfoCarriesTheBlockReason() throws {
        let info = LicenseInfo(
            from: LicenseState(status: .valid),
            isServiceAllowed: false,
            blockReason: "reason"
        )

        let decoded = try JSONCoding.decoder.decode(
            LicenseInfo.self,
            from: JSONCoding.encoder.encode(info)
        )

        XCTAssertEqual(decoded.blockReason, "reason")
    }
}

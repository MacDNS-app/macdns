// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

@testable import MacDNS

final class LocalRecordShortcutTests: XCTestCase {
    private func record(_ domain: String, _ qtype: String, _ value: String, enabled: Bool = true) -> DNSOverride {
        DNSOverride(domain: domain, value: value, qtype: qtype, enabled: enabled)
    }

    private func summary(_ overrides: [DNSOverride]) -> [String] {
        overrides.map { "\($0.domain) \($0.qtype) \($0.value) \($0.enabled ? "on" : "off")" }
    }

    // MARK: - Block

    func testBlockAddsAnAddressRecordForEachFamily() throws {
        let existing = [record("nas.lan", "A", "10.0.0.5")]

        XCTAssertEqual(LocalRecordShortcut.block(for: "ads.example.com", in: existing), .available)
        let blocked = try XCTUnwrap(LocalRecordShortcut.blocking("ads.example.com", in: existing))

        XCTAssertEqual(
            summary(blocked),
            ["nas.lan A 10.0.0.5 on", "ads.example.com A 0.0.0.0 on", "ads.example.com AAAA :: on"])
        XCTAssertEqual(LocalRecordShortcut.block(for: "ads.example.com", in: blocked), .blocked)
    }

    func testBlockedHostMatchesWhateverTheCaseOfTheRecords() {
        let existing = [record("Ads.Example.com", "A", "0.0.0.0"), record("ADS.EXAMPLE.COM", "AAAA", "::")]

        XCTAssertEqual(LocalRecordShortcut.block(for: "ads.example.com", in: existing), .blocked)
    }

    func testBlockTurnsBackOnARecordThatIsOffInsteadOfAddingASecondOne() throws {
        let existing = [record("ads.example.com", "A", "0.0.0.0", enabled: false)]

        let blocked = try XCTUnwrap(LocalRecordShortcut.blocking("ads.example.com", in: existing))

        XCTAssertEqual(summary(blocked), ["ads.example.com A 0.0.0.0 on", "ads.example.com AAAA :: on"])
    }

    func testBlockAddsOnlyTheRecordThatIsMissing() throws {
        let existing = [record("ads.example.com", "A", "0.0.0.0")]

        XCTAssertEqual(LocalRecordShortcut.block(for: "ads.example.com", in: existing), .available)
        let blocked = try XCTUnwrap(LocalRecordShortcut.blocking("ads.example.com", in: existing))

        XCTAssertEqual(summary(blocked), ["ads.example.com A 0.0.0.0 on", "ads.example.com AAAA :: on"])
    }

    func testBlockIsUnavailableWhenTheHostAlreadyHasItsOwnAddress() {
        let existing = [record("ads.example.com", "A", "10.0.0.7")]

        XCTAssertEqual(
            LocalRecordShortcut.block(for: "ads.example.com", in: existing),
            .unavailable(reason: "Cannot add A: 'ads.example.com' already has a A override"))
        XCTAssertNil(LocalRecordShortcut.blocking("ads.example.com", in: existing))
    }

    func testBlockIsUnavailableUnderACNAMERecord() {
        let existing = [record("ads.example.com", "CNAME", "elsewhere.example.net")]

        XCTAssertEqual(
            LocalRecordShortcut.block(for: "ads.example.com", in: existing),
            .unavailable(reason: "Cannot add A: CNAME already exists for this domain"))
    }

    func testBlockIsUnavailableForANameLocalRecordsDoNotAccept() {
        guard case .unavailable = LocalRecordShortcut.block(for: "bad..example.com", in: []) else {
            return XCTFail("an empty label is not a valid Local Record name")
        }
        XCTAssertNil(LocalRecordShortcut.blocking("bad..example.com", in: []))
    }

    func testUnblockRemovesOnlyTheBlockingRecordsOfThatHost() {
        let existing = [
            record("ads.example.com", "A", "0.0.0.0"),
            record("ads.example.com", "MX", "10 mail.example.com"),
            record("ADS.example.com", "AAAA", "::"),
            record("other.example.com", "A", "0.0.0.0"),
        ]

        let unblocked = LocalRecordShortcut.unblocking("ads.example.com", in: existing)

        XCTAssertEqual(
            summary(unblocked), ["ads.example.com MX 10 mail.example.com on", "other.example.com A 0.0.0.0 on"])
    }

    // MARK: - Add Local Record

    func testValidRecordHasNoError() {
        XCTAssertNil(LocalRecordShortcut.addError(host: "api.example.com", qtype: "A", value: "10.0.0.9", in: []))
    }

    func testEmptyValueHasNoErrorYet() {
        XCTAssertNil(LocalRecordShortcut.addError(host: "api.example.com", qtype: "A", value: "", in: []))
    }

    func testValueThatDoesNotFitTheTypeIsRejected() {
        XCTAssertNotNil(LocalRecordShortcut.addError(host: "api.example.com", qtype: "A", value: "::1", in: []))
    }

    func testSecondRecordOfTheSameTypeIsRejected() {
        let existing = [record("api.example.com", "A", "10.0.0.9")]

        XCTAssertEqual(
            LocalRecordShortcut.addError(host: "api.example.com", qtype: "A", value: "10.0.0.10", in: existing),
            "Cannot add A: 'api.example.com' already has a A override")
    }

    func testAddingAppendsAnEnabledRecordForTheHost() throws {
        let added = try XCTUnwrap(
            LocalRecordShortcut.adding(host: "api.example.com", qtype: "AAAA", value: "fd00::9", to: []))

        XCTAssertEqual(summary(added), ["api.example.com AAAA fd00::9 on"])
    }

    func testAddingRefusesARecordWithAnError() {
        XCTAssertNil(LocalRecordShortcut.adding(host: "api.example.com", qtype: "A", value: "", to: []))
        XCTAssertNil(LocalRecordShortcut.adding(host: "api.example.com", qtype: "A", value: "nope", to: []))
    }

    func testRecordTypeStartsAtTheLookupTypeWhenLocalRecordsSupportIt() {
        XCTAssertEqual(LocalRecordShortcut.initialType(forLookupType: "AAAA"), "AAAA")
        XCTAssertEqual(LocalRecordShortcut.initialType(forLookupType: "MX"), "MX")
        XCTAssertEqual(LocalRecordShortcut.initialType(forLookupType: "HTTPS"), "A")
        XCTAssertEqual(LocalRecordShortcut.initialType(forLookupType: nil), "A")
    }
}

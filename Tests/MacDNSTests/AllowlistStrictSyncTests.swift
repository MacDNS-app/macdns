// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

@testable import MacDNSAgent

final class AllowlistStrictSyncTests: XCTestCase {
    func testListFailureAbortsBeforeAnyMutation() {
        let resolver = RecordingAllowlistResolver(listResult: .failure(.ffiFailure))
        let manager = AllowlistManager(resolver: resolver)

        let result = manager.syncToLMDBStrict(
            domains: [AllowedDomain(domain: "allowed.example")]
        )

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.added.isEmpty)
        XCTAssertTrue(result.removed.isEmpty)
        XCTAssertEqual(resolver.replaceCallCount, 0)
    }

    func testSyncReplacesEntireAllowlistInOneCall() {
        let resolver = RecordingAllowlistResolver(
            listResult: .success(["stale.example", "kept.example"])
        )
        let manager = AllowlistManager(resolver: resolver)

        let result = manager.syncToLMDBStrict(
            domains: [
                AllowedDomain(domain: "kept.example"),
                AllowedDomain(domain: "fresh.example"),
                AllowedDomain(domain: "disabled.example", enabled: false),
            ]
        )

        XCTAssertTrue(result.success)
        XCTAssertEqual(resolver.replaceCallCount, 1)
        XCTAssertEqual(
            resolver.lastReplacedDomains.sorted(),
            ["fresh.example", "kept.example"]
        )
        XCTAssertEqual(result.added, ["fresh.example"])
        XCTAssertEqual(result.removed, ["stale.example"])
    }

    func testReplacementFailureReportsFailureWithoutPartialCounts() {
        let resolver = RecordingAllowlistResolver(
            listResult: .success(["stale.example"]),
            replaceSucceeds: false
        )
        let manager = AllowlistManager(resolver: resolver)

        let result = manager.syncToLMDBStrict(
            domains: [AllowedDomain(domain: "fresh.example")]
        )

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.added.isEmpty)
        XCTAssertTrue(result.removed.isEmpty)
        XCTAssertEqual(resolver.replaceCallCount, 1)
    }

    func testUnchangedAllowlistStillPublishesAuthoritativeSet() {
        let resolver = RecordingAllowlistResolver(
            listResult: .success(["kept.example"])
        )
        let manager = AllowlistManager(resolver: resolver)

        let result = manager.syncToLMDBStrict(
            domains: [AllowedDomain(domain: "kept.example")]
        )

        XCTAssertTrue(result.success)
        XCTAssertEqual(resolver.replaceCallCount, 1)
        XCTAssertTrue(result.added.isEmpty)
        XCTAssertTrue(result.removed.isEmpty)
    }
}

private final class RecordingAllowlistResolver: AllowlistResolverBackend {
    private let listResult: Result<[String], ResolverModule.AllowlistListError>
    private let replaceSucceeds: Bool

    private(set) var replaceCallCount = 0
    private(set) var lastReplacedDomains: [String] = []

    init(
        listResult: Result<[String], ResolverModule.AllowlistListError>,
        replaceSucceeds: Bool = true
    ) {
        self.listResult = listResult
        self.replaceSucceeds = replaceSucceeds
    }

    func listAllowedDomains() -> Result<[String], ResolverModule.AllowlistListError> {
        listResult
    }

    func replaceAllowedDomains(_ domains: [String]) -> Bool {
        replaceCallCount += 1
        lastReplacedDomains = domains
        return replaceSucceeds
    }
}

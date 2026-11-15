// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

@testable import MacDNSAgent

/// `dns_stats_snapshot` writes the Rust `#[repr(C)] StatsSnapshot` straight
/// into `RawResolverStats`. Nothing at runtime can detect a layout drift (the
/// agent would publish shifted counters), so the mirror's size and field
/// offsets are pinned here, against the same 11 x u64 the Rust-side
/// `struct_layout_is_eleven_u64_fields` pins.
final class ResolverStatsMirrorTests: XCTestCase {
    func testMirrorMatchesTheRustStructSize() {
        XCTAssertEqual(MemoryLayout<RawResolverStats>.size, ResolverModule.resolverStatsByteCount)
        XCTAssertEqual(MemoryLayout<RawResolverStats>.stride, ResolverModule.resolverStatsByteCount)
    }

    func testMirrorFieldsAreContiguousInDeclarationOrder() {
        let offsets: [PartialKeyPath<RawResolverStats>] = [
            \.queriesTotal,
            \.cacheHits,
            \.cacheMisses,
            \.blocked,
            \.servfail,
            \.prefetchRefills,
            \.staleServed,
            \.rebindingFiltered,
            \.belowNXDomainHits,
            \.udpOverloadDrops,
            \.tcpOverloadDrops,
        ]

        for (index, keyPath) in offsets.enumerated() {
            XCTAssertEqual(
                MemoryLayout<RawResolverStats>.offset(of: keyPath),
                index * MemoryLayout<UInt64>.size,
                "field \(index) moved; the Rust struct writes it at a fixed offset"
            )
        }
    }

    /// Distinct values per field so a mis-wired mapping shows up as a number
    /// mismatch instead of passing on two zeros.
    func testMappingCarriesEveryCounterToItsOwnField() {
        var raw = RawResolverStats()
        raw.queriesTotal = 1
        raw.cacheHits = 2
        raw.cacheMisses = 3
        raw.blocked = 4
        raw.servfail = 5
        raw.prefetchRefills = 6
        raw.staleServed = 7
        raw.rebindingFiltered = 8
        raw.belowNXDomainHits = 9
        raw.udpOverloadDrops = 10
        raw.tcpOverloadDrops = 11

        let snapshot = ResolverStatsSnapshot(raw)

        XCTAssertEqual(
            snapshot,
            ResolverStatsSnapshot(
                queriesTotal: 1, cacheHits: 2, cacheMisses: 3, blocked: 4, servfail: 5,
                prefetchRefills: 6, staleServed: 7, rebindingFiltered: 8, belowNXDomainHits: 9,
                udpOverloadDrops: 10, tcpOverloadDrops: 11))
    }
}

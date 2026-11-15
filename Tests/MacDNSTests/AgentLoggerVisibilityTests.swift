// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

/// Guards that every field on `AgentLogger`'s DNS channel stays readable.
///
/// `Logger` redacts interpolated `String` values by default, so dropping an
/// annotation, or writing `.private` for the queried name, silently turns
/// `SERVFAIL: domain=example.com qtype=A` into
/// `SERVFAIL: domain=<private> qtype=A`, which identifies nothing. macOS 26
/// removed `log config --mode private_data`, and the only remaining way to
/// unredact is a system-wide logging profile that applies to every process on
/// the machine, so in practice a redacted field is unrecoverable rather than
/// merely protected.
///
/// This reads the source rather than the emitted log on purpose: os_log applies
/// redaction at *read* time from the reader's entitlement, and a process always
/// sees its own private data in full, so logging and reading back through
/// `OSLogStore` shows the unredacted text either way and proves nothing. The
/// annotation in the source is what decides what a third party sees.
final class AgentLoggerVisibilityTests: XCTestCase {
    /// Every field the DNS channel emits. Each must be explicitly `.public`.
    private static let expectedFields = [
        "domain", "rule", "data", "qtype", "rcode", "answers", "provider",
        "category", "reason",
    ]

    private func dnsChannelSource() throws -> String {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // MacDNSTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // repo root
        let source = try String(
            contentsOf:
                repoRoot
                .appendingPathComponent("Sources/MacDNSAgent/Services/AgentLogger.swift"),
            encoding: .utf8
        )
        let marker = "// MARK: - DNS Channel"
        let start = try XCTUnwrap(
            source.range(of: marker),
            "AgentLogger.swift no longer has a '\(marker)' section — this guard lost its subject"
        )
        return String(source[start.upperBound...])
    }

    /// Unknown syntax remains in the result so the public-only check fails closed.
    private func annotations(in source: String) -> [(field: String, level: String)] {
        let characters = Array(source)
        var found: [(field: String, level: String)] = []
        var cursor = 0
        while cursor + 1 < characters.count {
            guard characters[cursor] == "\\" else {
                cursor += 1
                continue
            }
            var opening = cursor + 1
            while opening < characters.count, characters[opening] == "#" {
                opening += 1
            }
            guard opening < characters.count, characters[opening] == "(" else {
                cursor += 2
                continue
            }
            let rawInterpolation = opening != cursor + 1
            cursor = opening + 1
            let start = cursor
            var delimiters: [Character] = ["("]
            var commas: [Int] = []
            var quoted = false
            var unknownSyntax = rawInterpolation
            while cursor < characters.count, !delimiters.isEmpty {
                let character = characters[cursor]
                if quoted {
                    if character == "\\" {
                        cursor += 2
                        continue
                    }
                    if character == "\"" { quoted = false }
                } else if character == "\"" {
                    quoted = true
                } else if character == "#" || character == "/" {
                    unknownSyntax = true
                } else if character == "(" || character == "[" || character == "{" {
                    delimiters.append(character)
                } else if ")]}".contains(character) {
                    let expected: Character = character == ")" ? "(" : character == "]" ? "[" : "{"
                    if delimiters.last != expected { unknownSyntax = true }
                    delimiters.removeLast()
                    if delimiters.isEmpty { break }
                } else if character == ",", delimiters.count == 1 {
                    commas.append(cursor)
                }
                cursor += 1
            }
            guard cursor < characters.count, delimiters.isEmpty, !quoted else {
                found.append((String(characters[start...]), "unclassified"))
                break
            }
            let firstEnd = commas.first ?? cursor
            let field = String(characters[start..<firstEnd]).trimmingCharacters(in: .whitespacesAndNewlines)
            let arguments =
                commas.count == 1
                ? String(characters[(commas[0] + 1)..<cursor]).filter { !$0.isWhitespace }
                : ""
            let level: String
            if unknownSyntax || field.isEmpty {
                level = "unclassified"
            } else if commas.isEmpty {
                level = "missing"
            } else if arguments == "privacy:.public" {
                level = "public"
            } else if arguments == "privacy:.private" || arguments.hasPrefix("privacy:.private(") {
                level = "private"
            } else {
                level = "unclassified"
            }
            found.append((field, level))
            cursor += 1
        }
        return found
    }

    func testNestedMethodCallsCannotEscapeInterpolationClassification() {
        let found = annotations(in: #"\(domain.lowercased(), privacy: .public)"#)

        XCTAssertEqual(found.count, 1)
        XCTAssertEqual(found.first?.field, "domain.lowercased()")
        XCTAssertEqual(found.first?.level, "public")
    }

    func testHashedPrivateInterpolationCannotEscapeClassification() {
        let found = annotations(in: #"\(domain, privacy: .private(mask: .hash))"#)

        XCTAssertEqual(found.count, 1)
        XCTAssertEqual(found.first?.level, "private")
    }

    func testNestedArgumentsAndQuotedParenthesesAreClassified() {
        let found = annotations(in: #"\(domain.replacingOccurrences(of: ")", with: ","), privacy: .public)"#)

        XCTAssertEqual(found.count, 1)
        XCTAssertEqual(found.first?.level, "public")
    }

    func testMissingPrivateAndUnknownPrivacyAreRejectedPerOccurrence() {
        let rejected = [
            #"\(domain)"#,
            #"\(domain.lowercased())"#,
            #"\(domain, privacy: .private)"#,
            #"\(domain, privacy: .private(mask: .hash))"#,
            #"\(domain, privacy: visibility)"#,
            #"\(domain, privacy: .auto)"#,
            #"\(domain, format: .description, privacy: .public)"#,
            #"\(domain, privacy: .public"#,
            #"\(domain, privacy: .public /* unknown */)"#,
            ##"\#(domain, privacy: .public)"##,
        ]
        for interpolation in rejected {
            let found = annotations(in: #"\(domain, privacy: .public) "# + interpolation)

            XCTAssertEqual(found.count, 2, interpolation)
            XCTAssertEqual(found.first?.level, "public", interpolation)
            XCTAssertNotEqual(found.last?.level, "public", interpolation)
        }
    }

    func testUnclassifiedOccurrenceCannotHideBehindOtherPublicDomainOccurrences() throws {
        let source = try dnsChannelSource()
        let original = #"\(domain, privacy: .public)"#
        let occurrence = try XCTUnwrap(source.range(of: original))
        var changed = source
        changed.replaceSubrange(occurrence, with: #"\(domain.lowercased())"#)
        let found = annotations(in: changed)

        XCTAssertTrue(found.contains { $0.field == "domain" && $0.level == "public" })
        XCTAssertEqual(found.filter { $0.level != "public" }.map(\.field), ["domain.lowercased()"])
    }

    func testEveryFieldIsPublic() throws {
        let found = annotations(in: try dnsChannelSource())
        XCTAssertFalse(found.isEmpty, "The DNS channel must have classified interpolations")
        for (field, level) in found {
            XCTAssertEqual(
                level, "public",
                "\(field) has interpolation classification '\(level)'. "
                    + "Every DNS field must explicitly use privacy: .public"
            )
        }
    }

    func testNoExpectedFieldWentMissing() throws {
        let found = Set(annotations(in: try dnsChannelSource()).map(\.field))
        for field in Self.expectedFields {
            XCTAssertTrue(
                found.contains(field),
                "\(field) no longer appears in the DNS channel — this guard lost a subject"
            )
        }
    }

}

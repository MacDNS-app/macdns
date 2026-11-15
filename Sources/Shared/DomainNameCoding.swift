// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// The one IDNA A-label encoder in the Swift tree.
///
/// The App pre-validates names in `DomainValidator` and the authoritative
/// writers validate them again in `DNSPolicySemanticPolicy`. Both must compute
/// the identical ASCII wire form: if they drift, the UI accepts a name the
/// writers reject, or shows as distinct two names that collide once encoded.
/// Both call this encoder, so there is no second copy to drift.
///
/// It lives in `Shared` because that is the only module both the App and the
/// agent link. The Rust resolver keeps its own implementation
/// (`idna::domain_to_ascii_strict`), which stays pinned by
/// `DNSPolicyStructuralPolicyTests` and by the cross-language vectors in
/// `Tests/Fixtures/domain-name-conformance.json`.
public enum DomainNameCoding {
    /// A-label form of a single label. Case folding and canonical composition
    /// are applied before punycode encoding. The full UTS-46 mapping table is
    /// not reproduced, so labels holding code points the resolver would *map*
    /// rather than encode are rejected here instead of being encoded into a
    /// name the resolver never sees.
    ///
    /// Returns nil when the label cannot be encoded. Callers apply their own
    /// length limits. The 63-octet cap is a caller's rule, not this encoder's.
    public static func asciiLabel(_ label: String) -> String? {
        guard !isMappedByUTS46(label) else { return nil }
        if label.unicodeScalars.allSatisfy(\.isASCII) {
            return label.lowercased()
        }
        let folded = label.lowercased().precomposedStringWithCanonicalMapping
        guard let encoded = Punycode.encode(folded), !encoded.isEmpty else {
            return nil
        }
        return "xn--" + encoded
    }

    /// True when UTS-46 would rewrite the label into something other than the
    /// case-folded canonical composition this encoder punycodes: fullwidth and
    /// compatibility forms (`Ａ`, `１`), and singleton letters that fold to
    /// plain ASCII (`K` U+212A).
    ///
    /// The resolver runs the real mapping table, so encoding those code points
    /// here would make the App treat `Ａ.example` and `a.example` as distinct
    /// while the resolver collapses them into one name, a duplicate that
    /// rejects the whole policy snapshot. Rejecting is deliberately stricter
    /// than the resolver: the user retypes the plain form instead of saving a
    /// configuration that later refuses to load.
    public static func isMappedByUTS46(_ label: String) -> Bool {
        guard !label.unicodeScalars.allSatisfy(\.isASCII) else { return false }
        let folded = label.lowercased().precomposedStringWithCanonicalMapping
        if folded.unicodeScalars.allSatisfy(\.isASCII) { return true }
        let compatibility = folded
            .precomposedStringWithCompatibilityMapping
            .lowercased()
            .precomposedStringWithCanonicalMapping
        return compatibility != folded
    }

    /// True when a name holding non-ASCII text breaks a rule the resolver's
    /// `idna::domain_to_ascii_strict` enforces across the whole name: a label
    /// starting with a combining mark (RFC 5891 4.2.3.2) or the Bidi rule
    /// (RFC 5893). Swift exposes no bidi class, so the Bidi check is a stricter
    /// subset built on right-to-left script blocks. An A-label next to Unicode
    /// text is refused too: the resolver decodes and checks it, this encoder
    /// cannot. All-ASCII names always pass, because the resolver skips IDNA
    /// processing for them.
    public static func violatesIDNAContextRules(_ labels: [String]) -> Bool {
        guard !labels.allSatisfy({ $0.unicodeScalars.allSatisfy(\.isASCII) }) else {
            return false
        }
        let folded = labels.map { $0.lowercased().precomposedStringWithCanonicalMapping }
        for label in folded {
            if label.hasPrefix("xn--") { return true }
            if let first = label.unicodeScalars.first, isCombiningMark(first) { return true }
        }
        guard folded.contains(where: isRightToLeftLabel) else { return false }
        return !folded.allSatisfy {
            isRightToLeftLabel($0) ? satisfiesRightToLeftRule($0) : satisfiesLeftToRightRule($0)
        }
    }

    /// RFC 5893 rules 1-4, narrowed: starts with a right-to-left letter, holds
    /// only right-to-left letters and marks, `-` and one kind of digits, and
    /// does not end in `-`.
    private static func satisfiesRightToLeftRule(_ label: String) -> Bool {
        let scalars = Array(label.unicodeScalars)
        guard let first = scalars.first, isRightToLeftLetter(first) else { return false }
        var hasEuropeanDigit = false
        var hasArabicIndicDigit = false
        for scalar in scalars {
            if isRightToLeftLetter(scalar) || scalar == "-" { continue }
            if isCombiningMark(scalar) && isInRightToLeftBlock(scalar) { continue }
            if isEuropeanDigit(scalar) {
                hasEuropeanDigit = true
                continue
            }
            if isArabicIndicDigit(scalar) {
                hasArabicIndicDigit = true
                continue
            }
            return false
        }
        guard !(hasEuropeanDigit && hasArabicIndicDigit) else { return false }
        return scalars.last(where: { !isCombiningMark($0) }) != "-"
    }

    /// RFC 5893 rules 5-6, narrowed: starts with a letter, holds nothing from a
    /// right-to-left block and ends in a letter or an ASCII digit.
    private static func satisfiesLeftToRightRule(_ label: String) -> Bool {
        let scalars = Array(label.unicodeScalars)
        guard let first = scalars.first, isLetter(first),
            !scalars.contains(where: isInRightToLeftBlock),
            let last = scalars.last(where: { !isCombiningMark($0) })
        else {
            return false
        }
        return isLetter(last) || isEuropeanDigit(last)
    }

    private static func isRightToLeftLabel(_ label: String) -> Bool {
        label.unicodeScalars.contains(where: isRightToLeftLetter)
    }

    /// Blocks whose letters are all strong right-to-left (bidi class R or AL).
    private static func isInRightToLeftBlock(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x0590...0x08FF, 0xFB1D...0xFDFF, 0xFE70...0xFEFF, 0x10800...0x10FFF,
            0x1E800...0x1EFFF:
            return true
        default:
            return false
        }
    }

    private static func isRightToLeftLetter(_ scalar: Unicode.Scalar) -> Bool {
        isInRightToLeftBlock(scalar) && isLetter(scalar)
    }

    /// Modifier letters are left out: several of them are bidi class ON, not L.
    private static func isLetter(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.properties.generalCategory {
        case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .otherLetter:
            return true
        default:
            return false
        }
    }

    private static func isCombiningMark(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.properties.generalCategory {
        case .nonspacingMark, .spacingMark, .enclosingMark:
            return true
        default:
            return false
        }
    }

    /// Bidi class EN: ASCII and extended Arabic-Indic digits.
    private static func isEuropeanDigit(_ scalar: Unicode.Scalar) -> Bool {
        (0x30...0x39).contains(scalar.value) || (0x06F0...0x06F9).contains(scalar.value)
    }

    /// Bidi class AN: Arabic-Indic digits.
    private static func isArabicIndicDigit(_ scalar: Unicode.Scalar) -> Bool {
        (0x0660...0x0669).contains(scalar.value)
    }

    /// Wire length of a name already in A-label form: one length octet per
    /// label plus the root terminator, the same accounting hickory's
    /// `Name::extend_name` applies before enforcing `Name::MAX_LENGTH`. 255 is
    /// a wire limit, so it never applies to the text the user typed, and a
    /// wildcard owner must pass `*` in as a label of its own.
    public static func wireLength(asciiLabels labels: [String]) -> Int {
        labels.reduce(1) { $0 + 1 + $1.utf8.count }
    }

    /// RFC 3492 punycode encoder, enough to compute the ASCII wire form of an
    /// IDN label so octet limits and duplicate detection match the resolver's
    /// `idna::domain_to_ascii_strict`.
    private enum Punycode {
        private static let base = 36
        private static let tmin = 1
        private static let tmax = 26
        private static let skew = 38
        private static let damp = 700
        private static let initialBias = 72
        private static let initialN: UInt32 = 128

        static func encode(_ input: String) -> String? {
            let scalars = input.unicodeScalars.map(\.value)
            var output = String(
                String.UnicodeScalarView(
                    input.unicodeScalars.filter { $0.value < initialN }
                )
            )
            let basicCount = output.unicodeScalars.count
            var handled = basicCount
            if basicCount > 0 {
                output.append("-")
            }

            var n = initialN
            var delta = 0
            var bias = initialBias

            while handled < scalars.count {
                guard let next = scalars.filter({ $0 >= n }).min() else {
                    return nil
                }
                let (scaled, scaleOverflow) = Int(next - n)
                    .multipliedReportingOverflow(by: handled + 1)
                guard !scaleOverflow else { return nil }
                let (advanced, deltaOverflow) = delta.addingReportingOverflow(
                    scaled
                )
                guard !deltaOverflow else { return nil }
                delta = advanced
                n = next

                for scalar in scalars {
                    if scalar < n {
                        delta += 1
                    }
                    if scalar == n {
                        var remainder = delta
                        var k = base
                        while true {
                            let t = threshold(k: k, bias: bias)
                            if remainder < t { break }
                            output.append(digit(t + (remainder - t) % (base - t)))
                            remainder = (remainder - t) / (base - t)
                            k += base
                        }
                        output.append(digit(remainder))
                        bias = adapt(
                            delta: delta,
                            numPoints: handled + 1,
                            firstTime: handled == basicCount
                        )
                        delta = 0
                        handled += 1
                    }
                }
                delta += 1
                n += 1
            }

            return output
        }

        private static func threshold(k: Int, bias: Int) -> Int {
            if k <= bias + tmin { return tmin }
            if k >= bias + tmax { return tmax }
            return k - bias
        }

        private static func adapt(
            delta: Int,
            numPoints: Int,
            firstTime: Bool
        ) -> Int {
            var delta = firstTime ? delta / damp : delta / 2
            delta += delta / numPoints
            var k = 0
            while delta > ((base - tmin) * tmax) / 2 {
                delta /= base - tmin
                k += base
            }
            return k + (((base - tmin + 1) * delta) / (delta + skew))
        }

        /// 0-25 map to 'a'-'z', 26-35 map to '0'-'9'.
        private static func digit(_ value: Int) -> Character {
            value < 26
                ? Character(UnicodeScalar(UInt8(97 + value)))
                : Character(UnicodeScalar(UInt8(48 + value - 26)))
        }
    }
}

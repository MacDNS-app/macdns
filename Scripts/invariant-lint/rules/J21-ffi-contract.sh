#!/bin/sh
# J21: the FFI contract between the agent and `libmacdns_resolver.dylib`.
#
# Enforced mechanically as three properties:
#   1. every `#[no_mangle] extern "C"` export catches panics and returns an
#      appropriate sentinel (`0` / `-1` for integers, NULL for pointers, nothing
#      for `void`)
#   2. every `CString::into_raw` hand-off belongs to a pointer-returning export
#      that names its `dns_*_free_*` reclaimer, and only that reclaimer calls
#      `CString::from_raw`
#   3. every Swift call site of such an export releases the pointer in a `defer`
#      through that same free function
#
# The export table is discovered by parsing the crate, never hardcoded: a fixed
# list or count would break on the next legitimate export and get disabled, which
# is worse than no lint. Run with J21_INVENTORY=1 to print the discovered table.
#
# Depends on the `panic = "unwind"` compile guard in the crate's lib.rs:
# `catch_unwind` only yields a sentinel under that panic strategy, so neither
# check is sufficient alone.
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J21 ffi contract" "must catch panics and return a sentinel"

RUST_SRC="$REPO_ROOT/rust-resolver/crates/macdns-resolver/src"
PAIRS="$LINT_TMP.pairs"
INV="$LINT_TMP.inventory"
BINDINGS="$LINT_TMP.bindings"
trap 'rm -f "$LINT_TMP" "$LINT_ERR" "$PAIRS" "$INV" "$BINDINGS"' EXIT HUP INT TERM

if [ ! -d "$RUST_SRC" ]; then
    report "$RUST_SRC" 0 "resolver crate source directory is missing; the FFI surface moved"
    rule_end
fi

RUST=$(rust_files "$RUST_SRC")
assert_plain_paths "$RUST"

# 1 + 2. Panic guards, sentinels and CString ownership, all read off the same
# discovered export table. The producer/free pairs it resolves feed check 3.
: >"$PAIRS"
lint_awk -v srcdir="$RUST_SRC" \
    -v pairs_out="$PAIRS" \
    -v inventory_out="$INV" \
    -f "$AWKLIB" -f "$LINT_DIR/lib/J21-ffi-rust.awk" $RUST
report_stream "FFI contract"

# The discovered export table, on request. Written to a file rather than stderr
# because lint_awk reserves a scanner's stderr for crash diagnostics.
if [ -n "${J21_INVENTORY:-}" ] && [ -s "$INV" ]; then
    cat "$INV"
fi

# 3. Swift releases every Rust-owned C string in a `defer`, through the matching
# free function. Swift reaches the exports via `dlsym`, so the bound
# function-pointer property is resolved from its `sym("<symbol>")` line.
SWIFT=$(swift_files "$REPO_ROOT/Sources")
assert_plain_paths "$SWIFT"
while IFS="$TAB" read -r producer freefn; do
    [ -n "$producer" ] || continue

    lint_awk -v producer="$producer" -v freefn="$freefn" \
        -f "$AWKLIB" -f "$LINT_DIR/lib/J21-ffi-bindings.awk" $SWIFT
    cp "$LINT_TMP" "$BINDINGS"
    if ! awk -F "$TAB" '$3 == "producer" { found = 1 } END { exit !found }' "$BINDINGS"; then
        report "$RUST_SRC" 0 "$producer returns an owned C string but no supported Swift sym() binding calls it"
    fi
    while IFS="$TAB" read -r bindfile bindline kind text; do
        [ "$kind" = error ] || continue
        report "$bindfile" "$bindline" "$text"
    done <"$BINDINGS"

    bindfiles=$(awk -F "$TAB" '$3 == "producer" { print $1 }' "$BINDINGS" | sort -u)
    for bindfile in $bindfiles; do
        pvars=$(awk -F "$TAB" -v file="$bindfile" '$1 == file && $3 == "producer" { print $4 }' "$BINDINGS" | sort -u)
        fvars=$(awk -F "$TAB" -v file="$bindfile" '$1 == file && $3 == "free" { print $4 }' "$BINDINGS" | sort -u | tr '\n' '|')
        if [ -z "$fvars" ]; then
            report "$bindfile" 0 \
                "$producer / $freefn are not both bound as sym() properties here; the pointer cannot be released by its matching free function"
            continue
        fi
        for pvar in $pvars; do
            lint_awk -v pvar="$pvar" -v fvars="$fvars" -v producer="$producer" -v freefn="$freefn" \
                -f "$AWKLIB" -f "$LINT_DIR/lib/J21-ffi-defer.awk" "$bindfile"
            while IFS="$TAB" read -r _line _text; do
                [ -n "$_line" ] || continue
                report "$bindfile" "$_line" "FFI ownership: $_text"
            done <"$LINT_TMP"
        done
    done
done <"$PAIRS"

rule_end

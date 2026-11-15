#!/bin/sh
# Regenerates THIRD_PARTY_LICENSES.txt, which the app bundle ships in
# Contents/Resources. It covers every crate linked into the resolver dylib
# (cargo-about, see rust-resolver/about.toml), the NOTICE files those crates
# carry, and Sparkle.framework. With --check it only verifies that the
# committed file matches what the current dependencies would generate.
set -eu

mode=${1:-write}
case "$mode" in
write | --check) ;;
*)
	echo "usage: $0 [--check]" >&2
	exit 2
	;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)
rust_dir="$root/rust-resolver"
sparkle_license="$root/.build/artifacts/sparkle/Sparkle/LICENSE"
output="$root/THIRD_PARTY_LICENSES.txt"

if ! command -v cargo-about >/dev/null 2>&1; then
	echo "cargo-about not found. Install with: brew install cargo-about" >&2
	exit 1
fi
if [ ! -f "$sparkle_license" ]; then
	echo "Sparkle artifact missing. Running swift package resolve..."
	(cd "$root" && swift package resolve)
fi
if [ ! -f "$sparkle_license" ]; then
	echo "Sparkle artifact missing at $sparkle_license after swift package resolve" >&2
	exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

(cd "$rust_dir" && cargo about generate --locked about.hbs -o "$work/rust.txt")
(cd "$rust_dir" && cargo about generate --locked about-crate-dirs.hbs -o "$work/manifests.txt")

{
	echo "MacDNS includes the following third-party software."
	echo ""
	echo "================================================================================"
	echo "Sparkle"
	echo "================================================================================"
	echo ""
	cat "$sparkle_license"
	echo ""
	echo "================================================================================"
	echo "Rust crates linked into libmacdns_resolver.dylib"
	echo "================================================================================"
	cat "$work/rust.txt"
	grep 'Cargo.toml$' "$work/manifests.txt" | while read -r manifest; do
		crate_dir=$(dirname "$manifest")
		for notice in "$crate_dir"/NOTICE*; do
			[ -f "$notice" ] || continue
			echo ""
			echo "--------------------------------------------------------------------------------"
			echo "NOTICE from $(basename "$crate_dir")"
			echo ""
			cat "$notice"
		done
	done
} > "$work/generated.txt"

if [ "$mode" = "--check" ]; then
	if ! cmp -s "$work/generated.txt" "$output"; then
		echo "THIRD_PARTY_LICENSES.txt is stale. Run: make third-party-licenses" >&2
		exit 1
	fi
	echo "THIRD_PARTY_LICENSES.txt is current"
else
	mv "$work/generated.txt" "$output"
	echo "Wrote $output"
fi

#!/bin/bash
# Runs behind `make release`, locally and in the release workflow. It builds,
# notarizes and signs a release (`make release-build`) from the variables the
# workflow takes from repository secrets. Locally they come from .env at the
# repository root (see .env.example).
#
# The certificate goes into a temporary keychain and every decoded file into a
# temporary folder. Both are removed on exit, and the keychain search list is
# restored.
#
# usage: make release
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# .env can be a named pipe (a 1Password Environment), which the source builtin
# of macOS bash reads as empty.
if [ -e .env ]; then
	set -a
	eval "$(cat .env)"
	set +a
fi

required=(
	DEVELOPER_ID_P12_BASE64 DEVELOPER_ID_P12_PASSWORD
	APP_PROFILE_BASE64 EXTENSION_PROFILE_BASE64 CONTENT_FILTER_PROFILE_BASE64
	NOTARY_KEY_P8_BASE64 NOTARY_KEY_ID NOTARY_ISSUER_ID
	SPARKLE_PRIVATE_KEY KEYGEN_TRIAL_TOKEN
)
missing=()
for name in "${required[@]}"; do
	[ -n "${!name:-}" ] || missing+=("$name")
done
if [ ${#missing[@]} -gt 0 ]; then
	echo "Error: set ${missing[*]} (in .env locally, as repository secrets in CI)." >&2
	exit 1
fi

umask 077
work=$(mktemp -d)
keychain="$work/signing.keychain-db"
original_search_list=()
while IFS= read -r entry; do
	entry=${entry#"${entry%%[![:space:]]*}"}
	original_search_list+=("$(tr -d '"' <<<"$entry")")
done < <(security list-keychains -d user)

cleanup() {
	security list-keychains -d user -s "${original_search_list[@]}" || true
	security delete-keychain "$keychain" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

keychain_password=$(openssl rand -base64 32)
security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
base64 --decode <<<"$DEVELOPER_ID_P12_BASE64" >"$work/developer-id.p12"
security import "$work/developer-id.p12" -k "$keychain" -f pkcs12 \
	-P "$DEVELOPER_ID_P12_PASSWORD" -T /usr/bin/codesign
curl --silent --show-error --fail --location \
	https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer -o "$work/DeveloperIDG2CA.cer"
security import "$work/DeveloperIDG2CA.cer" -k "$keychain"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$keychain_password" "$keychain" >/dev/null
security list-keychains -d user -s "$keychain" "${original_search_list[@]}"

profiles="$work/profiles"
mkdir "$profiles"
base64 --decode <<<"$APP_PROFILE_BASE64" >"$profiles/MacDNS_Developer_ID.provisionprofile"
base64 --decode <<<"$EXTENSION_PROFILE_BASE64" >"$profiles/MacDNS_Extension_Developer_ID.provisionprofile"
base64 --decode <<<"$CONTENT_FILTER_PROFILE_BASE64" >"$profiles/MacDNS_Content_Filter_Developer_ID.provisionprofile"
base64 --decode <<<"$NOTARY_KEY_P8_BASE64" >"$work/notary-key.p8"
printf '%s' "$SPARKLE_PRIVATE_KEY" >"$work/sparkle-ed25519.key"

# The certificate in the temporary keychain signs, even when the login
# keychain holds another Developer ID identity.
identity=$(security find-identity -v -p codesigning "$keychain" |
	awk -F'"' '/Developer ID Application/ { print $2; exit }')
if [ -z "$identity" ]; then
	echo "Error: DEVELOPER_ID_P12_BASE64 holds no Developer ID Application identity." >&2
	exit 1
fi

make_args=(
	DEV_ID_APPLICATION="$identity"
	PROFILE_DIR="$profiles"
	NOTARY_AUTH="--key $work/notary-key.p8 --key-id $NOTARY_KEY_ID --issuer $NOTARY_ISSUER_ID"
	SPARKLE_KEY_ARGS="--ed-key-file $work/sparkle-ed25519.key"
)

make release-build "${make_args[@]}"

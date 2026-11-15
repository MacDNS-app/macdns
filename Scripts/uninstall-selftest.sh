#!/bin/sh
set -eu

# Run the real uninstall script in a sandbox. HOME is a temp directory, the
# environment is empty and PATH holds only the stubs below, so a command the
# script gains later fails instead of reaching the system. The stub `rm`
# deletes only inside the sandbox HOME.
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/macdns-uninstall.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

bin="$work/bin"
mkdir "$bin"

for tool in launchctl killall pkill open sudo dscacheutil defaults osascript; do
    cat > "$bin/$tool" <<'SH'
#!/bin/sh
printf '%s %s\n' "${0##*/}" "$*" >> "${SELFTEST_CALLS:?}"
SH
done

cat > "$bin/systemextensionsctl" <<'SH'
#!/bin/sh
row='*\t*\tTEAMID0000\tapp.macdns.%s (2.0.5/525)\t%s\t[%s]\n'
case "${SELFTEST_EXTENSIONS:?}" in
    active)
        printf '2 extension(s)\n--- com.apple.system_extension.network_extension\n'
        printf "$row" dnsproxy DNSProxyExtension 'activated enabled'
        printf "$row" contentfilter ContentFilterExtension 'activated enabled'
        ;;
    terminated)
        printf '1 extension(s)\n--- com.apple.system_extension.network_extension\n'
        printf "$row" dnsproxy DNSProxyExtension 'terminated waiting to uninstall on reboot'
        ;;
    failing) exit 1 ;;
esac
SH

cat > "$bin/rm" <<'SH'
#!/bin/sh
for arg in "$@"; do
    case "$arg" in
        -*) continue ;;
        */../* | */..) ;;
        "${SELFTEST_HOME:?}"/*) continue ;;
    esac
    printf 'rm refused %s\n' "$arg" >> "${SELFTEST_CALLS:?}"
    exit 0
done
printf 'rm %s\n' "$*" >> "${SELFTEST_CALLS:?}"
exec /bin/rm "$@"
SH

printf '#!/bin/sh\necho 501\n' > "$bin/id"
cat > "$bin/getconf" <<'SH'
#!/bin/sh
printf '%s/var-folders/C/\n' "${SELFTEST_HOME:?}"
SH
printf '#!/bin/sh\nexec /usr/bin/grep "$@"\n' > "$bin/grep"
chmod +x "$bin"/*

: > "$work/canary"
env -i SELFTEST_HOME="$work/home" SELFTEST_CALLS="$work/canary-calls" "$bin/rm" -rf "$work/canary"
test -f "$work/canary" || {
    echo "FAIL: the stub rm deleted a path outside the sandbox HOME"
    exit 1
}

failures=0

fail() {
    echo "FAIL: $name: $1"
    failures=$((failures + 1))
}

run_uninstall() {
    name=$1 extensions=$2
    home="$work/$name/home"
    support="$home/Library/Application Support/MacDNS"
    calls="$work/$name/calls"
    output="$work/$name/output"
    mkdir -p "$support"
    echo '{}' > "$support/state.json"
    echo '{}' > "$support/license.json"
    : > "$calls"
    status=0
    env -i HOME="$home" PATH="$bin" SELFTEST_HOME="$home" SELFTEST_CALLS="$calls" \
        SELFTEST_EXTENSIONS="$extensions" /bin/bash "$repo/Scripts/uninstall.sh" \
        < /dev/null > "$output" 2>&1 || status=$?
    failures_before=$failures
}

report() {
    if test "$failures" -eq "$failures_before"; then
        echo "PASS: $name"
    else
        cat "$output"
    fi
}

expect_refusal() {
    run_uninstall "$1" "$2"
    test "$status" -ne 0 || fail "exited 0 without confirming the extensions are gone"
    { test -f "$support/state.json" && test -f "$support/license.json"; } ||
        fail "deleted the user's configuration"
    test ! -s "$calls" || fail "stopped or removed something: $(tr '\n' ';' < "$calls")"
    grep -qF 'Uninstall…' "$output" || fail "did not name the in-app Uninstall… button"
    report
}

expect_refusal active-extensions active
expect_refusal failing-extension-listing failing

run_uninstall no-active-extensions terminated
test "$status" -eq 0 || fail "exited $status"
test ! -e "$support" || fail "kept the configuration directory"
grep -qx 'launchctl bootout gui/501/app.macdns.agent' "$calls" || fail "did not boot out the agent"
report

# Caches, URL session storage and preferences macOS keeps under the bundle
# identifiers. Neighbours that only share a prefix belong to other apps.
leftovers="Library/Caches/app.macdns Library/Caches/app.macdns.agent
Library/HTTPStorages/app.macdns.agent
Library/WebKit/app.macdns.probe var-folders/C/app.macdns
Library/Preferences/app.macdns.plist Library/Preferences/app.macdns.probe.plist"
neighbours="Library/Caches/app.macdnsx Library/Caches/com.example.app.macdns
Library/Preferences/app.macdnsx.plist"
home="$work/leftovers/home"
for path in $leftovers $neighbours; do
    mkdir -p "$home/${path%/*}"
    : > "$home/$path"
done
run_uninstall leftovers terminated
test "$status" -eq 0 || fail "exited $status"
for path in $leftovers; do
    test ! -e "$home/$path" || fail "kept $path"
done
for path in $neighbours; do
    test -e "$home/$path" || fail "removed $path, which belongs to another app"
done
for domain in app.macdns app.macdns.probe; do
    grep -qx "defaults delete $domain" "$calls" || fail "did not delete the $domain defaults"
done
report

test "$failures" -eq 0

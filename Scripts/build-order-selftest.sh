#!/bin/sh
set -eu

# Exercise the real orchestration rules with local stubs. No build or signing
# command is copied into the fixture.
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/macdns-build-order.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

extract_rule() {
    awk -v target="$2" '
        $0 ~ "^" target ":" { active = 1; print; next }
        active && /=== Assembling app bundle ===/ { exit }
        active && /^[^\t]/ && NF { exit }
        active && /^\t[+@]*\$\(MAKE\)/ { print }
    ' "$1"
}

cat > "$work/worker.sh" <<'SH'
set -eu
task=$1
printf '%s start\n' "$task" >> "$TEST_DIR/events"
require_done() {
    for dependency in "$@"; do
        test -f "$TEST_DIR/$dependency.done" || {
            echo "FAIL: $task started before $dependency finished" >&2
            exit 1
        }
    done
}
case "$task" in
    prepare) sleep 0.1 ;;
    build_*)
        require_done prepare
        touch "$TEST_DIR/$task.started"
        attempts=0
        until test -f "$TEST_DIR/build_resolver.started" &&
            test -f "$TEST_DIR/build_swift.started" &&
            test -f "$TEST_DIR/build_extension.started" &&
            test -f "$TEST_DIR/build_content_filter.started"; do
            attempts=$((attempts + 1))
            test "$attempts" -lt 100 || {
                echo "FAIL: independent compilation tasks did not overlap" >&2
                exit 1
            }
            sleep 0.02
        done
        ;;
    verify_build|verify_swift_build)
        require_done build_resolver build_swift build_extension build_content_filter ;;
    assemble-app-bundle) require_done verify_build verify_swift_build ;;
    dmg) require_done check-release-build-sequence ;;
    notarize) require_done dmg ;;
    staple) require_done notarize ;;
    sparkle-sign) require_done staple ;;
    release-build) require_done sparkle-sign ;;
esac
test "${FAIL_TASK:-}" != "$task" || {
    echo "Injected failure: $task" >&2
    exit 1
}
touch "$TEST_DIR/$task.done"
printf '%s done\n' "$task" >> "$TEST_DIR/events"
SH

{
    echo '.PHONY: release-build assemble-app-bundle prepare build_resolver build_swift build_extension build_content_filter verify_build verify_swift_build check-release-build-sequence dmg notarize staple sparkle-sign'
    extract_rule "$repo/Makefile" release-build
    printf '\t@sh "$(TEST_DIR)/../worker.sh" release-build\n'
    extract_rule "$repo/Sources/MacDNS/Makefile" assemble-app-bundle
    printf '\t@sh "$(TEST_DIR)/../worker.sh" assemble-app-bundle\n'
    for task in prepare build_resolver build_swift build_extension build_content_filter verify_build verify_swift_build check-release-build-sequence dmg notarize staple sparkle-sign; do
        printf '%s:\n\t@sh "$(TEST_DIR)/../worker.sh" %s\n' "$task" "$task"
    done
} > "$work/Makefile"

run_case() {
    name=$1 target=$2 failure=$3 forbidden=$4
    mkdir "$work/$name"
    if (cd "$work" && make --no-print-directory -j8 "$target" TEST_DIR="$work/$name" FAIL_TASK="$failure") > "$work/$name/output" 2>&1; then
        test -z "$failure" || {
            echo "FAIL: $name ignored $failure failure"
            exit 1
        }
    else
        if test -z "$failure"; then
            cat "$work/$name/output"
            exit 1
        fi
        grep -q "Injected failure: $failure" "$work/$name/output"
    fi
    for task in $forbidden; do
        if grep -q "^$task start$" "$work/$name/events"; then
            echo "FAIL: $name started $task after a failed prerequisite"
            exit 1
        fi
    done
    echo "PASS: $name"
}

run_case assembly assemble-app-bundle '' ''
run_case assembly-failure assemble-app-bundle build_resolver 'verify_build verify_swift_build assemble-app-bundle'
run_case release release-build '' ''
run_case sequence-failure release-build check-release-build-sequence 'dmg notarize staple sparkle-sign release-build'
run_case dmg-failure release-build dmg 'notarize staple sparkle-sign release-build'
run_case notarize-failure release-build notarize 'staple sparkle-sign release-build'

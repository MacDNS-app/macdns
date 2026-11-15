#!/bin/sh
# Durable proof that the invariant rules still fire.
#
# WHY THIS EXISTS
# A lint that cannot fail is worse than no lint: it manufactures confidence in
# the invariants it claims to guard. Two real defects in this suite had that
# shape: rule modules that were present but never executed, and awk scanners
# that crashed while the rule still printed a well-formed FAIL built from their
# empty output. This selftest proves that each rule goes RED for the reason it
# claims.
#
# HOW IT WORKS
# Every case runs a REAL rule module against a synthetic fixture tree via
# MACDNS_LINT_ROOT. The fixture is a minimal, invariant-compliant mini-repo that
# carries only the shapes the rules match, so cases never anchor on production
# source and do not rot on every unrelated commit.
#
# The fixture's AGENTS.md is copied from the real one at run time, because the
# rules quote it and anchor on its bullets. That is the one intentional coupling.
#
# Not wired into `make lint` or `make ci`: it proves the lint, it does not lint
# the tree. Run it when changing a rule, a helper, or the runner.
#
# Usage:
#   Scripts/invariant-lint/selftest/run.sh          # every case
#   Scripts/invariant-lint/selftest/run.sh J13      # cases whose file matches
set -u

SELFTEST_DIR=$(cd "$(dirname "$0")" && pwd)
LINT_DIR=$(cd "$SELFTEST_DIR/.." && pwd)
REAL_ROOT=$(cd "$LINT_DIR/../.." && pwd)
FIXTURE="$SELFTEST_DIR/fixture"

WORK=$(mktemp -d -t macdns-invariant-selftest)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

if [ ! -f "$REAL_ROOT/AGENTS.md" ]; then
    printf 'invariant-lint selftest: no AGENTS.md at %s\n' "$REAL_ROOT" >&2
    exit 2
fi

W="$WORK/tree"
CASE=""
BROKEN=0
PASSED=0
FAILED=0

# --- fixture -----------------------------------------------------------------

# The `## Critical invariants` section of the real AGENTS.md. Copied rather than
# duplicated so the fixture cannot drift into quoting an invariant that no longer
# exists. The bullet-deletion cases then mutate a faithful copy.
claude_md() {
    awk '
        /^## Critical invariants/                          { inside = 1 }
        inside && /^## / && !/^## Critical invariants/      { inside = 0 }
        inside                                             { print }
    ' "$REAL_ROOT/AGENTS.md"
}

# begin <case-name> Restores a pristine fixture tree.
begin() {
    CASE="$1"
    rm -rf "$W"
    mkdir -p "$W"
    cp -R "$FIXTURE/." "$W/"
    claude_md >"$W/AGENTS.md"
    if [ ! -s "$W/AGENTS.md" ]; then
        printf '  BROKEN %s — the real AGENTS.md has no "## Critical invariants" section\n' "$CASE"
        BROKEN=$((BROKEN + 1))
    fi
}

# --- mutations ---------------------------------------------------------------
#
# All matching is literal (awk index()), never regex: awk expands backslash
# escapes in -v assignments, so a regex-shaped anchor silently fails to land and
# turns the case into a vacuous pass. Every mutation asserts that it changed the
# file for the same reason.

_changed() {
    if cmp -s "$W/$1" "$WORK/before"; then
        printf '  BROKEN %s — mutation matched nothing in %s: %s\n' "$CASE" "$1" "$2"
        BROKEN=$((BROKEN + 1))
        return 1
    fi
    return 0
}

# add <rel> <line> Appends a line of code to an existing fixture file.
add() {
    if [ ! -f "$W/$1" ]; then
        printf '  BROKEN %s — no such fixture file: %s\n' "$CASE" "$1"
        BROKEN=$((BROKEN + 1))
        return 1
    fi
    printf '%s\n' "$2" >>"$W/$1"
}

# put <rel> <line> Creates a new file holding one line of code.
put() {
    mkdir -p "$(dirname "$W/$1")"
    printf '%s\n' "$2" >"$W/$1"
}

# swap <rel> <literal-old> <new-line> Replaces every line containing old.
swap() {
    cp "$W/$1" "$WORK/before"
    awk -v old="$2" -v new="$3" '
        index($0, old) { print new; next }
        { print }
    ' "$WORK/before" >"$W/$1"
    _changed "$1" "$2"
}

# drop <rel> <literal-match> Deletes every line containing the match.
drop() {
    cp "$W/$1" "$WORK/before"
    awk -v m="$2" 'index($0, m) { next } { print }' "$WORK/before" >"$W/$1"
    _changed "$1" "$2"
}

# swap_after <rel> <literal-anchor> <literal-old> <new-line> Replaces only the
# first line containing old that appears at or after the anchor line. For text
# that repeats verbatim in several functions, where the point of the case is
# which occurrence was removed.
swap_after() {
    cp "$W/$1" "$WORK/before"
    awk -v anchor="$2" -v old="$3" -v new="$4" '
        !armed && index($0, anchor) { armed = 1 }
        armed && !done && index($0, old) { print new; done = 1; next }
        { print }
    ' "$WORK/before" >"$W/$1"
    _changed "$1" "$2 -> $3"
}

# unlink <rel>... Removes fixture files, for cases about a rule losing scope.
unlink() {
    for _u in "$@"; do
        if [ ! -f "$W/$_u" ]; then
            printf '  BROKEN %s — no such fixture file: %s\n' "$CASE" "$_u"
            BROKEN=$((BROKEN + 1))
            return 1
        fi
        rm -f "$W/$_u"
    done
}

# --- expectations ------------------------------------------------------------

# expect <rule-id> <ok|fail|error> [must-contain] [must-not-contain]
#
# `must-contain` is required for fail/error: a case that only asserts "something
# went red" would pass for the wrong reason, which is the failure mode this whole
# file exists to prevent.
expect() {
    expect_in "$LINT_DIR" "$@"
}

expect_in() {
    _lint_dir="$1"
    _id="$2"
    _want="$3"
    _needle="${4:-}"
    _absent="${5:-}"

    if [ "$_want" != "ok" ] && [ -z "$_needle" ]; then
        printf '  BROKEN %s — a %s expectation must name the message it expects\n' "$CASE" "$_want"
        BROKEN=$((BROKEN + 1))
        return 1
    fi

    _rule=""
    for _candidate in "$_lint_dir/rules/$_id"*; do
        [ -f "$_candidate" ] || continue
        _rule="$_candidate"
        break
    done
    if [ -z "$_rule" ]; then
        printf '  BROKEN %s — no rule module matches %s\n' "$CASE" "$_id"
        BROKEN=$((BROKEN + 1))
        return 1
    fi

    _out=$(MACDNS_LINT_ROOT="$W" sh "$_rule" 2>&1)
    case $? in
        0) _got=ok ;;
        1) _got=fail ;;
        *) _got=error ;;
    esac

    if [ "$_got" != "$_want" ]; then
        _report_case_failure "want $_want, got $_got"
        return 1
    fi
    if [ -n "$_needle" ] && ! printf '%s' "$_out" | grep -qF -- "$_needle"; then
        _report_case_failure "missing expected message: $_needle"
        return 1
    fi
    if [ -n "$_absent" ] && printf '%s' "$_out" | grep -qF -- "$_absent"; then
        _report_case_failure "output must not contain: $_absent"
        return 1
    fi
    PASSED=$((PASSED + 1))
    printf '  ok   %s\n' "$CASE"
}

_report_case_failure() {
    FAILED=$((FAILED + 1))
    printf '  FAIL %s — %s\n' "$CASE" "$1"
    printf '%s\n' "$_out" | sed 's/^/         | /'
}

# expect_runner <lint-dir> <ok|fail|error> <must-contain> Exercises run.sh
# itself rather than one rule module.
expect_runner() {
    _out=$(MACDNS_LINT_ROOT="$W" sh "$1/run.sh" 2>&1)
    case $? in
        0) _got=ok ;;
        1) _got=fail ;;
        *) _got=error ;;
    esac
    if [ "$_got" != "$2" ]; then
        _report_case_failure "want $2, got $_got"
        return 1
    fi
    if ! printf '%s' "$_out" | grep -qF -- "$3"; then
        _report_case_failure "missing expected message: $3"
        return 1
    fi
    PASSED=$((PASSED + 1))
    printf '  ok   %s\n' "$CASE"
}

# clone_lint <name> Prints the path of a private copy of the whole lint tree,
# for cases that damage the lint itself instead of the fixture.
clone_lint() {
    _clone="$WORK/$1"
    rm -rf "$_clone"
    mkdir -p "$_clone"
    cp -R "$LINT_DIR/." "$_clone/"
    rm -rf "$_clone/selftest"
    printf '%s' "$_clone"
}

# --- driver ------------------------------------------------------------------

selected=$*
ran=0

printf '=== Invariant Lint Selftest ===\n'

for case_file in "$SELFTEST_DIR/cases"/*.sh; do
    [ -f "$case_file" ] || continue
    name=$(basename "$case_file" .sh)
    if [ -n "$selected" ]; then
        keep=0
        for want in $selected; do
            case "$name" in
                "$want"*) keep=1 ;;
            esac
        done
        [ "$keep" -eq 1 ] || continue
    fi
    ran=$((ran + 1))
    printf -- '-- %s\n' "$name"
    . "$case_file"
done

if [ "$ran" -eq 0 ]; then
    printf 'invariant-lint selftest: no case files matched: %s\n' "$selected" >&2
    exit 1
fi

if [ "$BROKEN" -ne 0 ]; then
    printf '%d case(s) could not run — the selftest itself is broken\n' "$BROKEN" >&2
    exit 2
fi

if [ "$FAILED" -ne 0 ]; then
    printf '%d of %d selftest case(s) failed\n' "$FAILED" "$((PASSED + FAILED))" >&2
    exit 1
fi

printf '%d selftest case(s) passed across %d rule(s)\n' "$PASSED" "$ran"

# Shared helpers for the MacDNS invariant lint suite.
#
# Sourced by every rule module. A rule module must define LINT_DIR before
# sourcing this file.
#
# Contract of a rule module:
#   - protects exactly ONE documented invariant from AGENTS.md
#   - anchors itself to a literal substring of that invariant's bullet, so
#     deleting the invariant fails the lint instead of silently disarming it
#   - reports every violation as `file:line: message`
#   - prints the invariant text, quoted from AGENTS.md, when it fails
#   - carries at least one positive assertion, so it cannot pass vacuously after
#     the code it guards is renamed or deleted
#
# Detection helpers always feed `report` from a `while read < file` loop rather
# than a pipeline, because a pipeline runs in a subshell and would discard the
# violation count.

# MACDNS_LINT_ROOT retargets every rule at another tree. It exists for
# selftest/, which runs the real rules against synthetic fixtures; nothing in
# the normal `make lint-invariants` path sets it.
REPO_ROOT=${MACDNS_LINT_ROOT:-$(cd "$LINT_DIR/../.." && pwd)}
AGENTS_MD="$REPO_ROOT/AGENTS.md"
AWKLIB="$LINT_DIR/lib/awklib.awk"
REGION_AWK="$LINT_DIR/lib/region.awk"
GREP_CODE_AWK="$LINT_DIR/lib/grep_code.awk"
CALLBACK_LINT_AWK="$LINT_DIR/lib/callback_lint.awk"

TAB=$(printf '\t')
LINT_TMP=$(mktemp -t macdns-invariant-lint)
LINT_ERR="$LINT_TMP.err"
trap 'rm -f "$LINT_TMP" "$LINT_ERR"' EXIT HUP INT TERM

RULE_ID=""
RULE_ANCHOR=""
VIOLATIONS=0
VIOLATION_LOG=""

# Prints the AGENTS.md "Critical invariants" bullet containing RULE_ANCHOR.
invariant_text() {
    awk -v anchor="$RULE_ANCHOR" '
        /^## Critical invariants/    { inside = 1; next }
        inside && /^## /             { inside = 0 }
        inside && index($0, anchor)  { print; found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$AGENTS_MD"
}

rule_begin() {
    RULE_ID="$1"
    RULE_ANCHOR="$2"
    VIOLATIONS=0
    VIOLATION_LOG=""
    if ! invariant_text >/dev/null 2>&1; then
        printf '  FAIL %s — the protected invariant is no longer in AGENTS.md\n' "$RULE_ID"
        printf '       missing anchor: %s\n' "$RULE_ANCHOR"
        exit 1
    fi
}

# report <file> <line> <message>
report() {
    VIOLATIONS=$((VIOLATIONS + 1))
    VIOLATION_LOG="${VIOLATION_LOG}    ${1#"$REPO_ROOT"/}:$2: $3
"
}

rule_end() {
    if [ "$VIOLATIONS" -eq 0 ]; then
        printf '  ok   %s\n' "$RULE_ID"
        exit 0
    fi
    printf '  FAIL %s — %d violation(s)\n' "$RULE_ID" "$VIOLATIONS"
    printf '%s' "$VIOLATION_LOG"
    printf '    invariant (AGENTS.md):\n'
    invariant_text | sed 's/^- /      /'
    exit 1
}

# A crashed scanner checked nothing, so its empty output is no evidence either
# way. Reporting it as a violation invents findings, and reporting it as clean
# invents a pass. Exit 2 instead, which the runner surfaces as an internal error
# rather than a result. Using the reserved awk builtin `close` as a parameter
# name once made every scanner a syntax error while the rules still printed a
# well-formed FAIL built from crashed programs.
#
# Written to stderr because findings are stdout and internal errors are not
# findings. stderr also escapes any redirect a caller put on the helper that
# crashed.
rule_error() {
    {
        printf '  ERROR %s — %s; the rule did not run\n' "${RULE_ID:-invariant-lint}" "$1"
        if [ -s "$LINT_ERR" ]; then
            sed 's/^/         /' "$LINT_ERR"
        fi
    } >&2
    exit 2
}

# lint_awk <awk-arg>... Runs a scanner into LINT_TMP, aborting on failure.
# /dev/null is appended so an empty file list can never leave awk reading stdin.
lint_awk() {
    if ! awk "$@" /dev/null >"$LINT_TMP" 2>"$LINT_ERR"; then
        rule_error "scanner failed"
    fi
    : >"$LINT_ERR"
}

# lint_awk_test <awk-arg>... A scanner used as a predicate: 0 = matched,
# 1 = did not match, anything else is a crash.
lint_awk_test() {
    awk "$@" /dev/null >/dev/null 2>"$LINT_ERR"
    _lt_status=$?
    case "$_lt_status" in
        0 | 1) : >"$LINT_ERR" ;;
        *) rule_error "predicate scanner failed" ;;
    esac
    return "$_lt_status"
}

# Fails the rule when a required file is absent. A rule pointed at a deleted
# file must not report success.
require_file() {
    if [ ! -f "$1" ]; then
        report "$1" 0 "expected file is missing; the invariant's implementation moved or was deleted"
        return 1
    fi
    return 0
}

# report_stream <message> Turns the "<file>\t<line>\t<text>" lines a producer
# left in LINT_TMP into reported violations.
report_stream() {
    while IFS="$TAB" read -r _rs_file _rs_line _rs_text; do
        [ -n "$_rs_line" ] || continue
        report "$_rs_file" "$_rs_line" "$1: $_rs_text"
    done <"$LINT_TMP"
}

# code_scan <message> <ere> <file>... The knob-free common case.
# Rules needing `also`/`allow`/`skip`/`neutralize` call lint_awk directly and
# then report_stream, so the knob and its justification stay visible in the rule.
code_scan() {
    _cs_msg="$1"
    shift
    _cs_re="$1"
    shift
    if [ "$#" -eq 0 ]; then
        rule_error "code_scan got an empty file list, so it checked nothing"
    fi
    lint_awk -v re="$_cs_re" -f "$AWKLIB" -f "$GREP_CODE_AWK" "$@"
    report_stream "$_cs_msg"
}

# require_present <file> <ere> <message> Fails unless the file contains ere.
require_present() {
    lint_awk -v re="$2" -f "$AWKLIB" -f "$GREP_CODE_AWK" "$1"
    if [ ! -s "$LINT_TMP" ]; then
        report "$1" 1 "$3"
    fi
}

# region <file> <start-ere> [filter-ere] [occurrence] Prints "lineno<TAB>code"
# for the brace-matched region, optionally restricted to lines matching filter-ere.
# Status 3 means "no such region", which is a finding; anything else is a crash.
region() {
    awk -v start_re="$2" -v re="${3:-}" -v occurrence="${4:-1}" \
        -f "$AWKLIB" -f "$REGION_AWK" "$1" 2>"$LINT_ERR"
    _rg_status=$?
    case "$_rg_status" in
        0 | 3) : >"$LINT_ERR" ;;
        *) rule_error "region scanner failed" ;;
    esac
    return "$_rg_status"
}

# scan_region <file> <start-ere> <ere> <message> [occurrence]
scan_region() {
    if ! region "$1" "$2" "$3" "${5:-1}" >"$LINT_TMP"; then
        report "$1" 0 "region /$2/ not found; the invariant's implementation moved"
        return
    fi
    while IFS="$TAB" read -r _sr_line _sr_text; do
        [ -n "$_sr_line" ] || continue
        report "$1" "$_sr_line" "$4: $(trim "$_sr_text")"
    done <"$LINT_TMP"
}

# require_region_present <file> <start-ere> <ere> <message> [occurrence]
require_region_present() {
    if ! region "$1" "$2" "$3" "${5:-1}" >"$LINT_TMP"; then
        report "$1" 0 "region /$2/ not found; the invariant's implementation moved"
        return
    fi
    if [ ! -s "$LINT_TMP" ]; then
        report "$1" 1 "$4"
    fi
}

# require_any_region_present <file> <start-ere> <ere> <message> At least one
# region whose header matches start-ere must contain ere.
#
# For entrypoints that delegate inside their own function family (`dns_shutdown`
# -> `dns_shutdown_v2` -> `dns_shutdown_inner`): the property being enforced is
# "the shutdown path clears the session", not "the function with this exact name
# does", and the split between wrapper and body is implementation detail.
require_any_region_present() {
    _ar_n=1
    _ar_found=0
    while [ "$_ar_n" -le 32 ]; do
        region "$1" "$2" "$3" "$_ar_n" >"$LINT_TMP" || break
        if [ -s "$LINT_TMP" ]; then
            _ar_found=1
            break
        fi
        _ar_n=$((_ar_n + 1))
    done
    if [ "$_ar_found" -eq 0 ]; then
        report "$1" 1 "$4"
    fi
}

# callback_scan <file> <message> [-v k=v]... Runs the callback-body engine over
# one file, because its "no callback body found" check is per invocation.
callback_scan() {
    _cb_file="$1"
    shift
    _cb_msg="$1"
    shift
    lint_awk "$@" -f "$AWKLIB" -f "$CALLBACK_LINT_AWK" "$_cb_file"
    while IFS="$TAB" read -r _cb_line _cb_text; do
        [ -n "$_cb_line" ] || continue
        report "$_cb_file" "$_cb_line" "$_cb_msg: $_cb_text"
    done <"$LINT_TMP"
}

trim() {
    printf '%s' "$1" | sed 's/^[ 	]*//; s/[ 	]*$//'
}

# File lists are expanded unquoted so awk receives many operands in one call.
# That is safe only while no source path contains whitespace. This check makes
# the rule fail loudly rather than silently skip files if that ever changes.
assert_plain_paths() {
    if printf '%s' "$1" | grep -q '[ 	]'; then
        report "$REPO_ROOT/AGENTS.md" 0 \
            "a source path contains whitespace; the lint's file-list expansion is unsafe"
    fi
}

swift_files() {
    find "$@" -type f -name '*.swift' | sort
}

rust_files() {
    find "$@" -type f -name '*.rs' | sort
}

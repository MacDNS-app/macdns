#!/bin/sh
# Mechanical enforcement for the critical invariants documented in AGENTS.md.
#
# One rule module per invariant, so a failure names the contract it protects.
# Every module reports `file:line` for each violation and then quotes the
# invariant bullet from AGENTS.md. Pure POSIX shell + awk: no new runtime
# dependency, and fast enough to run on every `make ci`.
#
# Layout contract:
#   rules/  executable rule modules only. Every file here is executed.
#   lib/    shared awk/shell helpers, including per-rule awk producers
#
# Discovery walks the rules/ directory listing instead of globbing one
# extension, and any entry it cannot execute is a hard failure. That is the
# non-vacuity guarantee: a rule module can never be present but inert. Globbing
# *.sh once skipped awk modules silently and reported green for invariants that
# were never checked.
#
# J20 is enforced in two places on purpose. `verify_signing` in
# Sources/MacDNS/Makefile checks the dylib's hardened-runtime flag and
# TeamIdentifier, because only the signed artifacts of `make release` can show
# them. rules/J20-dylib-handle.sh checks the handle lifetime, whose failure is a
# crash on the next start on a machine that already shipped.
#
# rules/ does not yet cover every bullet in the Critical invariants section.
# A missing rule is a gap, not a statement that the invariant is enforced.
#
# Usage:
#   Scripts/invariant-lint/run.sh              # run every rule
#   Scripts/invariant-lint/run.sh J09 J10      # run selected rules by id prefix
set -u

LINT_DIR=$(cd "$(dirname "$0")" && pwd)
RULES_DIR="$LINT_DIR/rules"

selected=$*
failures=0
errors=0
ran=0
present=0
skipped=0

# Exit-status contract of a rule module:
#   0  the invariant holds
#   1  violations found (a finding)
#   2  the rule could not run (a crashed scanner, a missing helper)
# 2 is tracked separately because an internal error is not a result: reporting it
# as a violation would invent findings, ignoring it would invent a pass.
run_rule() {
    "$@"
    case $? in
        0) ;;
        1) failures=$((failures + 1)) ;;
        *) errors=$((errors + 1)) ;;
    esac
}

printf '=== Invariant Lint ===\n'

if [ ! -d "$RULES_DIR" ]; then
    printf 'invariant-lint: %s does not exist\n' "$RULES_DIR" >&2
    exit 1
fi

for rule in "$RULES_DIR"/*; do
    [ -f "$rule" ] || continue
    present=$((present + 1))
    name=$(basename "$rule")
    id=${name%.*}

    if [ -n "$selected" ]; then
        keep=0
        for want in $selected; do
            case "$id" in
                "$want"*) keep=1 ;;
            esac
        done
        if [ "$keep" -eq 0 ]; then
            skipped=$((skipped + 1))
            continue
        fi
    fi

    ran=$((ran + 1))
    case "$name" in
        *.sh)
            run_rule sh "$rule"
            ;;
        *)
            if [ -x "$rule" ]; then
                run_rule "$rule"
            else
                # The runner cannot invoke it, so it would be an inert rule. That
                # is a broken lint, not a violated invariant, hence an error.
                printf '  ERROR %s — not an executable rule module\n' "$id" >&2
                printf '         %s cannot be executed by the runner.\n' "rules/$name" >&2
                printf '         A rule module must be a *.sh file or an executable with a shebang.\n' >&2
                printf '         A shared awk producer is not a rule: move it to lib/ and invoke it\n' >&2
                printf '         from the rule module that owns it.\n' >&2
                errors=$((errors + 1))
            fi
            ;;
    esac
done

if [ "$present" -eq 0 ]; then
    printf 'invariant-lint: no rule modules found in %s\n' "$RULES_DIR" >&2
    exit 1
fi

if [ "$ran" -eq 0 ]; then
    printf 'invariant-lint: no rule modules matched: %s\n' "$selected" >&2
    exit 1
fi

# Non-vacuity assertion, checked against the directory listing rather than any
# hardcoded inventory: on a full run, every file in rules/ must have been
# executed. A hardcoded list would rot into the same silent pass it prevents.
if [ -z "$selected" ] && [ "$ran" -ne "$present" ]; then
    printf 'invariant-lint: %d rule module(s) present but only %d executed\n' \
        "$present" "$ran" >&2
    exit 1
fi

if [ "$errors" -ne 0 ]; then
    printf '%d of %d invariant rule(s) could not run; fix the lint itself before trusting it\n' \
        "$errors" "$ran" >&2
    exit 2
fi

if [ "$failures" -ne 0 ]; then
    printf '%d of %d invariant rule(s) failed\n' "$failures" "$ran" >&2
    exit 1
fi

if [ "$skipped" -gt 0 ]; then
    printf '%d invariant rule(s) passed (%d skipped by selection)\n' "$ran" "$skipped"
else
    printf '%d invariant rule(s) passed (all %d module(s) in rules/ executed)\n' "$ran" "$present"
fi

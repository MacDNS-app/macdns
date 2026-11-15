# Prints "<lineno>\t<code>" for the delimiter-matched region that starts at the
# first `opener` at or after the `occurrence`-th line matching `start_re`.
#
# lib/region.awk does the same for braces only. J16 needs the identical walk over
# `[` … `]` as well, because the stop half of the lifecycle order is written as an
# array literal (`static let stopActions: [ProxyReadinessAction] = [ … ]`) with no
# braces to match. Parameterising the delimiters keeps J16 on one code path for
# both shapes instead of two scanners with different bugs.
#
# The bracket walk starts at the FIRST `[` on the header line, which for a typed
# array literal is the type annotation. That is harmless: the annotation's
# brackets balance on the same line, so the depth after the header line is still
# the one contributed by the literal's own `[`.
#
# <code> has its trailing comment removed, so a rule never matches a symbol that
# is only mentioned in a comment.
#
# Exits 3 when no region is found: an anchor that no longer matches must fail
# loudly rather than silently pass on an empty region.

BEGIN {
    if (occurrence == "") occurrence = 1
    if (opener == "") opener = "{"
    if (closer == "") closer = "}"
    matches = 0
    armed = 0
    started = 0
    depth = 0
}

function emit(lineno, code) {
    if (re == "" || code ~ re) print lineno "\t" code
}

{
    il_guard_raw($0, FILENAME, FNR)
    code = il_decomment($0)
    counted = il_blank_strings(code)

    if (!armed) {
        if ($0 ~ start_re) {
            matches++
            if (matches == occurrence + 0) armed = 1
        }
        if (!armed) next
    }

    if (!started) {
        o = index(counted, opener)
        if (o == 0) next
        started = 1
        depth = il_delta(substr(counted, o), opener, closer)
        emit(FNR, substr(code, o))
        if (depth <= 0) exit
        next
    }

    depth += il_delta(counted, opener, closer)
    emit(FNR, code)
    if (depth <= 0) exit
}

END {
    if (!started) {
        printf("invariant-lint: %s: no region found for /%s/ (occurrence %d)\n",
            FILENAME, start_re, occurrence) > "/dev/stderr"
        exit 3
    }
}

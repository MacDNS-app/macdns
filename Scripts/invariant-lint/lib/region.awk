# Prints "<lineno>\t<code>" for the brace-matched region that starts at the
# first "{" at or after the `occurrence`-th line matching `start_re`.
#
# With `re` set, only region lines matching it are printed. The region is still
# scanned in full so brace tracking stays correct.
#
# <code> is the source line with its trailing comment removed, so rules never
# match a mention of a banned symbol inside a comment.
#
# Exits 3 when no region is found: a rule whose anchor no longer matches must
# fail loudly rather than silently pass on an empty region.

BEGIN {
    if (occurrence == "") occurrence = 1
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
        o = index(counted, "{")
        if (o == 0) next
        started = 1
        depth = il_delta(substr(counted, o), "{", "}")
        emit(FNR, substr(code, o))
        if (depth <= 0) exit
        next
    }

    depth += il_delta(counted, "{", "}")
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

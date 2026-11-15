# Scanner for J20. See rules/J20-dylib-handle.sh for the contract.
#
# Emits "<file>\t<line>\t<message>" per violation; scope-level findings carry
# line 0 and the scope path. Requires -v scope=<agent source root>.
#
# Everything is discovered from the `dlopen` call site outward: the handle
# property is whatever that call's result is stored into, so renaming it needs no
# change here. `dlsym` is never counted: resolving more symbols from an already
# open handle is what the handle is for.

BEGIN {
    OPEN_RE = "(^|[^A-Za-z0-9_])dlopen[ \t]*[(]"
    CLOSE_RE = "(^|[^A-Za-z0-9_])dlclose[ \t]*[(]"
    NV = 0
    NS = 0
    ND = 0
    NUNPARSED = 0
}

{
    il_guard_raw($0, FILENAME, FNR)
    N++
    FILE[N] = FILENAME
    LNO[N] = FNR
    CODE[N] = il_decomment($0)
    BLANK[N] = il_blank_strings(CODE[N])
}

END {
    if (N == 0) {
        scope_violate("no Swift source reached the scanner; J20 checked nothing")
    } else {
        find_depths()
        find_defs()
        check_handle()
    }
    emit()
}

function violate(i, msg) {
    NV++
    VAT[NV] = i
    VMSG[NV] = msg
}

function scope_violate(msg) {
    NS++
    SMSG[NS] = msg
}

function emit(   k, j, best, tmp) {
    for (k = 1; k <= NS; k++) {
        printf("%s\t%d\t%s\n", scope, 0, SMSG[k])
    }
    for (k = 1; k < NV; k++) {
        best = k
        for (j = k + 1; j <= NV; j++) {
            if (VAT[j] < VAT[best]) best = j
        }
        if (best != k) {
            tmp = VAT[k]; VAT[k] = VAT[best]; VAT[best] = tmp
            tmp = VMSG[k]; VMSG[k] = VMSG[best]; VMSG[best] = tmp
        }
    }
    for (k = 1; k <= NV; k++) {
        printf("%s\t%d\t%s\n", FILE[VAT[k]], LNO[VAT[k]], VMSG[k])
    }
}

# Brace depth entering each line, reset per file. A stored property sits at a
# shallower depth than any statement inside a function body, which is how the
# handle is told apart from a local that dies with the call.
function find_depths(   i, d) {
    d = 0
    for (i = 1; i <= N; i++) {
        if (i > 1 && FILE[i] != FILE[i - 1]) d = 0
        DEPTH[i] = d
        d += il_delta(BLANK[i], "{", "}")
    }
}

# Forward character walk to the matching closer. Sets WALK_LINE / WALK_COL to the
# closer's position and returns its line, or 0 when it never balances.
function match_pair(i, pos, opener, closer,   d, k, s, j, c, start) {
    d = 0
    for (k = i; k <= N; k++) {
        if (FILE[k] != FILE[i]) return 0
        s = BLANK[k]
        start = (k == i) ? pos : 1
        for (j = start; j <= length(s); j++) {
            c = substr(s, j, 1)
            if (c == opener) {
                d++
            } else if (c == closer) {
                d--
                if (d == 0) {
                    WALK_LINE = k
                    WALK_COL = j
                    return k
                }
            }
        }
    }
    return 0
}

function find_defs(   i, s, name, rest, p, sigcol, pl, pc, bl, bc, k, j) {
    for (i = 1; i <= N; i++) {
        s = BLANK[i]
        if (match(s, /(^|[^A-Za-z0-9_])func[ \t]+[A-Za-z_][A-Za-z0-9_]*/) == 0) continue
        name = substr(s, RSTART, RLENGTH)
        sub(/^[^A-Za-z0-9_]*/, "", name)
        sub(/^func[ \t]+/, "", name)
        rest = substr(s, RSTART + RLENGTH)
        p = index(rest, "(")
        if (p == 0) {
            unparsed(i)
            continue
        }
        sigcol = RSTART + RLENGTH + p - 1
        if (match_pair(i, sigcol, "(", ")") == 0) {
            unparsed(i)
            continue
        }
        pl = WALK_LINE
        pc = WALK_COL
        # The body brace is the first `{` after the signature's closing paren, so
        # a closure default argument inside the signature is never mistaken for it.
        bl = 0
        for (k = pl; k <= N && k <= pl + 2; k++) {
            if (FILE[k] != FILE[i]) break
            j = index(substr(BLANK[k], (k == pl) ? pc + 1 : 1), "{")
            if (j > 0) {
                bl = k
                bc = ((k == pl) ? pc : 0) + j
                break
            }
        }
        if (bl == 0) continue
        if (match_pair(bl, bc, "{", "}") == 0) {
            unparsed(i)
            continue
        }
        ND++
        DNAME[ND] = name
        DBODY[ND] = bl
        DEND[ND] = WALK_LINE
    }
}

function unparsed(i) {
    NUNPARSED++
    UNPARSEDAT[NUNPARSED] = i
}

function enclosing_def(i,   d, best, bestspan, span) {
    best = 0
    bestspan = 0
    for (d = 1; d <= ND; d++) {
        if (i < DBODY[d] || i > DEND[d]) continue
        span = DEND[d] - DBODY[d]
        if (best == 0 || span < bestspan) {
            best = d
            bestspan = span
        }
    }
    return best
}

function binding_name(frag) {
    sub(/^[^A-Za-z0-9_]*/, "", frag)
    sub(/^(let|var)[ \t]+/, "", frag)
    sub(/[ \t]*=.*$/, "", frag)
    return frag
}

function assign_target(frag) {
    sub(/^[^A-Za-z0-9_]*/, "", frag)
    sub(/[ \t]*=.*$/, "", frag)
    sub(/^self[ \t]*[.][ \t]*/, "", frag)
    return il_trim(frag)
}

# Does the block opened on line k exit before falling through?
function block_returns(k,   c, e, j) {
    c = index(BLANK[k], "{")
    if (c == 0) return 0
    if (match_pair(k, c, "{", "}") == 0) return 0
    e = WALK_LINE
    for (j = k; j <= e; j++) {
        if (BLANK[j] ~ /(^|[^A-Za-z0-9_])return([^A-Za-z0-9_]|$)/) return 1
    }
    return 0
}

function check_handle(   i, k, oi, d, s, handle, localv, target, hd, guarded, unknown, line, dd, where, note) {
    NOPEN = 0
    for (i = 1; i <= N; i++) {
        if (BLANK[i] ~ CLOSE_RE) {
            violate(i, "`dlclose` in the agent target; the handle must live for the whole agent lifetime — every symbol pointer resolved from it stays live after teardown, and `stop()` releases tasks and the Tokio runtime, never the library")
        }
        if (BLANK[i] ~ OPEN_RE) {
            NOPEN++
            OPENAT[NOPEN] = i
        }
    }

    if (NOPEN == 0) {
        scope_violate("no `dlopen` call in the agent target; the resolver dylib is not loaded here any more and J20's subject moved")
        return
    }
    if (NOPEN > 1) {
        for (k = 1; k <= NOPEN; k++) {
            violate(OPENAT[k], sprintf("`dlopen` call site %d of %d; the resolver dylib is opened once per agent lifetime and every later `start()` reuses the cached handle", k, NOPEN))
        }
        return
    }

    oi = OPENAT[1]
    d = enclosing_def(oi)
    if (d == 0) {
        violate(oi, "`dlopen` is not inside a function body; J20 cannot tell what guards it")
        return
    }

    # A signature the def scanner could not parse in this file could hide the
    # enclosing function, which would make the guard search look at the wrong span.
    for (k = 1; k <= NUNPARSED; k++) {
        if (FILE[UNPARSEDAT[k]] != FILE[oi]) continue
        violate(UNPARSEDAT[k], "unrecognised function signature in the file that owns the dylib handle; J20 will not guess the enclosing scope of `dlopen`")
    }

    s = BLANK[oi]
    handle = ""
    localv = ""
    if (match(s, /(^|[^A-Za-z0-9_])(let|var)[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*dlopen[ \t]*\(/)) {
        localv = binding_name(substr(s, RSTART, RLENGTH))
    } else if (match(s, /(^|[^A-Za-z0-9_])(self[ \t]*\.[ \t]*)?[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*dlopen[ \t]*\(/)) {
        handle = assign_target(substr(s, RSTART, RLENGTH))
    }

    if (localv != "") {
        for (k = DBODY[d]; k <= DEND[d]; k++) {
            if (k == oi) continue
            if (match(BLANK[k], "(^|[^A-Za-z0-9_])(self[ \t]*[.][ \t]*)?[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*" localv "([^A-Za-z0-9_]|$)") == 0) continue
            target = assign_target(substr(BLANK[k], RSTART, RLENGTH))
            if (target ~ /^(let|var)[ \t]/) continue
            handle = target
            break
        }
    }

    if (handle == "") {
        violate(oi, "unrecognised `dlopen` result binding; J20 cannot identify the cached handle property, so it cannot prove the dylib is opened once")
        return
    }

    hd = 0
    for (k = 1; k <= N; k++) {
        if (FILE[k] != FILE[oi]) continue
        if (BLANK[k] !~ ("(^|[^A-Za-z0-9_])var[ \t]+" handle "[ \t]*:")) continue
        if (DEPTH[k] >= DEPTH[oi]) continue
        hd = k
        break
    }
    if (hd == 0) {
        violate(oi, "the `dlopen` result is stored in `" handle "`, which is not a `var` property outliving the call; a later `start()` would open the dylib again instead of reusing the handle")
    }

    guarded = 0
    unknown = 0
    for (k = DBODY[d]; k < oi; k++) {
        line = BLANK[k]
        if (line ~ ("(^|[^A-Za-z0-9_])guard[ \t]+(self[ \t]*[.][ \t]*)?" handle "[ \t]*==[ \t]*nil[ \t]*(,|else|$)")) {
            guarded = 1
            break
        }
        if (line ~ ("(^|[^A-Za-z0-9_])if[ \t]+(self[ \t]*[.][ \t]*)?" handle "[ \t]*!=[ \t]*nil")) {
            if (block_returns(k)) {
                guarded = 1
                break
            }
            unknown = k
            continue
        }
        if (line ~ ("(^|[^A-Za-z0-9_])if[ \t]+let[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*(self[ \t]*[.][ \t]*)?" handle "([^A-Za-z0-9_]|$)")) {
            if (block_returns(k)) {
                guarded = 1
                break
            }
            unknown = k
            continue
        }
        if (line ~ ("(^|[^A-Za-z0-9_])(self[ \t]*[.][ \t]*)?" handle "([^A-Za-z0-9_]|$)") && line ~ /(^|[^A-Za-z0-9_])nil([^A-Za-z0-9_]|$)/) {
            unknown = k
        }
    }
    if (!guarded) {
        if (unknown) {
            violate(unknown, "unrecognised `" handle "` nil-guard shape ahead of `dlopen`; J20 will not assume it exits early")
        } else {
            violate(oi, "`dlopen` is not preceded by a `guard " handle " == nil` early exit in " DNAME[d] "(); a repeated call would load the dylib a second time")
        }
    }

    for (k = 1; k <= N; k++) {
        if (FILE[k] != FILE[oi]) continue
        if (BLANK[k] ~ ("(^|[^A-Za-z0-9_])var[ \t]+" handle "[ \t]*:")) continue
        if (BLANK[k] !~ ("(^|[^A-Za-z0-9_])(self[ \t]*[.][ \t]*)?" handle "[ \t]*=[ \t]*nil([^A-Za-z0-9_]|$)")) continue
        dd = enclosing_def(k)
        where = (dd == 0) ? "" : " in " DNAME[dd] "()"
        note = (dd != 0 && DNAME[dd] ~ /^stop/) ? " — `stop()` tears down tasks and the Tokio runtime but leaves the handle intact" : ""
        violate(k, "`" handle "` is cleared" where note "; the next `start()` must reuse the same handle rather than re-`dlopen` the dylib")
    }

    if (dump_out != "") {
        printf("J20 dylib handle: %s, opened once at %s:%d\n", handle, FILE[oi], LNO[oi]) > dump_out
        printf("J20 opened inside: %s(), guarded by a `%s == nil` early exit\n", DNAME[d], handle) > dump_out
        printf("J20 handle property: %s:%d\n", (hd ? FILE[hd] : "<none>"), (hd ? LNO[hd] : 0)) > dump_out
        printf("J20 dlclose call sites: 0 required\n") > dump_out
    }
}

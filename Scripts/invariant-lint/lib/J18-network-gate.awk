# Call-site scanner for J18: agent-originated external network work must start
# inside the NetworkReadySignal gate.
#
# Everything this scanner needs is discovered from the source it reads. It
# carries no list of function names, because a name list is how a call-site lint
# dies: the next legitimate rename turns it red, someone disables it, and the
# invariant is left unguarded.
#
#   gate seam    the type that awaits `NetworkReadySignal` and exposes a
#                closure-taking entry point it awaits, which is what "one
#                testable gate" looks like structurally. Both the type name and
#                the entry-point name are read off the source.
#   gate handles the seam type plus every identifier declared with it as its
#                type, so an injected `self.someGate.run { }` is recognised
#                without knowing what the property was called.
#   gate regions the brace-matched closure of every `<handle>.<entry>` call.
#   inventory    the calls inside those regions that both name at least two
#                words of the enumeration AGENTS.md documents for this invariant
#                AND demonstrably reach an external-network primitive (a
#                URLSession request start, or a `sym("dns_…")`-bound FFI
#                entrypoint). The enumeration lives in the invariant bullet, not
#                here, so the document the team already maintains is the
#                inventory. Divergence between it and the code is reported.
#
# The inventory is then closed over the whole agent target: every other call
# site of an inventoried entry must be gated too. Two exemptions, both shapes
# rather than names, and both move the obligation instead of removing it: a call
# from inside another inventoried entry (one subsystem, gated at its own entry),
# and a function whose body is a single statement delegating to an inventoried
# entry (the wrapper joins the inventory, so its own call sites get checked in
# the next round).
#
# Inputs:
#   tokens         the documented enumeration, space-separated lowercase words
#   scope          path reported for findings that belong to the target rather
#                  than to any one line
#   inventory_out  optional path for a dump of everything discovered
#
# Output: "<file>\t<line>\t<message>" per violation, in source order.

BEGIN {
    ndoc = 0
    split(tokens, _tk, " ")
    for (i in _tk) {
        t = tolower(_tk[i])
        if (length(t) < 4) continue
        if (!(t in DOC)) { DOC[t] = 1; ndoc++ }
    }

    # A URLSession request start. Keyed on the request-start methods and their
    # argument labels rather than on the type name, so a `URLSession` type
    # annotation or a session-configuration builder is not mistaken for traffic.
    URL_RE = "[.](data|dataTask|download|downloadTask|upload|uploadTask|bytes)[ \t]*[(][ \t]*(for|from|with|request|resumeData)[ \t]*:"

    SIGNAL = "NetworkReadySignal"

    # Language keywords that can be followed by "(" and would otherwise be
    # collected as call targets. A Swift keyword list is not a project inventory.
    split("if while guard switch return for catch repeat", _kw, " ")
    for (i in _kw) KW[_kw[i]] = 1

    SEP = "\036"
    MAXDEPTH = 3
}

{
    il_guard_raw($0, FILENAME, FNR)
    N++
    FILE[N] = FILENAME
    LNO[N] = FNR
    CODE[N] = il_decomment($0)
    BLANK[N] = il_blank_strings(CODE[N])
}

# --- reporting ---------------------------------------------------------------

function fail(msg) {
    printf("invariant-lint: J18: %s\n", msg) > "/dev/stderr"
    exit 2
}

function violate(idx, msg) {
    if ((idx SUBSEP msg) in SEEN) return
    SEEN[idx SUBSEP msg] = 1
    VMSG[idx] = (idx in VMSG) ? VMSG[idx] SEP msg : msg
}

function scope_violate(msg) {
    if (msg in SCOPESEEN) return
    SCOPESEEN[msg] = 1
    NSCOPE++
    SCOPEMSG[NSCOPE] = msg
}

# --- small helpers -----------------------------------------------------------

function brace_end(idx, pos,   depth, j, s) {
    depth = 0
    j = idx
    s = substr(BLANK[j], pos)
    while (1) {
        depth += il_delta(s, "{", "}")
        if (depth <= 0) return j
        j++
        if (j > N || FILE[j] != FILE[idx]) return 0
        s = BLANK[j]
    }
}

function alt_add(cur, item) {
    if (cur == "") return item
    if (cur ~ ("(^|[|])" item "([|]|$)")) return cur
    return cur "|" item
}

# Collects "name(" call targets from one blanked line into out[1..n].
function callees(line, out,   s, name, pre, cnt, off) {
    cnt = 0
    s = line
    off = 0
    while (match(s, "[A-Za-z_][A-Za-z0-9_]*[ \t]*[(]")) {
        name = substr(s, RSTART, RLENGTH)
        sub(/[ \t]*[(]$/, "", name)
        pre = (RSTART + off > 1) ? substr(line, RSTART + off - 1, 1) : ""
        if (pre !~ /[A-Za-z0-9_]/ && !(name in KW)) {
            cnt++
            out[cnt] = name
        }
        off += RSTART + RLENGTH - 1
        s = substr(s, RSTART + RLENGTH)
    }
    return cnt
}

# Splits an identifier into lowercase words on camel-case and "_" boundaries.
function words(name, out,   i, c, cur, cnt) {
    cnt = 0
    cur = ""
    for (i = 1; i <= length(name); i++) {
        c = substr(name, i, 1)
        if (c == "_") {
            if (cur != "") { cnt++; out[cnt] = tolower(cur); cur = "" }
            continue
        }
        if (c ~ /[A-Z]/ && cur != "") { cnt++; out[cnt] = tolower(cur); cur = "" }
        cur = cur c
    }
    if (cur != "") { cnt++; out[cnt] = tolower(cur) }
    return cnt
}

# How many distinct documented work-item words this identifier names. Matching is
# by prefix so "updates" answers to "update". The threshold of two is what
# separates a named work item ("startBlocklistScheduler", "forceBlocklistUpdate")
# from a bystander that merely shares one word with the enumeration
# ("reloadBlocklist", "markRefreshCompleted").
function doc_score(name,   out, hit, n, i, t, score) {
    if (name in DOCSCORE) return DOCSCORE[name]
    split("", out)
    split("", hit)
    n = words(name, out)
    score = 0
    for (i = 1; i <= n; i++) {
        for (t in DOC) {
            if (index(out[i], t) == 1 && !(t in hit)) {
                hit[t] = 1
                score++
            }
        }
    }
    DOCSCORE[name] = score
    return score
}

# --- discovery ---------------------------------------------------------------

function find_types(   i, t) {
    for (i = 1; i <= N; i++) {
        if (BLANK[i] !~ /^[ \t]*([A-Za-z@]+[ \t]+)*(struct|class|actor|enum|extension)[ \t]+[A-Za-z_]/) continue
        t = BLANK[i]
        sub(/^[ \t]*/, "", t)
        while (t !~ /^(struct|class|actor|enum|extension)[ \t]/) {
            if (!sub(/^[^ \t]+[ \t]+/, "", t)) break
        }
        if (t !~ /^(struct|class|actor|enum|extension)[ \t]/) continue
        sub(/^(struct|class|actor|enum|extension)[ \t]+/, "", t)
        sub(/[^A-Za-z0-9_].*$/, "", t)
        if (t == "") continue
        TYPEAT[i] = t
        if (BLANK[i] ~ /(struct|class|actor|enum)[ \t]/ && !(t in TYPEDECL)) TYPEDECL[t] = i
    }
}

function type_of(idx,   j) {
    for (j = idx; j >= 1; j--) {
        if (FILE[j] != FILE[idx]) return ""
        if (j in TYPEAT) return TYPEAT[j]
    }
    return ""
}

function find_defs(   i, name, npos, ppos, depth, j, first, s, sigEnd, q, k, bpos, bodyLine, bodyPos, endLine, sig, p, pn) {
    for (i = 1; i <= N; i++) {
        if (BLANK[i] !~ "(^|[^A-Za-z0-9_])(func|init)([^A-Za-z0-9_]|$)") continue
        name = ""
        npos = 0
        if (match(BLANK[i], "(^|[^A-Za-z0-9_])func[ \t]+[A-Za-z_][A-Za-z0-9_]*")) {
            name = substr(BLANK[i], RSTART, RLENGTH)
            sub(/^[^A-Za-z0-9_]?func[ \t]+/, "", name)
            npos = RSTART + RLENGTH
        } else if (match(BLANK[i], "(^|[^A-Za-z0-9_])init[ \t]*[(]")) {
            name = "init"
            npos = RSTART + RLENGTH - 1
        }
        if (name == "") continue

        ppos = index(substr(BLANK[i], npos), "(")
        if (ppos == 0) continue
        ppos = npos + ppos - 1

        depth = 0
        j = i
        first = 1
        sig = ""
        while (1) {
            s = first ? substr(BLANK[j], ppos) : BLANK[j]
            sig = sig " " s
            depth += il_delta(s, "(", ")")
            if (depth <= 0) break
            first = 0
            j++
            if (j > N || FILE[j] != FILE[i]) break
        }
        if (depth > 0) continue
        sigEnd = j

        q = 0
        for (k = length(BLANK[sigEnd]); k >= 1; k--) {
            if (substr(BLANK[sigEnd], k, 1) == ")") { q = k; break }
        }
        bodyLine = 0
        bodyPos = 0
        bpos = index(substr(BLANK[sigEnd], q + 1), "{")
        if (bpos > 0) {
            bodyLine = sigEnd
            bodyPos = q + bpos
        } else {
            for (k = sigEnd + 1; k <= sigEnd + 2 && k <= N && FILE[k] == FILE[i]; k++) {
                if (BLANK[k] ~ "(^|[^A-Za-z0-9_])(func|init|var|let|case)[ \t]") break
                bpos = index(BLANK[k], "{")
                if (bpos > 0) { bodyLine = k; bodyPos = bpos; break }
            }
        }

        ND++
        DNAME[ND] = name
        DSTART[ND] = i
        DSIG[ND] = sig
        DTYPE[ND] = type_of(i)
        DEFIDX[name] = (name in DEFIDX) ? DEFIDX[name] " " ND : "" ND

        pn = ""
        p = sig
        while (match(p, "[A-Za-z_][A-Za-z0-9_]*[ \t]*:")) {
            s = substr(p, RSTART, RLENGTH)
            sub(/[ \t]*:$/, "", s)
            pn = pn " " s
            p = substr(p, RSTART + RLENGTH)
        }
        DPARAMS[ND] = pn

        if (bodyLine == 0) {
            DHASBODY[ND] = 0
            DEND[ND] = i
            continue
        }
        endLine = brace_end(bodyLine, bodyPos)
        if (endLine == 0) {
            DHASBODY[ND] = 0
            DEND[ND] = i
            continue
        }
        DHASBODY[ND] = 1
        DBODY[ND] = bodyLine
        DBODYPOS[ND] = bodyPos
        DEND[ND] = endLine
    }
}

function find_sym_bindings(   i, s, f) {
    for (i = 1; i <= N; i++) {
        if (CODE[i] !~ /sym[ \t]*[(][ \t]*"/) continue
        if (!match(CODE[i], "[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*sym[ \t]*[(]")) continue
        s = substr(CODE[i], RSTART, RLENGTH)
        sub(/[ \t]*=.*$/, "", s)
        f = FILE[i]
        SYMALT[f] = alt_add(SYMALT[f], s)
    }
}

function body_line(d, k) {
    return (k == DBODY[d]) ? substr(BLANK[k], DBODYPOS[d]) : BLANK[k]
}

# The seam: a type other than the signal itself that references the signal and
# exposes a closure-taking entry point it awaits. That is the structure of "one
# gate every network start goes through", and it is what makes the entry point
# discoverable instead of assumed.
function find_gate(   i, t, d, k, np, pl, j, cand, ncand, entry) {
    split("", cand)
    for (i = 1; i <= N; i++) {
        if (BLANK[i] !~ (SIGNAL "[ \t]*[.]")) continue
        t = type_of(i)
        if (t == "" || t == SIGNAL) continue
        cand[t] = 1
    }

    ncand = 0
    GATE = ""
    GATEFN = ""
    for (d = 1; d <= ND; d++) {
        if (!DHASBODY[d]) continue
        if (!(DTYPE[d] in cand)) continue
        if (DSIG[d] !~ /->/) continue
        np = split(DPARAMS[d], pl, " ")
        entry = 0
        for (j = 1; j <= np; j++) {
            for (k = DBODY[d]; k <= DEND[d]; k++) {
                if (body_line(d, k) ~ ("await[ \t]+" pl[j] "[ \t]*[(]")) { entry = 1; break }
            }
            if (entry) break
        }
        if (!entry) continue
        if (GATE == "" ) { GATE = DTYPE[d]; GATEFN = DNAME[d]; ncand = 1 }
        else if (DTYPE[d] != GATE) { ncand++; OTHERGATE[ncand] = DTYPE[d]; OTHERAT[ncand] = DSTART[d] }
    }
    return ncand
}

# --- evidence ----------------------------------------------------------------

function body_has_primitive(d,   k) {
    for (k = DBODY[d]; k <= DEND[d]; k++) {
        if (body_line(d, k) ~ URL_RE) return 1
    }
    return 0
}

function body_has_ffi(d,   k, f) {
    f = FILE[DSTART[d]]
    if (SYMALT[f] == "") return 0
    for (k = DBODY[d]; k <= DEND[d]; k++) {
        if (body_line(d, k) ~ ("(^|[^A-Za-z0-9_])(" SYMALT[f] ")([^A-Za-z0-9_]|$)")) return 1
    }
    return 0
}

# Does a URLSession request start in this function's own body? Used only for the
# "gated but undocumented" report, where the evidence has to be unambiguous. An
# FFI call is not: the gate regions legitimately contain FFI calls that touch
# nothing but LMDB and the cache.
function direct_url(name,   list, n, i, d) {
    if (!(name in DEFIDX)) return 0
    n = split(DEFIDX[name], list, " ")
    for (i = 1; i <= n; i++) {
        d = list[i]
        if (DHASBODY[d] && body_has_primitive(d)) return 1
    }
    return 0
}

# Reaches an external-network primitive within MAXDEPTH hops of agent-target
# function bodies. Bounded and cycle-guarded: this is evidence gathering for the
# calls a gate region already guards, not a whole-program call graph.
function reaches_network(name, depth,   list, n, i, d, k, cs, c, m, j) {
    if (depth <= 0) return 0
    if ((name SUBSEP depth) in EVID) return EVID[name SUBSEP depth]
    if (name in WALKING) return 0
    if (!(name in DEFIDX)) { EVID[name SUBSEP depth] = 0; return 0 }
    WALKING[name] = 1
    n = split(DEFIDX[name], list, " ")
    for (i = 1; i <= n; i++) {
        d = list[i]
        if (!DHASBODY[d]) continue
        if (body_has_primitive(d) || body_has_ffi(d)) {
            delete WALKING[name]
            EVID[name SUBSEP depth] = 1
            return 1
        }
    }
    for (i = 1; i <= n; i++) {
        d = list[i]
        if (!DHASBODY[d]) continue
        for (k = DBODY[d]; k <= DEND[d]; k++) {
            split("", cs)
            m = callees(body_line(d, k), cs)
            for (j = 1; j <= m; j++) {
                c = cs[j]
                if (c == name) continue
                if (reaches_network(c, depth - 1)) {
                    delete WALKING[name]
                    EVID[name SUBSEP depth] = 1
                    return 1
                }
            }
        }
    }
    delete WALKING[name]
    EVID[name SUBSEP depth] = 0
    return 0
}

# --- placement ---------------------------------------------------------------

function in_gate(idx,   r) {
    for (r = 1; r <= NREG; r++) {
        if (idx >= REGSTART[r] && idx <= REGEND[r]) return r
    }
    return 0
}

function enclosing_def(idx,   d, best, span, bestspan) {
    best = 0
    bestspan = 0
    for (d = 1; d <= ND; d++) {
        if (!DHASBODY[d]) continue
        if (idx < DSTART[d] || idx > DEND[d]) continue
        span = DEND[d] - DSTART[d]
        if (best == 0 || span < bestspan) { best = d; bestspan = span }
    }
    return best
}

# A function whose whole body is one statement handing off to `callee`. The
# wrapper starts nothing itself; whoever calls it does, so the obligation moves
# to the wrapper's own call sites rather than disappearing.
function is_delegating_wrapper(d, callee,   k, line, stmts, hit, t) {
    if (!DHASBODY[d]) return 0
    stmts = 0
    hit = 0
    for (k = DBODY[d]; k <= DEND[d]; k++) {
        line = (k == DBODY[d]) ? substr(BLANK[k], DBODYPOS[d] + 1) : BLANK[k]
        if (k == DEND[d]) {
            t = line
            sub(/[}][^}]*$/, "", t)
            line = t
        }
        t = il_trim(line)
        if (t == "") continue
        stmts++
        if (t ~ ("(^|[^A-Za-z0-9_])" callee "[ \t]*[(]")) hit = 1
    }
    return (stmts == 1 && hit)
}

# --- main --------------------------------------------------------------------

END {
    if (N == 0) fail("no agent source was scanned")
    if (ndoc < 2) fail("the documented work enumeration yielded fewer than two usable words")

    find_types()
    find_defs()
    find_sym_bindings()

    # 1. The gate seam.
    extra = find_gate()
    if (GATE == "") {
        scope_violate("no gate seam found: no type awaits " SIGNAL " and hands a caller's closure through; the single testable gate is gone")
        emit()
        exit 0
    }
    for (i = 2; i <= extra; i++) {
        violate(OTHERAT[i], OTHERGATE[i] " is a second " SIGNAL " gate seam alongside " GATE "; agent-originated network work must go through one gate")
    }

    # The method the seam awaits on the signal, and the rule that nothing else
    # may await it: an open-coded wait is a second, untestable gate.
    if (GATE in TYPEDECL) {
        gs = TYPEDECL[GATE]
        gb = index(BLANK[gs], "{")
        ge = (gb > 0) ? brace_end(gs, gb) : 0
    } else {
        gs = 0
        ge = 0
    }
    WAITFN = ""
    for (i = 1; i <= N; i++) {
        if (!match(BLANK[i], SIGNAL "[ \t]*[.]([A-Za-z_][A-Za-z0-9_]*[ \t]*[.][ \t]*)*[A-Za-z_][A-Za-z0-9_]*[ \t]*[(]")) continue
        m = substr(BLANK[i], RSTART, RLENGTH)
        sub(/[ \t]*[(]$/, "", m)
        sub(/^.*[.]/, "", m)
        if (gs != 0 && i >= gs && i <= ge) {
            if (WAITFN == "") WAITFN = m
            else if (WAITFN != m) violate(i, GATE " awaits more than one " SIGNAL " method; J18 cannot tell which one is the gate's wait")
        }
    }
    if (WAITFN == "") {
        scope_violate(GATE " no longer awaits " SIGNAL "; the gate would release work immediately")
    } else {
        for (i = 1; i <= N; i++) {
            if (BLANK[i] !~ (SIGNAL "[ \t]*[.]([A-Za-z_][A-Za-z0-9_]*[ \t]*[.][ \t]*)*" WAITFN "[ \t]*[(]")) continue
            if (gs != 0 && i >= gs && i <= ge) continue
            t = type_of(i)
            if (t == SIGNAL) continue
            violate(i, "open-coded " SIGNAL "." WAITFN "() outside " GATE "; every agent-originated network start must go through the one gate")
        }
    }

    # 2. Gate handles: the seam type plus every identifier declared with it.
    GATEALT = GATE
    for (i = 1; i <= N; i++) {
        if (!match(BLANK[i], "[A-Za-z_][A-Za-z0-9_]*[ \t]*:[ \t]*" GATE "([^A-Za-z0-9_]|$)")) continue
        t = substr(BLANK[i], RSTART, RLENGTH)
        sub(/[ \t]*:.*$/, "", t)
        if (t == "" || t == GATE) continue
        GATEALT = alt_add(GATEALT, t)
    }

    # 3. Gate regions.
    RUNRE = "(^|[^A-Za-z0-9_])(" GATEALT ")([ \t]*[.][ \t]*[A-Za-z_][A-Za-z0-9_]*)*[ \t]*[.][ \t]*" GATEFN "[ \t]*[({]"
    NREG = 0
    for (i = 1; i <= N; i++) {
        if (BLANK[i] !~ RUNRE) continue
        if (!match(BLANK[i], "[.][ \t]*" GATEFN "[ \t]*[{(]")) continue
        p = RSTART + RLENGTH - 1
        bp = index(substr(BLANK[i], p), "{")
        j = i
        if (bp > 0) {
            bp = p + bp - 1
        } else {
            for (j = i + 1; j <= N && FILE[j] == FILE[i]; j++) {
                bp = index(BLANK[j], "{")
                if (bp > 0) break
            }
            if (bp == 0) {
                violate(i, "gate call has no closure body the scanner can bound; J18 cannot tell what is gated")
                continue
            }
        }
        e = brace_end(j, bp)
        if (e == 0) {
            violate(i, "gate closure is unbalanced; J18 cannot tell what is gated")
            continue
        }
        NREG++
        REGSTART[NREG] = i
        REGBRACE[NREG] = j
        REGPOS[NREG] = bp
        REGEND[NREG] = e
    }

    if (NREG == 0) {
        scope_violate("no " GATE "." GATEFN " region in the agent target; nothing defers agent-originated external network work behind " SIGNAL)
    }

    # 4. Inventory: what each gate region actually guards.
    for (r = 1; r <= NREG; r++) {
        covered = 0
        for (i = REGBRACE[r]; i <= REGEND[r]; i++) {
            line = (i == REGBRACE[r]) ? substr(BLANK[i], REGPOS[r]) : BLANK[i]
            if (line ~ URL_RE) covered = 1
            split("", cs)
            m = callees(line, cs)
            for (j = 1; j <= m; j++) {
                c = cs[j]
                if (c == GATEFN) continue
                score = doc_score(c)
                if (score >= 2 && reaches_network(c, MAXDEPTH)) {
                    INV[c] = 1
                    covered = 1
                } else if (score < 2 && direct_url(c)) {
                    violate(i, "gated call to " c "() starts a URLSession request but names no work item from the invariant's enumeration (" tokens "); AGENTS.md's inventory and the code have diverged")
                }
            }
        }
        if (!covered) {
            violate(REGSTART[r], "this " GATE "." GATEFN " region guards no external network start the invariant enumerates (" tokens "); the gate lost its subject or the work moved out from under it")
        }
    }

    # 5. Closure: every other call site of an inventoried entry must be gated.
    rounds = 0
    changed = 1
    while (changed && rounds < 8) {
        changed = 0
        rounds++
        for (c in INV) {
            if (c in CLOSED) continue
            CLOSED[c] = 1
            for (i = 1; i <= N; i++) {
                if (BLANK[i] !~ ("(^|[^A-Za-z0-9_])" c "[ \t]*[(]")) continue
                if (BLANK[i] ~ ("(^|[^A-Za-z0-9_])func[ \t]+" c "[ \t]*[(]")) continue
                if (in_gate(i)) continue
                d = enclosing_def(i)
                if (d != 0 && (DNAME[d] in INV)) continue
                if (d != 0 && is_delegating_wrapper(d, c)) {
                    if (!(DNAME[d] in INV)) {
                        INV[DNAME[d]] = 1
                        WRAPPED[DNAME[d]] = c
                        changed = 1
                    }
                    continue
                }
                violate(i, "ungated call to " c "(); agent-originated external network work must start inside a " GATE "." GATEFN " region")
            }
        }
    }

    # 6. The release paths stay wired. Every method the signal exposes other than
    #    the one the gate awaits exists to release it, so each needs a caller
    #    outside the signal. Otherwise gated work hangs for the agent's life.
    if (!(SIGNAL in TYPEDECL)) {
        scope_violate(SIGNAL " is no longer declared in the agent target; its release paths cannot be checked")
    } else {
        ss = TYPEDECL[SIGNAL]
        sb = index(BLANK[ss], "{")
        se = (sb > 0) ? brace_end(ss, sb) : 0
        if (se == 0) {
            scope_violate(SIGNAL "'s declaration is unbalanced; its release paths cannot be checked")
        } else {
            nrel = 0
            for (d = 1; d <= ND; d++) {
                if (DSTART[d] <= ss || DSTART[d] > se) continue
                if (BLANK[DSTART[d]] ~ /(^|[^A-Za-z0-9_])private[ \t]/) continue
                if (DNAME[d] == WAITFN || DNAME[d] == "init") continue
                nrel++
                RELNAME[nrel] = DNAME[d]
                RELAT[nrel] = DSTART[d]
            }
            if (nrel == 0) {
                violate(ss, SIGNAL " exposes no release method besides " WAITFN "(); gated work would never be released")
            }
            for (k = 1; k <= nrel; k++) {
                found = 0
                for (i = 1; i <= N; i++) {
                    if (i >= ss && i <= se) continue
                    if (BLANK[i] ~ ("[.][ \t]*" RELNAME[k] "[ \t]*[(]")) { found = 1; break }
                }
                if (!found) {
                    violate(RELAT[k], SIGNAL "." RELNAME[k] "() has no caller outside the signal; one of the invariant's release paths is not wired")
                }
            }
        }
    }

    dump()
    emit()
}

function dump(   c, r) {
    if (inventory_out == "") return
    printf("J18 gate seam: %s.%s, awaiting %s.%s()\n", GATE, GATEFN, SIGNAL, WAITFN) > inventory_out
    printf("J18 gate handles: %s\n", GATEALT) > inventory_out
    printf("J18 documented enumeration: %s\n", tokens) > inventory_out
    for (r = 1; r <= NREG; r++) {
        printf("J18 gate region: %s:%d-%d\n", FILE[REGSTART[r]], LNO[REGSTART[r]], LNO[REGEND[r]]) > inventory_out
    }
    for (c in INV) {
        if (c in WRAPPED) {
            printf("J18 inventory: %s (single-statement wrapper delegating to %s)\n", c, WRAPPED[c]) > inventory_out
        } else {
            printf("J18 inventory: %s (%d documented words, reaches an external-network primitive)\n", c, doc_score(c)) > inventory_out
        }
    }
    close(inventory_out)
}

function emit(   i, k, n, parts) {
    for (k = 1; k <= NSCOPE; k++) {
        printf("%s\t%d\t%s\n", scope, 0, SCOPEMSG[k])
    }
    for (i = 1; i <= N; i++) {
        if (!(i in VMSG)) continue
        n = split(VMSG[i], parts, SEP)
        for (k = 1; k <= n; k++) {
            printf("%s\t%d\t%s\n", FILE[i], LNO[i], parts[k])
        }
    }
}

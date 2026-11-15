# J21, Rust side: the two halves of the FFI contract that live in the crate.
#
#   1. every `#[no_mangle] extern "C"` export catches panics and returns an
#      appropriate sentinel (`0` / `-1` for integers, NULL for pointers, nothing
#      for `void`)
#   2. every `CString::into_raw` hand-off is owned by a pointer-returning export
#      that names its matching `dns_*_free_*` reclaimer, and only that reclaimer
#      calls `CString::from_raw`
#
# Both halves share one export scanner, which is why they live in one file.
#
# Exports are DISCOVERED by parsing the source. A hardcoded inventory (or an
# expected export count) would break on the next legitimate export and get
# disabled, which leaves the invariant unprotected.
#
# Each export body is flattened into one string: comments are stripped and string
# literals are blanked (length-preserving, so offsets stay valid in the original
# text) before any paren/brace counting. The panic-recovery form is then read off
# the method chain applied to the `catch_unwind(..)` expression itself, so an
# `unwrap_or` belonging to unrelated arithmetic, such as
# `c_int::try_from(n).unwrap_or(c_int::MAX)` inside `dns_snapshot_cache`, is
# never mistaken for the sentinel.
#
# Accepted guard shapes:
#   catch_ffi_panic(..)                  int-returning exports; the helper's own
#                                        sentinel is validated separately
#   catch_unwind(..).unwrap_or(S)        S must be the sentinel for the return
#   catch_unwind(..).unwrap_or_else(..)  closure tail must be the sentinel
#   let r = catch_unwind(..); match r { .. Err(_) => .. }   arm tail is the sentinel
#   let _ = catch_unwind(..)[.map_err(..)]                  void exports only
#   a body that is a single call to another guarded export in this file. No
#     export uses this shape today. It stays accepted so a wrapper export does
#     not need a guard of its own.
#
# Any shape outside that set is reported as unrecognised rather than accepted, so
# a new idiom has to be taught to the lint instead of slipping past it.
#
# Only the panic-recovery expression is judged against `0` / `-1` / NULL. Status
# codes returned from inside the guarded closure, such as `dns_snapshot_cache`'s
# `SNAPSHOT_TIMED_OUT` (-2), are the export's own protocol and out of scope.
#
# `#[cfg(test)]` modules exempt only free-standing `into_raw` / `CString::from_raw`
# in the CString half, since a test may juggle raw pointers on its own. An occurrence
# inside an export body is judged wherever that export sits, so appending an
# export below a test module cannot smuggle a hand-off past the rule.
#
# Input variables:
#   srcdir       path reported for crate-wide (END) findings
#   inventory_out  when set, receives the discovered export table
#   pairs_out    when set, receives "<producer>\t<free fn>" for the Swift-side rule
#
# Output: "<file>\t<lineno>\t<message>" per violation.

BEGIN {
    state = "IDLE"
    exports = 0
    helper_seen = 0
    helper_used = 0
    n_void = 0
    n_int = 0
    n_ptr = 0
}

function viol(file, lineno, msg) {
    printf("%s\t%d\t%s\n", file, lineno, msg)
}

# Index of the closer matching the opener at position p, or 0.
function span_close(s, p, opener, closer,   i, n, c, d) {
    n = length(s)
    d = 0
    for (i = p; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == opener) {
            d++
        } else if (c == closer) {
            d--
            if (d == 0) return i
        }
    }
    return 0
}

# Trailing expression of a statement sequence: the text after the last
# depth-zero ";". Split positions come from the blanked form, so a ";" inside a
# string literal or a nested call never splits.
function last_stmt(raw, blank,   i, n, c, d, pos) {
    n = length(blank)
    d = 0
    pos = 0
    for (i = 1; i <= n; i++) {
        c = substr(blank, i, 1)
        if (c == "(" || c == "{" || c == "[") {
            d++
        } else if (c == ")" || c == "}" || c == "]") {
            d--
        } else if (c == ";" && d == 0) {
            pos = i
        }
    }
    return il_trim(substr(raw, pos + 1))
}

# Trailing expression of a closure argument such as `|_| { log!(..); 0 }`.
function closure_tail(raw, blank,   p, q, e, br, bb) {
    p = index(blank, "|")
    if (p == 0) return "@unparsed"
    q = index(substr(blank, p + 1), "|")
    if (q == 0) return "@unparsed"
    q = p + q
    br = substr(raw, q + 1)
    bb = substr(blank, q + 1)
    while (substr(bb, 1, 1) == " ") {
        br = substr(br, 2)
        bb = substr(bb, 2)
    }
    if (substr(bb, 1, 1) == "{") {
        e = span_close(bb, 1, "{", "}")
        if (e == 0) return "@unparsed"
        br = substr(br, 2, e - 2)
        bb = substr(bb, 2, e - 2)
    }
    return last_stmt(br, bb)
}

# Nesting depth at position `at`, counted from `from`.
function span_depth(s, from, at,   i, c, d) {
    d = 0
    for (i = from; i < at; i++) {
        c = substr(s, i, 1)
        if (c == "(" || c == "{" || c == "[") d++
        else if (c == ")" || c == "}" || c == "]") d--
    }
    return d
}

# Trailing expression of the `Err(..) =>` arm of `match <bound> { .. }`.
function err_arm_tail(raw, blank, bound,   p, e, q, ar, ab) {
    if (!match(blank, "match[ ]+" bound "[ ]*[{]")) return "@nomatch"
    p = RSTART + RLENGTH - 1
    e = span_close(blank, p, "{", "}")
    if (e == 0) return "@unparsed"
    ar = substr(raw, p + 1, e - p - 1)
    ab = substr(blank, p + 1, e - p - 1)
    if (!match(ab, /Err[(][^)]*[)][ ]*=>/)) return "@noerr"
    q = RSTART + RLENGTH
    while (substr(ab, q, 1) == " ") q++
    if (substr(ab, q, 1) == "{") {
        e = span_close(ab, q, "{", "}")
        if (e == 0) return "@unparsed"
        return last_stmt(substr(ar, q + 1, e - q - 1), substr(ab, q + 1, e - q - 1))
    }
    e = q
    while (e <= length(ab) && !(substr(ab, e, 1) == "," && span_depth(ab, q, e) == 0)) e++
    return il_trim(substr(ar, q, e - q))
}

# The single statement of a one-statement body, or "" when the body has more.
function single_statement(raw, blank,   i, n, c, d, seg, out, count) {
    n = length(blank)
    d = 0
    seg = ""
    count = 0
    out = ""
    for (i = 1; i <= n; i++) {
        c = substr(blank, i, 1)
        if (c == "(" || c == "{" || c == "[") d++
        else if (c == ")" || c == "}" || c == "]") d--
        if (c == ";" && d == 0) {
            if (il_trim(seg) != "") {
                count++
                out = il_trim(seg)
            }
            seg = ""
            continue
        }
        seg = seg substr(raw, i, 1)
    }
    if (il_trim(seg) != "") {
        count++
        out = il_trim(seg)
    }
    return (count == 1) ? out : ""
}

function ret_kind(ret) {
    if (ret == "") return "void"
    if (ret ~ /^[*]/) return "ptr"
    if (ret ~ /^(c_int|c_uint|c_long|c_ulong|c_short|c_ushort|c_char|i8|i16|i32|i64|isize|u8|u16|u32|u64|usize)$/) return "int"
    return "unknown"
}

function sentinel_ok(kind, value) {
    if (kind == "int") return (value == "0" || value == "-1")
    if (kind == "ptr") return (value ~ /^((std|core)::)?(ptr::)?null_mut[(][)]$/)
    return 0
}

# Parses the accumulated signature text, setting G_name and G_ret.
function parse_sig(sig,   i, n, c, d, arrow, head) {
    G_name = ""
    G_ret = ""
    head = sig
    sub(/[{].*$/, "", head)
    if (match(head, /extern[ ]+"C"[ ]+fn[ ]+[A-Za-z0-9_]+/) ||
        match(head, /(^|[^A-Za-z0-9_])fn[ ]+[A-Za-z0-9_]+/)) {
        G_name = substr(head, RSTART, RLENGTH)
        sub(/^.*fn[ ]+/, "", G_name)
    }
    # Return type is the text after the last depth-zero "->", so a function
    # pointer parameter carrying its own "->" cannot be misread.
    n = length(head)
    d = 0
    arrow = 0
    for (i = 1; i <= n; i++) {
        c = substr(head, i, 1)
        if (c == "-" && substr(head, i + 1, 1) == ">") {
            if (d == 0) arrow = i + 2
            i++
            continue
        }
        if (c == "(" || c == "[") d++
        else if (c == ")" || c == "]") d--
    }
    if (arrow > 0) G_ret = il_trim(substr(head, arrow))
}

function analyze(file, lineno, name, ret, raw, blank, tally,
                 kind, inner_raw, inner_blank, gi, ci, open, endp, pre, bound,
                 discarded, k, m, op, cp, lastm, arg_raw, arg_blank, value, stmt,
                 target, e)
{
    kind = ret_kind(ret)
    if (tally) {
        if (inventory_out != "") {
            printf("  %-40s %s\n", name, (ret == "" ? "void" : ret)) > inventory_out
        }
        if (kind == "void") n_void++
        else if (kind == "int") n_int++
        else if (kind == "ptr") n_ptr++
    }

    if (kind == "unknown") {
        viol(file, lineno, name ": unsupported FFI return type `" ret \
            "` — teach the J21 lint its sentinel before landing this export")
        return
    }

    gi = index(blank, "catch_ffi_panic(")
    ci = index(blank, "catch_unwind(")

    if (gi == 0 && ci == 0) {
        # A body that is a single call to another export is guarded by that
        # export. Resolved in END, because the target may appear later.
        e = span_close(blank, 1, "{", "}")
        if (e == 0) e = length(blank) + 1
        inner_raw = substr(raw, 2, e - 2)
        inner_blank = substr(blank, 2, e - 2)
        stmt = single_statement(inner_raw, inner_blank)
        if (stmt != "" && match(stmt, /(^|[^A-Za-z0-9_])dns_[A-Za-z0-9_]+[ ]*[(]/)) {
            target = substr(stmt, RSTART, RLENGTH)
            sub(/^[^A-Za-z0-9_]*/, "", target)
            sub(/[ ]*[(]$/, "", target)
            n_deleg++
            DELEG_NAME[n_deleg] = name
            DELEG_TARGET[n_deleg] = target
            DELEG_FILE[n_deleg] = file
            DELEG_LINE[n_deleg] = lineno
            return
        }
        viol(file, lineno, name ": no panic guard — the body neither calls " \
            "catch_unwind/catch_ffi_panic nor delegates to a guarded export")
        return
    }

    if (gi != 0 && ci == 0) {
        helper_used = 1
        GUARDED[name] = 1
        if (kind != "int") {
            viol(file, lineno, name ": catch_ffi_panic returns c_int but this " \
                "export returns `" (ret == "" ? "void" : ret) "`")
        }
        return
    }

    open = ci + length("catch_unwind(") - 1
    endp = span_close(blank, open, "(", ")")
    if (endp == 0) {
        viol(file, lineno, name ": unbalanced catch_unwind(..) — the J21 lint cannot verify its sentinel")
        return
    }
    GUARDED[name] = 1

    # `catch_unwind` may be called through any path prefix, so the binding is
    # matched with the qualifier that precedes it. Without this, the fully
    # qualified `let r = std::panic::catch_unwind(..)` form reads as unbound and a
    # correctly guarded export is reported for a sentinel the lint failed to find.
    pre = substr(raw, 1, ci - 1)
    discarded = (pre ~ /let[ ]+_[ ]*=[ ]*([A-Za-z0-9_]+::)*$/)
    bound = ""
    if (!discarded && match(pre, /let[ ]+[A-Za-z0-9_]+[ ]*=[ ]*([A-Za-z0-9_]+::)*$/)) {
        bound = substr(pre, RSTART, RLENGTH)
        sub(/^let[ ]+/, "", bound)
        sub(/[ ]*=.*$/, "", bound)
    }

    # Walk the method chain applied to the catch_unwind expression.
    k = endp + 1
    lastm = ""
    arg_raw = ""
    arg_blank = ""
    while (1) {
        while (substr(blank, k, 1) == " ") k++
        if (substr(blank, k, 1) != ".") break
        k++
        if (!match(substr(blank, k), /^[A-Za-z0-9_]+[(]/)) break
        m = substr(blank, k, RLENGTH - 1)
        op = k + RLENGTH - 1
        cp = span_close(blank, op, "(", ")")
        if (cp == 0) break
        lastm = m
        arg_raw = substr(raw, op + 1, cp - op - 1)
        arg_blank = substr(blank, op + 1, cp - op - 1)
        k = cp + 1
    }

    if (lastm == "unwrap" || lastm == "expect") {
        viol(file, lineno, name ": catch_unwind(..)." lastm \
            "(..) re-raises the panic instead of returning a sentinel")
        return
    }

    # A void export has nothing to return; discarding or logging the Err is the
    # whole contract, and `unwrap`/`expect` was already rejected above.
    if (kind == "void") return

    value = "@none"
    if (lastm == "unwrap_or") {
        value = il_trim(arg_raw)
    } else if (lastm == "unwrap_or_else") {
        value = closure_tail(arg_raw, arg_blank)
    } else if (lastm == "" && bound != "") {
        value = err_arm_tail(substr(raw, endp + 1), substr(blank, endp + 1), bound)
    } else if (lastm == "map_err" || (lastm == "" && discarded)) {
        viol(file, lineno, name ": the catch_unwind result is discarded, so a " \
            "panic returns no sentinel for `" ret "`")
        return
    }

    if (value ~ /^@/) {
        viol(file, lineno, name ": unrecognised panic-recovery form" \
            (lastm == "" ? "" : " (." lastm ")") \
            " — the J21 lint cannot read its sentinel")
        return
    }
    if (!sentinel_ok(kind, value)) {
        viol(file, lineno, name ": panic path yields `" value "`, not a " \
            (kind == "ptr" ? "NULL pointer" : "`0` / `-1`") " sentinel")
    }
}

FNR == 1 {
    state = "IDLE"
    is_helper = 0
    doc = ""
    cfgtest_pending = 0
}

# Ownership hand-offs are buffered with their line, then matched against the
# export ranges in END. Buffering avoids coupling this scan to the state machine
# below, which consumes lines with `next`.
{
    probe = il_decomment($0)
    if (probe ~ /(^|[^A-Za-z0-9_])CString::from_raw[ ]*[(]/) {
        n_from++
        FROM_FILE[n_from] = FILENAME
        FROM_LINE[n_from] = FNR
    } else if (probe ~ /[.]into_raw[ ]*[(][ ]*[)]/) {
        n_into++
        INTO_FILE[n_into] = FILENAME
        INTO_LINE[n_into] = FNR
    }

    # First `#[cfg(test)] mod ..` in a file marks where its test code begins.
    if (cfgtest_pending) {
        if (probe ~ /^[ \t]*$/) {
            # keep waiting
        } else {
            if (probe ~ /^[ \t]*(pub[ ]+)?mod[ ]+/ && !(FILENAME in TEST_START)) {
                TEST_START[FILENAME] = FNR
            }
            cfgtest_pending = 0
        }
    } else if ($0 ~ /^[ \t]*#\[cfg\(test\)\]/) {
        cfgtest_pending = 1
    }
}

{
    if (state == "IDLE") {
        if ($0 ~ /^[ \t]*\/\/\//) {
            doc = doc " " $0
            next
        }
        if ($0 ~ /^[ \t]*#\[no_mangle\]/) {
            state = "SIG"
            sig = ""
            sig_line = FNR
            is_helper = 0
            exp_doc = doc
            doc = ""
            next
        }
        # Attributes between the doc block and `#[no_mangle]` keep the block.
        if (!($0 ~ /^[ \t]*#\[/)) doc = ""
        # The int-sentinel helper every `catch_ffi_panic` caller depends on. Not
        # an export, so it is validated but never counted in the inventory.
        if ($0 ~ /(^|[^A-Za-z0-9_])fn[ ]+catch_ffi_panic[ ]*[(]/) {
            state = "SIG"
            sig = ""
            sig_line = FNR
            is_helper = 1
            helper_seen = 1
        } else {
            next
        }
    }

    il_guard_raw($0, FILENAME, FNR)
    code = il_decomment($0)
    counted = il_blank_strings(code)

    if (state == "SIG") {
        o = index(counted, "{")
        if (o == 0) {
            sig = sig " " code
            next
        }
        parse_sig(sig " " substr(code, 1, o - 1) " {")
        exp_name = G_name
        exp_ret = G_ret
        exp_file = FILENAME
        exp_line = sig_line
        body_raw = substr(code, o)
        body_blank = substr(counted, o)
        depth = il_delta(body_blank, "{", "}")
        state = "BODY"
        if (depth <= 0) finish_export()
        next
    }

    if (state == "BODY") {
        body_raw = body_raw " " code
        body_blank = body_blank " " counted
        depth += il_delta(counted, "{", "}")
        if (depth <= 0) finish_export()
        next
    }
}

# The `catch_ffi_panic` helper runs through the same machinery so a wrong
# sentinel there is caught under its own name, but it is not an export and never
# enters the inventory tally.
function finish_export() {
    if (!is_helper) {
        exports++
        EXP_NAME[exports] = exp_name
        EXP_RET[exports] = exp_ret
        EXP_FILE[exports] = exp_file
        EXP_LINE[exports] = exp_line
        EXP_END[exports] = FNR
        EXP_DOC[exports] = exp_doc
        EXP_INDEX[exp_name] = exports
    }
    analyze(exp_file, exp_line, exp_name, exp_ret, body_raw, body_blank, !is_helper)
    state = "IDLE"
}

# Index of the export whose body encloses <file>:<line>, or 0.
function owner_of(file, lineno,   i) {
    for (i = 1; i <= exports; i++) {
        if (EXP_FILE[i] == file && lineno >= EXP_LINE[i] && lineno <= EXP_END[i]) return i
    }
    return 0
}

function in_test_code(file, lineno) {
    return ((file in TEST_START) && lineno >= TEST_START[file])
}

END {
    if (exports == 0) {
        printf("%s\t0\t%s\n", srcdir,
            "no `#[no_mangle] extern \"C\"` export found — the J21 export scanner no longer matches the crate")
    }
    for (i = 1; i <= n_deleg; i++) {
        if (!(DELEG_TARGET[i] in GUARDED)) {
            viol(DELEG_FILE[i], DELEG_LINE[i], DELEG_NAME[i] \
                ": delegates to `" DELEG_TARGET[i] "`, which is not a panic-guarded export")
        }
    }
    if (helper_used && !helper_seen) {
        printf("%s\t0\t%s\n", srcdir,
            "exports call catch_ffi_panic but its definition was not found; its sentinel is unverified")
    }

    # --- CString ownership -------------------------------------------------
    # Producers: every `into_raw` hand-off belongs to a pointer-returning export.
    #
    # An occurrence inside an export body is always judged, wherever the export
    # sits in the file. Only free-standing occurrences get the `#[cfg(test)]`
    # exemption, so a test helper juggling raw pointers stays quiet while a real
    # export can never hide behind a test module above it.
    for (i = 1; i <= n_into; i++) {
        o = owner_of(INTO_FILE[i], INTO_LINE[i])
        if (o == 0) {
            if (in_test_code(INTO_FILE[i], INTO_LINE[i])) continue
            viol(INTO_FILE[i], INTO_LINE[i],
                "into_raw() hands ownership across the FFI boundary from outside any #[no_mangle] export")
            continue
        }
        if (ret_kind(EXP_RET[o]) != "ptr") {
            viol(INTO_FILE[i], INTO_LINE[i], EXP_NAME[o] \
                ": into_raw() leaks an owned allocation from an export returning `" \
                (EXP_RET[o] == "" ? "void" : EXP_RET[o]) "`")
            continue
        }
        PRODUCER[o] = 1
        n_producer++
    }

    # Reclaimers: `CString::from_raw` is the matching free function's alone.
    for (i = 1; i <= n_from; i++) {
        o = owner_of(FROM_FILE[i], FROM_LINE[i])
        if (o == 0) {
            if (in_test_code(FROM_FILE[i], FROM_LINE[i])) continue
            viol(FROM_FILE[i], FROM_LINE[i],
                "CString::from_raw outside any #[no_mangle] export; a Rust-owned C string may be reclaimed only by its dns_*_free_* export")
            continue
        }
        if (EXP_NAME[o] !~ /^dns_[A-Za-z0-9_]*_free_/) {
            viol(FROM_FILE[i], FROM_LINE[i], EXP_NAME[o] \
                ": reclaims a C string but is not a dns_*_free_* export")
            continue
        }
        RECLAIMS[EXP_NAME[o]] = 1
    }

    # A dns_*_free_* export that frees nothing is a contract hole.
    for (i = 1; i <= exports; i++) {
        if (EXP_NAME[i] ~ /^dns_[A-Za-z0-9_]*_free_/ && !(EXP_NAME[i] in RECLAIMS)) {
            viol(EXP_FILE[i], EXP_LINE[i], EXP_NAME[i] \
                ": named as a free function but never calls CString::from_raw")
        }
    }

    # Each producer must name its reclaimer in its own doc comment. The mapping is
    # declared rather than guessed from naming, so the Swift-side rule has an
    # authoritative pair to check the `defer` against.
    for (i = 1; i <= exports; i++) {
        if (!(i in PRODUCER)) continue
        if (!match(EXP_DOC[i], /dns_[A-Za-z0-9_]*_free_[A-Za-z0-9_]+/)) {
            viol(EXP_FILE[i], EXP_LINE[i], EXP_NAME[i] \
                ": doc comment does not name the dns_*_free_* function that reclaims its result")
            continue
        }
        freefn = substr(EXP_DOC[i], RSTART, RLENGTH)
        if (!(freefn in EXP_INDEX)) {
            viol(EXP_FILE[i], EXP_LINE[i], EXP_NAME[i] \
                ": doc comment points at `" freefn "`, which is not an exported function")
            continue
        }
        if (pairs_out != "") printf("%s\t%s\n", EXP_NAME[i], freefn) > pairs_out
    }

    # Positive anchor: the rule must not pass because its subject disappeared.
    if (n_producer == 0) {
        printf("%s\t0\t%s\n", srcdir,
            "no CString::into_raw hand-off found in any pointer-returning export — the J21 ownership rule has lost its subject")
    }

    if (inventory_out != "") {
        printf("  %d exports: %d int, %d pointer, %d void\n",
            exports, n_int, n_ptr, n_void) > inventory_out
    }
}

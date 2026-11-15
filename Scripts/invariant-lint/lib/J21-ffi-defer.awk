# J21, Swift side: a Rust-owned C string must be released by its matching
# `dns_*_free_*` function, and the release must be a `defer` so an early return
# on the error paths between the call and the decode cannot leak it.
#
# The Rust side hands this rule an authoritative (producer, free fn) pair. Swift
# reaches both through `dlsym`, so the rule works on the bound function-pointer
# properties rather than the C symbol names:
#
#   fnAllowlistList     = sym("dns_allowlist_list")        -> pvar
#   fnAllowlistFreeJson = sym("dns_allowlist_free_json")   -> fvar
#
# Any `func` body that uses pvar (other than on its own `sym(..)` binding line)
# must carry a `defer` invoking fvar, or a local bound from fvar such as
# `guard .., let freeJson = fnAllowlistFreeJson else`. Local aliases are resolved
# because the real call site frees through one.
#
# Each locally bound producer result must be passed to that release call.
# Unresolved calls and shadowed aliases fail explicitly rather than guessing.
# Input variables: pvar, pipe-separated fvars, producer, freefn.
# Output: "<lineno>\t<message>" per violation.

BEGIN {
    state = "SCAN"
    call_sites = 0
    pvar_re = "(^|[^A-Za-z0-9_])" pvar "([^A-Za-z0-9_]|$)"
    let_re = "(^|[^A-Za-z0-9_])let[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*"
    defer_re = "(^|[^A-Za-z0-9_])defer[ \t]*[{]"
}

function region_reset(lineno,   key, n, i, parts) {
    fn_line = lineno
    uses_producer = 0
    defers = ""
    for (key in producer_alias) delete producer_alias[key]
    for (key in free_alias) delete free_alias[key]
    for (key in results) delete results[key]
    for (key in declared) delete declared[key]
    producer_alias[pvar] = 1
    n = split(fvars, parts, "|")
    for (i = 1; i <= n; i++) if (parts[i] != "") free_alias[parts[i]] = 1
    producer_calls = 0
    result_count = 0
    ddepth = 0
    unresolved = ""
    unsafe_free = 0
}

function region_end(   ptr, alias, ok) {
    if (uses_producer) {
        call_sites++
        if (unresolved != "") printf("%d\t%s\n", fn_line, unresolved)
        if (producer_calls == 0 || producer_calls != result_count) {
            printf("%d\t%s\n", fn_line,
                "unsupported " producer " call shape: every producer result must have a distinct local let binding")
        }
        for (ptr in results) {
            ok = 0
            for (alias in free_alias) {
                if (defers ~ "(^|[^A-Za-z0-9_.])(self[.])?" alias "[ \t]*[?]?[ \t]*[(][ \t]*" ptr "[ \t]*[)]") ok = 1
            }
            if (!ok) {
                printf("%d\t%s\n", results[ptr],
                    "calls " producer " without a `defer` releasing the result " ptr " through " freefn)
            }
        }
        if (unsafe_free) {
            printf("%d\t%s\n", fn_line,
                "releases the " producer " result with free()/deallocate() instead of " freefn)
        }
    }
    state = "SCAN"
}

function scan_bindings(code,   rest, binding, id, rhs, source, suffix, relevant) {
    rest = code
    while (match(rest, let_re)) {
        binding = substr(rest, RSTART, RLENGTH)
        sub(/^.*let[ \t]+/, "", binding)
        sub(/[ \t]*=.*/, "", binding)
        id = binding
        rhs = substr(rest, RSTART + RLENGTH)
        source = rhs
        sub(/^self[.]/, "", source)
        if (!match(source, /^[A-Za-z_][A-Za-z0-9_]*/)) {
            rest = rhs
            continue
        }
        suffix = il_trim(substr(source, RLENGTH + 1))
        source = substr(source, 1, RLENGTH)
        relevant = (id in producer_alias || id in free_alias || id in results || source in producer_alias || source in free_alias)
        if (relevant && (id in declared || id in producer_alias || id in free_alias || id in results)) {
            unresolved = "unsupported FFI ownership scope: alias is shadowed or reassigned: " id
        }
        declared[id] = 1
        if (source in producer_alias) {
            if (suffix ~ /^[?]?[ \t]*[(]/) {
                results[id] = FNR
                result_count++
            } else if (suffix == "" || suffix ~ /^(,|else([^A-Za-z0-9_]|$)|[;}])/) {
                producer_alias[id] = 1
            } else {
                unresolved = "unsupported producer alias binding: " id
            }
        }
        if (source in free_alias) {
            if (suffix == "" || suffix ~ /^(,|else([^A-Za-z0-9_]|$)|[;}])/) {
                free_alias[id] = 1
            } else {
                unresolved = "unsupported free alias binding: " id
            }
        }
        rest = rhs
    }
}

function scan_defers(code,   rest, o, e, prefix) {
    rest = code
    if (ddepth > 0) {
        e = il_brace_end(rest, 1, ddepth)
        if (e == 0) {
            defers = defers " " rest
            ddepth += il_delta(rest, "{", "}")
            return
        }
        defers = defers " " substr(rest, 1, e)
        rest = substr(rest, e + 1)
        ddepth = 0
    }
    while (match(rest, defer_re)) {
        prefix = substr(rest, RSTART, RLENGTH)
        o = RSTART + index(prefix, "{") - 1
        rest = substr(rest, o)
        e = il_brace_end(rest, 1, 0)
        if (e == 0) {
            defers = defers " " rest
            ddepth = il_delta(rest, "{", "}")
            return
        }
        defers = defers " " substr(rest, 1, e)
        rest = substr(rest, e + 1)
    }
}

function alias_shadowed(code, alias, header,   rest, signature) {
    if (code ~ "(^|[^A-Za-z0-9_.])(let|var)[ \t]+" alias "[ \t]*:") return 1
    if (header && code ~ "(^|[^A-Za-z0-9_.])" alias "[ \t]*:") return 1
    rest = code
    while (match(rest, /[{][^{}]*[ \t]in([^A-Za-z0-9_]|$)/)) {
        signature = substr(rest, RSTART, RLENGTH)
        if (signature ~ "(^|[^A-Za-z0-9_])" alias "([^A-Za-z0-9_]|$)") return 1
        rest = substr(rest, RSTART + RLENGTH)
    }
    return 0
}

function scan_scope_aliases(code, header,   alias) {
    for (alias in producer_alias) {
        if (alias_shadowed(code, alias, header)) unresolved = "unsupported FFI ownership scope: alias is shadowed or reassigned: " alias
    }
    for (alias in free_alias) {
        if (alias_shadowed(code, alias, header)) unresolved = "unsupported FFI ownership scope: alias is shadowed or reassigned: " alias
    }
    for (alias in results) {
        if (alias_shadowed(code, alias, header)) unresolved = "unsupported FFI ownership scope: alias is shadowed or reassigned: " alias
    }
}

function scan_body_line(code,   alias, rest, call_re, assign_re) {
    if (code ~ pvar_re && code !~ /sym[ ]*[(]/) uses_producer = 1
    for (alias in producer_alias) {
        assign_re = "(^|[^A-Za-z0-9_.])(self[.])?" alias "[ \t]*=[^=]"
        if (code ~ assign_re && code !~ /sym[ \t]*[(]/) unresolved = "unsupported FFI ownership scope: alias is shadowed or reassigned: " alias
    }
    for (alias in free_alias) {
        assign_re = "(^|[^A-Za-z0-9_.])(self[.])?" alias "[ \t]*=[^=]"
        if (code ~ assign_re && code !~ /sym[ \t]*[(]/) unresolved = "unsupported FFI ownership scope: alias is shadowed or reassigned: " alias
    }
    scan_bindings(code)
    scan_scope_aliases(code, 0)
    for (alias in producer_alias) {
        rest = code
        call_re = "(^|[^A-Za-z0-9_.])(self[.])?" alias "[ \t]*[?]?[ \t]*[(]"
        while (match(rest, call_re)) {
            producer_calls++
            rest = substr(rest, RSTART + RLENGTH)
        }
    }
    scan_defers(code)
    if (code ~ /(^|[^A-Za-z0-9_])func[ \t]+[A-Za-z0-9_]+/) unresolved = "unsupported FFI ownership scope: nested function scope"
    if (code ~ /(^|[^A-Za-z0-9_])free[ ]*[(]/ || code ~ /[.]deallocate[ ]*[(]/) unsafe_free = 1
}

FNR == 1 {
    state = "SCAN"
}

{
    il_guard_raw($0, FILENAME, FNR)
    code = il_decomment($0)
    counted = il_blank_strings(code)

    if (state == "INBODY") {
        scan_body_line(counted)
        depth += il_delta(counted, "{", "}")
        if (depth <= 0) region_end()
        next
    }

    if (state == "PENDING") {
        scan_scope_aliases(counted, 1)
        o = index(counted, "{")
        if (o == 0) next
        state = "INBODY"
        depth = il_delta(substr(counted, o), "{", "}")
        scan_body_line(substr(counted, o))
        if (depth <= 0) region_end()
        next
    }

    if (counted ~ /(^|[^A-Za-z0-9_])func[ \t]+[A-Za-z0-9_]+/) {
        region_reset(FNR)
        scan_scope_aliases(counted, 1)
        o = index(counted, "{")
        if (o > 0) {
            state = "INBODY"
            depth = il_delta(substr(counted, o), "{", "}")
            scan_body_line(substr(counted, o))
            if (depth <= 0) region_end()
        } else {
            state = "PENDING"
        }
    }
}

END {
    if (call_sites == 0) {
        printf("0\t%s\n",
            "no Swift call site uses " pvar " (bound to " producer \
            ") — the J21 defer rule has lost its anchor")
    }
}

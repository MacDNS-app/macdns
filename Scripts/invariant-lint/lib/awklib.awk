# Shared awk helpers for the invariant lint suite.
#
# The scanners below are Swift/Rust-source-aware only to the degree the rules
# need: line comments are removed so a comment can never trip a rule, and
# string-literal bodies are blanked before brace/paren counting so a brace in a
# string cannot desynchronise region tracking.
#
# Known limits, deliberate:
# - Multi-line string literals (""") are rejected outright (il_guard_raw), so a
#   rule fails loudly instead of mis-counting braces. No Swift source in this
#   repo uses them today.
# - Raw strings (#"..."#) are scanned as ordinary strings. Every raw string in
#   this repo is single-line and brace-free, so counting is unaffected.
# - Block comments (/* */) are not handled; no Swift source in this repo uses
#   them.

# Removes a trailing line comment, leaving string literals intact.
function il_decomment(s,   out, i, c, n, instr, esc, p) {
    # Fast path: without a quote there is no string literal to protect, so the
    # first "//" ends the code. Most source lines take this branch, which keeps
    # the suite cheap enough to run on every `make ci`.
    if (index(s, "\"") == 0) {
        p = index(s, "//")
        return (p == 0) ? s : substr(s, 1, p - 1)
    }
    out = ""
    instr = 0
    esc = 0
    n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (instr) {
            out = out c
            if (esc) {
                esc = 0
            } else if (c == "\\") {
                esc = 1
            } else if (c == "\"") {
                instr = 0
            }
            continue
        }
        if (c == "\"") {
            instr = 1
            out = out c
            continue
        }
        if (c == "/" && substr(s, i + 1, 1) == "/") {
            break
        }
        out = out c
    }
    return out
}

# Replaces string-literal contents with spaces, preserving length so offsets
# taken from the blanked form stay valid in the original.
function il_blank_strings(s,   out, i, c, n, instr, esc) {
    if (index(s, "\"") == 0) return s
    out = ""
    instr = 0
    esc = 0
    n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (instr) {
            out = out " "
            if (esc) {
                esc = 0
            } else if (c == "\\") {
                esc = 1
            } else if (c == "\"") {
                instr = 0
            }
            continue
        }
        if (c == "\"") {
            instr = 1
            out = out " "
            continue
        }
        out = out c
    }
    return out
}

# Net nesting change contributed by one already-blanked line.
# `opener`/`closer` avoid awk's reserved built-in name `close`.
function il_delta(s, opener, closer,   i, c, n, d) {
    n = length(s)
    d = 0
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == opener) {
            d++
        } else if (c == closer) {
            d--
        }
    }
    return d
}

# Finds the closing brace of an already-blanked scope, or 0 if it stays open.
# `nesting` carries an open scope across lines. Otherwise `offset` points at `{`.
function il_brace_end(s, offset, nesting,   i, c) {
    for (i = offset; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == "{") nesting++
        if (c == "}") {
            nesting--
            if (nesting == 0) return i
        }
    }
    return 0
}

function il_guard_raw(s, file, lineno) {
    if (index(s, "\"\"\"") > 0) {
        printf("invariant-lint: %s:%d: multi-line string literal is out of scope for the region scanner\n",
            file, lineno) > "/dev/stderr"
        exit 2
    }
}

function il_trim(s) {
    sub(/^[ \t]+/, "", s)
    sub(/[ \t]+$/, "", s)
    return s
}

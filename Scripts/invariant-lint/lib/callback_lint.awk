# Lints the body of every inline callback closure reached through either
#
#   `call_re`   the closure is an argument of a call, e.g.
#               CFNotificationCenterAddObserver( ... { ... } ... )
#   `assign_re` the closure is assigned to a typed constant, e.g.
#               let cb: SCDynamicStoreCallBack = { ... }
#
# and enforces the "callback may only hand work off" shape:
#
#   allow_re    statements permitted at the callback's own top level
#   deny_re     forbidden in the callback's synchronous body, at any depth
#   require_re  the body must contain at least one match (proof it enqueues)
#   escape_re   opens a closure that runs elsewhere (`.async {`, `Task {`)
#
# Everything nested inside an escape closure is skipped entirely: it executes on
# the target queue, not in the callback, so the callback-body restrictions do not
# apply to it. Synchronous nesting (`if`, `guard`, `defer`) stays under deny_re.
#
# All patterns are POSIX EREs and must avoid backslash escapes, because awk
# expands escapes in -v assignments. Use bracket forms: [(] [)] [.] [{].
#
# Output: "<lineno>\t<message>" per violation. Emits a violation on line 0 when
# no callback body is found at all, because a rule that matches nothing is
# broken rather than satisfied.

BEGIN {
    state = "SCAN"
    bodies = 0
    G_pdepth = 0
}

# Walks s looking for the "{" that opens a closure argument while still inside
# the call's parentheses. Sets G_found (offset in s, 0 if none) and G_closed
# (1 when the argument list ended first).
function il_scan_args(s,   i, c, n) {
    G_found = 0
    G_closed = 0
    n = length(s)
    for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (c == "(") {
            G_pdepth++
            continue
        }
        if (c == ")") {
            G_pdepth--
            if (G_pdepth <= 0) {
                G_closed = 1
                return
            }
            continue
        }
        if (c == "{" && G_pdepth > 0) {
            G_found = i
            return
        }
    }
}

function body_start(code, counted, offset,   body, ending) {
    state = "INBODY"
    bodies++
    body_line = FNR
    in_guard = 0
    saw_require = 0
    escaped_depth = 0
    first_body_line = 1
    body = substr(counted, offset)
    ending = il_brace_end(body, 1, 0)
    if (ending > 0) body = substr(body, 1, ending)
    depth = il_delta(body, "{", "}")
    check_body_line(substr(code, offset, length(body)), body, 0)
    first_body_line = 0
    if (depth <= 0) body_end()
}

function body_end() {
    if (!saw_require) {
        printf("%d\t%s\n", body_line,
            "callback body never hands work off (no match for the required enqueue form)")
    }
    state = "SCAN"
    G_pdepth = 0
}

# Skip only the brace-matched async body, then inspect synchronous suffixes.
function check_body_line(code, counted, level,   ending, tail, b, prefix, trim_count) {
    if (escaped_depth > 0) {
        ending = il_brace_end(counted, 1, escaped_depth)
        if (ending == 0) {
            escaped_depth += il_delta(counted, "{", "}")
            return
        }
        code = substr(code, ending + 1)
        counted = substr(counted, ending + 1)
        level = escaped_base
        escaped_depth = 0
    }
    while (escape_re != "" && match(counted, escape_re)) {
        tail = substr(counted, RSTART)
        b = index(tail, "{")
        if (b == 0) break
        b += RSTART - 1
        prefix = substr(counted, 1, b)
        check_body_segment(substr(code, 1, b), prefix, level == 1 || first_body_line)
        escaped_base = level + il_delta(substr(prefix, 1, b - 1), "{", "}")
        counted = substr(counted, b)
        code = substr(code, b)
        ending = il_brace_end(counted, 1, 0)
        if (ending == 0) {
            escaped_depth = il_delta(counted, "{", "}")
            return
        }
        code = substr(code, ending + 1)
        counted = substr(counted, ending + 1)
        level = escaped_base
        first_body_line = 0
    }
    # A semicolon after an async closure separates another callback statement.
    if (match(counted, /^[ \t]*;[ \t]*/)) {
        trim_count = RLENGTH
        code = substr(code, trim_count + 1)
        counted = substr(counted, trim_count + 1)
    }
    check_body_segment(code, counted, level == 1 || first_body_line)
}

function check_body_segment(code, counted, at_top,   t, rest) {
    if (counted ~ deny_re) {
        printf("%d\t%s\n", FNR, "forbidden in a callback body: " il_trim(code))
        return
    }
    if (counted ~ require_re) saw_require = 1
    if (!at_top) return

    t = il_trim(counted)
    if (first_body_line) {
        # Closure signature line, e.g. "{ _, changedKeys, info in".
        rest = t
        sub(/^\{/, "", rest)
        rest = il_trim(rest)
        if (rest == "" || rest ~ /(^|[^A-Za-z0-9_])in$/) return
        t = rest
    }
    if (t == "") return
    # Pure punctuation: closing braces, parens, brackets, commas.
    if (t ~ /^[]}),;[:space:]]*$/) return
    if (in_guard) {
        if (t ~ /(^|[^A-Za-z0-9_])else([^A-Za-z0-9_]|$)/) in_guard = 0
        return
    }
    if (t ~ /^guard([^A-Za-z0-9_]|$)/) {
        if (!(t ~ /(^|[^A-Za-z0-9_])else([^A-Za-z0-9_]|$)/)) in_guard = 1
        return
    }
    if (t ~ allow_re) return
    printf("%d\t%s\n", FNR, "statement is not an allowed signal/enqueue form: " t)
}

{
    il_guard_raw($0, FILENAME, FNR)
    code = il_decomment($0)
    counted = il_blank_strings(code)

    if (state == "INBODY") {
        prev_depth = depth
        ending = il_brace_end(counted, 1, depth)
        if (ending > 0) {
            code = substr(code, 1, ending)
            counted = substr(counted, 1, ending)
        }
        depth += il_delta(counted, "{", "}")
        check_body_line(code, counted, prev_depth)
        if (depth <= 0) body_end()
        next
    }

    if (state == "INARGS") {
        il_scan_args(counted)
        if (G_found > 0) {
            body_start(code, counted, G_found)
        } else if (G_closed) {
            state = "SCAN"
            G_pdepth = 0
        }
        next
    }

    if (assign_re != "" && $0 ~ assign_re) {
        o = index(counted, "{")
        if (o > 0) {
            body_start(code, counted, o)
            next
        }
    }

    if (call_re != "" && match(counted, call_re)) {
        G_pdepth = 0
        il_scan_args(substr(counted, RSTART))
        if (G_found > 0) {
            body_start(code, counted, RSTART + G_found - 1)
        } else if (!G_closed) {
            state = "INARGS"
        }
        next
    }
}

END {
    if (bodies == 0) {
        printf("0\t%s\n", "no callback body found — the rule's anchor no longer matches this file")
    }
}

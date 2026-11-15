# Pairs every `<flag> = true` with a function-scoped `defer` that clears it.
#
# Input:
#   flags   pipe-separated flag names, discovered from their declarations by the
#           rule module. Never a hardcoded inventory.
#
# Output (tab separated, for report_stream):
#   <file>\t<lineno>\t<message>
# plus a "<assignments> <pairs>" summary written to `stats_out`, so the rule can
# tell "the invariant holds" from "there was nothing to check".
#
# What counts as a pairing:
#   - the `defer` keyword sits at the enclosing function body's OWN top level. A
#     `defer` nested inside a closure runs when the closure returns, which is not
#     the function exit the invariant is about, so it does not count.
#   - the reset may sit anywhere inside that defer's body, including inside a
#     closure it hands to a lock helper. The agent uses
#     `defer { finishLifecycleTransition { flag = false } }`.
#
# Function bodies are found by walking braces from a `func`/`init` header to the
# first `{` that opens a body. Two guards keep a header without a body (a
# protocol requirement) from adopting an unrelated brace far below it: a type
# declaration cancels the pending header, and so does a 20-line gap.
#
# Nested functions get their own frame, so a defer in the outer function does not
# excuse an assignment made inside a nested one.

BEGIN {
    nflags = 0
    n = split(flags, parts, "|")
    for (i = 1; i <= n; i++) {
        if (parts[i] == "") continue
        nflags++
        flag[nflags] = parts[i]
        assign_re[nflags] = "(^|[^A-Za-z0-9_.])(self[.])?" parts[i] "[ \t]*=[ \t]*true([^A-Za-z0-9_]|$)"
        clear_re[nflags] = "(^|[^A-Za-z0-9_.])(self[.])?" parts[i] "[ \t]*=[ \t]*false([^A-Za-z0-9_]|$)"
    }
    depth = 0
    top = 0
    pending = 0
    pending_age = 0
    defer_open = 0
    defer_base = 0
    assignments = 0
    pairs = 0
    FUNC_RE = "(^|[^A-Za-z0-9_])(func[ \t]+[A-Za-z_]|init[ \t]*[(]|deinit[ \t]*[{])"
    TYPE_RE = "(^|[^A-Za-z0-9_])(class|struct|enum|protocol|extension|actor)[ \t]+[A-Za-z_]"
    DEFER_RE = "(^|[^A-Za-z0-9_])defer[ \t]*[{]"
}

function push_frame(base,   i) {
    top++
    frame_base[top] = base
    frame_file[top] = FILENAME
    for (i = 1; i <= nflags; i++) {
        asg[top, i] = 0
        rst[top, i] = 0
    }
}

function pop_frame(   i) {
    for (i = 1; i <= nflags; i++) {
        if (asg[top, i] == 0) continue
        assignments++
        if (rst[top, i]) {
            pairs++
            continue
        }
        printf("%s\t%d\t%s\n", frame_file[top], asg[top, i],
            flag[i] " is set true with no function-scoped `defer { " flag[i] " = false }`; an early return or a thrown error leaves the transition stuck")
    }
    top--
}

FNR == 1 {
    while (top > 0) pop_frame()
    depth = 0
    pending = 0
    defer_open = 0
}

{
    il_guard_raw($0, FILENAME, FNR)
    code = il_decomment($0)
    counted = il_blank_strings(code)
    start_depth = depth

    if (counted ~ FUNC_RE) {
        pending = 1
        pending_age = 0
    } else if (pending) {
        pending_age++
        if (pending_age > 20 || counted ~ TYPE_RE) pending = 0
    }

    if (pending && index(counted, "{") > 0) {
        o = index(counted, "{")
        push_frame(start_depth + il_delta(substr(counted, 1, o), "{", "}"))
        pending = 0
    } else if (top > 0 && !defer_open && match(counted, DEFER_RE)) {
        # The depth is taken at the `defer` keyword, not at the start of its
        # line: `lock.withLock { defer { flag = false } }` starts at the
        # function's top level but the defer inside it does not, and it fires
        # when the closure returns rather than when the function does.
        seg = substr(counted, RSTART, RLENGTH)
        prefix = substr(counted, 1, RSTART + index(seg, "defer") - 2)
        defer_depth = start_depth + il_delta(prefix, "{", "}")
        if (defer_depth == frame_base[top]) {
            defer_open = 1
            defer_base = defer_depth
        }
    }

    for (i = 1; i <= nflags; i++) {
        if (counted ~ assign_re[i]) {
            if (top == 0) {
                printf("%s\t%d\t%s\n", FILENAME, FNR,
                    flag[i] " is set true outside any function body; the lint cannot verify a function-scoped defer for it")
            } else if (asg[top, i] == 0) {
                asg[top, i] = FNR
            }
        }
        if (defer_open && top > 0 && counted ~ clear_re[i]) rst[top, i] = 1
    }

    depth += il_delta(counted, "{", "}")
    if (defer_open && depth <= defer_base) defer_open = 0
    while (top > 0 && depth < frame_base[top]) pop_frame()
}

END {
    while (top > 0) pop_frame()
    if (stats_out != "") printf("%d %d\n", assignments, pairs) > stats_out
}

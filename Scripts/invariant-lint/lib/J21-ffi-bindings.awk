# Finds single-line Swift `property = sym("symbol")` bindings and rejects
# incomplete or unsupported bindings rather than silently skipping them.
# Output: <file> <line> <producer|free|error> <property or diagnostic>, tab-separated.

BEGIN {
    binding_re = "(^|[^A-Za-z0-9_.])(self[.])?[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*sym([ \t]*[(]|[ \t]*$)"
}

{
    il_guard_raw($0, FILENAME, FNR)
    code = il_decomment($0)
    counted = il_blank_strings(code)
    while (match(counted, binding_re)) {
        end = RSTART + RLENGTH
        name = substr(counted, RSTART, RLENGTH)
        sub(/[ \t]*=.*/, "", name)
        sub(/^.*[^A-Za-z0-9_]/, "", name)
        tail = substr(code, end)
        if (substr(counted, end - 1, 1) == "(" && match(tail, /^[ \t]*"[A-Za-z_][A-Za-z0-9_]*"[ \t]*[)]/)) {
            symbol = substr(tail, RSTART, RLENGTH)
            sub(/^[ \t]*"/, "", symbol)
            sub(/".*$/, "", symbol)
            key = FILENAME SUBSEP name
            if (key in symbols && symbols[key] != symbol) ambiguous[key] = 1
            symbols[key] = symbol
            if (symbol == producer || symbol == freefn) {
                files[key] = FILENAME
                lines[key] = FNR
                names[key] = name
                kinds[key] = (symbol == producer ? "producer" : "free")
            }
        } else {
            printf("%s\t%d\terror\tunsupported sym binding for %s: expected property = sym(\"symbol\") on one line\n",
                FILENAME, FNR, name)
        }
        code = substr(code, end)
        counted = substr(counted, end)
    }
}

END {
    for (key in kinds) {
        if (ambiguous[key]) {
            printf("%s\t%d\terror\tunsupported ambiguous sym binding for %s\n",
                files[key], lines[key], names[key])
        } else {
            printf("%s\t%d\t%s\t%s\n", files[key], lines[key], kinds[key], names[key])
        }
    }
}

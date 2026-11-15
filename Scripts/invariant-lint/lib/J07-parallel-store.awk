# Flags parallel-persistence APIs (`store_re`) outside an allowlist of enclosing
# function names (`allowed`, space separated).
#
# The allowlist is keyed on the enclosing function rather than on the line,
# because the permitted call sites read and write a local variable whose name
# carries no marker of its own.
#
# Output: "<file>\t<lineno>\t<code> (in <function>)".

FNR == 1 {
    fn = "<file scope>"
    guard = " " allowed " "
}

{
    il_guard_raw($0, FILENAME, FNR)
    code = il_decomment($0)

    if (match(code, /(^|[^A-Za-z0-9_])func[ ]+[A-Za-z0-9_]+/)) {
        decl = substr(code, RSTART, RLENGTH)
        sub(/^.*func[ ]+/, "", decl)
        fn = decl
    }

    scoped = scoped_function != "" && fn == scoped_function && FILENAME ~ scoped_file
    if (code ~ store_re && index(guard, " " fn " ") == 0 && !scoped) {
        printf("%s\t%d\t%s (in %s)\n", FILENAME, FNR, il_trim(code), fn)
    }
}

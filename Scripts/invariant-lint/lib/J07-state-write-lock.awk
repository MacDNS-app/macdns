# Flags a write whose destination expression names the state file unless the
# write sits inside an open `StateFileLock.withExclusiveLock` region.
#
# `write_re` matches the destination label rather than the write call, because
# the `try data.write(` and `to: PathResolver.stateFile,` halves live on
# separate lines after formatting.
#
# Output: "<file>\t<lineno>\t<code>".

FNR == 1 {
    pending = 0
    inlock = 0
    depth = 0
}

{
    il_guard_raw($0, FILENAME, FNR)
    code = il_decomment($0)
    counted = il_blank_strings(code)

    if (inlock) {
        depth += il_delta(counted, "{", "}")
        if (depth <= 0) inlock = 0
    } else if (pending) {
        o = index(counted, "{")
        if (o > 0) {
            pending = 0
            inlock = 1
            depth = il_delta(substr(counted, o), "{", "}")
            if (depth <= 0) inlock = 0
        }
    }

    if (!inlock && !pending && code ~ /StateFileLock[.]withExclusiveLock/) {
        o = index(counted, "{")
        if (o > 0) {
            inlock = 1
            depth = il_delta(substr(counted, o), "{", "}")
            if (depth <= 0) inlock = 0
        } else {
            pending = 1
        }
    }

    if (code ~ write_re && !inlock) {
        printf("%s\t%d\t%s\n", FILENAME, FNR, il_trim(code))
    }
}

# Prints "<file>\t<lineno>\t<code>" for every line whose comment-stripped form
# matches `re`. Used instead of grep wherever a comment mentioning a banned
# symbol must not count as a violation.
#
# Optional knobs (all POSIX EREs; awk expands backslash escapes in -v
# assignments, so use bracket forms [(] [)] [.] [{] instead of \( \) \. \{ ):
#
#   also        a second pattern the line must ALSO match (logical AND)
#   allow       exempts a line matching it. Narrow allowlist entries live here.
#   skip        exempts a whole file whose path matches it
#   neutralize  blanked before matching, so a superset symbol can be carved out
#               of an otherwise broad pattern

{
    if (skip != "" && FILENAME ~ skip) next
    il_guard_raw($0, FILENAME, FNR)
    code = il_decomment($0)
    if (allow != "" && code ~ allow) next
    probe = code
    if (neutralize != "") gsub(neutralize, "", probe)
    if (probe !~ re) next
    if (also != "" && probe !~ also) next
    printf("%s\t%d\t%s\n", FILENAME, FNR, il_trim(code))
}

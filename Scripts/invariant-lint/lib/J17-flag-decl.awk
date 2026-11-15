# Discovers the lifecycle transition flags J17 protects, from their declarations.
#
# Prints "<file>\t<lineno>\t<name>" for every stored Bool whose name has the
# in-progress shape `is<Verb>ing[Suffix]`: `isStartingServices`,
# `isStoppingServices`, `isRestoringServices`, `isValidating`.
#
# Discovering the set instead of listing it is what keeps the rule alive: a new
# transition guard is linted the moment it is declared, and renaming one does not
# silently drop it from an inventory.
#
# The shape deliberately excludes `is<Preposition><Noun>` mode flags such as
# `isInForwardingMode`, whose gerund is inside a compound noun rather than the
# verb right after `is`. Those describe a state that outlives the function that
# set it, so a defer reset would be wrong, not missing.

{
    code = il_decomment($0)
    if (!match(code, /(^|[^A-Za-z0-9_])var[ \t]+is[A-Z][a-z]+ing([A-Z][A-Za-z]*)?[ \t]*(:[ \t]*Bool|=[ \t]*false)/)) next
    seg = substr(code, RSTART, RLENGTH)
    if (!match(seg, /is[A-Z][a-z]+ing([A-Z][A-Za-z]*)?/)) next
    printf("%s\t%d\t%s\n", FILENAME, FNR, substr(seg, RSTART, RLENGTH))
}

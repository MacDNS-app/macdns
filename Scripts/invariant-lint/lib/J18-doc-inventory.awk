# Extracts J18's inventory of gated work from the invariant bullet itself.
#
# The bullet enumerates the agent-originated external network work in a
# parenthetical: "(initial update check, blocklist scheduler/force refresh)".
# That parenthetical is the inventory, so the rule reads it out of AGENTS.md
# instead of duplicating a name list in the lint. A reworded bullet changes what
# the rule enforces. A bullet that stops enumerating anything makes the rule
# fail loudly rather than silently checking nothing.
#
# Prints the enumeration as space-separated lowercase word tokens, or nothing
# when the bullet carries no parenthetical.

/^## Critical invariants/ { inside = 1; next }
inside && /^## /          { inside = 0 }

inside && !done && index($0, anchor) {
    a = index($0, "(")
    if (a == 0) next
    rest = substr($0, a + 1)
    b = index(rest, ")")
    if (b == 0) next
    inv = substr(rest, 1, b - 1)
    gsub(/[^A-Za-z]+/, " ", inv)
    sub(/^ +/, "", inv)
    sub(/ +$/, "", inv)
    if (inv == "") next
    print tolower(inv)
    done = 1
}

# The clean fixture is a compliant mini-repo: every rule must be green on it.
#
# This is the GREEN half of every red/green pair below. Without it, a rule that
# fails on everything would still look correct in all the violation cases.

begin "baseline"
for rule_id in J07 J08 J09 J10 J11 J12 J13 J14 J15; do
    CASE="baseline $rule_id is green on the compliant fixture"
    expect "$rule_id" ok
done

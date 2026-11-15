#!/bin/sh
# J16: the service lifecycle order:
#   start  ResolverModule.start() -> proxyEnable -> bypassDisable
#   stop   bypassEnable -> proxyDisable -> ResolverModule.stop()
#
# Out of order, the two halves fail in opposite directions: publishing readiness
# before the resolver is up points the provider at a dead listener, and tearing
# the resolver down before bypass is raised drops live queries on the floor.
#
# The agent does not post the four signals inline. It hands an ordered list of
# readiness steps to `applyProxyReadinessActions`, so the order lives in two
# places and both are linted as source order:
#
#   1. MacDNSAgent: startServices() runs ResolverModule.start() before the start
#      readiness actions, and stopAllServices() runs the stop readiness actions
#      before ResolverModule.stop()
#   2. ProxyReadinessLifecyclePolicy: proxyEnable before the bypass probe on
#      start, and the bypass probe before proxyDisable on stop
#
# Sequencing a signal any other way inside those two functions is reported as an
# unrecognised shape rather than passed: a direct `notifyBypassDisable()` or
# `setProxyBypassRequested()` there is an ordering step this rule cannot order.
#
# Deliberately NOT enforced:
#   - runtime delivery order. Darwin notifications are unordered, asynchronous
#     hints (J14); only the source order of the calls is a static property.
#   - the other bypass paths (captive-portal fail-safe, forwarding transitions).
#     They are not service start/stop and are governed by their own invariants.
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J16 service lifecycle order" "Service start:"

AGENT="$REPO_ROOT/Sources/MacDNSAgent/MacDNSAgent.swift"
POLICY="$REPO_ROOT/Sources/MacDNSAgent/Services/ProxyReadinessLifecyclePolicy.swift"
require_file "$AGENT" || rule_end
require_file "$POLICY" || rule_end

J16_REGION="$LINT_TMP.region"
J16_REGION_LINE=0
trap 'rm -f "$LINT_TMP" "$LINT_ERR" "$J16_REGION"' EXIT HUP INT TERM

# j16_region <file> <start-ere> <opener> <closer> Loads a region for the checks
# below. Status 3 means the anchor no longer matches, which is a finding.
j16_region() {
    awk -v start_re="$2" -v opener="$3" -v closer="$4" \
        -f "$AWKLIB" -f "$LINT_DIR/lib/J16-region.awk" "$1" \
        >"$J16_REGION" 2>"$LINT_ERR"
    _jr_status=$?
    case "$_jr_status" in
        0 | 3) : >"$LINT_ERR" ;;
        *) rule_error "region scanner failed" ;;
    esac
    if [ "$_jr_status" -eq 3 ]; then
        report "$1" 0 "region /$2/ not found; the invariant's implementation moved"
        return 1
    fi
    J16_REGION_LINE=$(cut -f1 "$J16_REGION" | sed -n '1p')
    return 0
}

# j16_first <ere> Prints the line number of the first loaded region line whose
# code matches, or nothing when there is none.
j16_first() {
    lint_awk -v re="$1" '
        {
            _tab = index($0, "\t")
            if (substr($0, _tab + 1) ~ re) {
                print substr($0, 1, _tab - 1)
                exit
            }
        }
    ' "$J16_REGION"
    sed -n '1p' "$LINT_TMP"
}

# j16_require <file> <ere> <message>
j16_require() {
    if [ -z "$(j16_first "$2")" ]; then
        report "$1" "$J16_REGION_LINE" "$3"
    fi
}

# j16_order <file> <ere-first> <label-first> <ere-second> <label-second>
# Both steps must be present, and the first must precede the second.
j16_order() {
    _jo_a=$(j16_first "$2")
    _jo_b=$(j16_first "$4")
    if [ -z "$_jo_a" ]; then
        report "$1" "$J16_REGION_LINE" "$3 is missing from this lifecycle path"
    fi
    if [ -z "$_jo_b" ]; then
        report "$1" "$J16_REGION_LINE" "$5 is missing from this lifecycle path"
    fi
    if [ -n "$_jo_a" ] && [ -n "$_jo_b" ] && [ "$_jo_a" -ge "$_jo_b" ]; then
        report "$1" "$_jo_b" "lifecycle order violated: $5 must come after $3"
    fi
}

# j16_deny <file> <ere> <message>
j16_deny() {
    lint_awk -v re="$2" '
        {
            _tab = index($0, "\t")
            _code = substr($0, _tab + 1)
            if (_code ~ re) printf("%s\t%s\n", substr($0, 1, _tab - 1), _code)
        }
    ' "$J16_REGION"
    while IFS="$TAB" read -r _jd_line _jd_code; do
        [ -n "$_jd_line" ] || continue
        report "$1" "$_jd_line" "$3: $(trim "$_jd_code")"
    done <"$LINT_TMP"
}

# A signal posted straight from a lifecycle function bypasses the ordered action
# list, so this rule can no longer place it in the sequence.
INLINE_SIGNAL='notifyProxyEnable[ ]*[(]|notifyProxyDisable[ ]*[(]|notifyBypassEnable[ ]*[(]|notifyBypassDisable[ ]*[(]|setProxyBypassRequested[ ]*[(]'

# 1. Start: the resolver is up before readiness is published.
if j16_region "$AGENT" 'func[ ]+startServices[ ]*[(]' '{' '}'; then
    j16_order "$AGENT" \
        'ResolverModule[.]shared[.]start[ ]*[(]' 'ResolverModule.start()' \
        'ProxyReadinessLifecyclePolicy[.]startActions' 'the start readiness actions (proxyEnable, bypassDisable)'
    j16_require "$AGENT" 'applyProxyReadinessActions[ ]*[(]' \
        "startServices no longer publishes readiness through applyProxyReadinessActions"
    j16_deny "$AGENT" "$INLINE_SIGNAL" \
        "readiness signal posted inline in startServices instead of through the ordered action list"
    j16_deny "$AGENT" 'ResolverModule[.]shared[.]stop[ ]*[(]' \
        "resolver teardown inside the start path skips the bypassEnable/proxyDisable sequence"
fi

# 2. Stop: bypass is raised before the resolver goes away.
if j16_region "$AGENT" 'func[ ]+stopAllServices[ ]*[(]' '{' '}'; then
    j16_order "$AGENT" \
        'ProxyReadinessLifecyclePolicy[.]stopActions' 'the stop readiness actions (bypassEnable, proxyDisable)' \
        'ResolverModule[.]shared[.]stop[ ]*[(]' 'ResolverModule.stop()'
    j16_deny "$AGENT" "$INLINE_SIGNAL" \
        "readiness signal posted inline in stopAllServices instead of through the ordered action list"
    j16_deny "$AGENT" 'ResolverModule[.]shared[.]start[ ]*[(]' \
        "resolver start inside the stop path"
fi

# 3. The interpreter still implements every step it is handed. Without this the
#    ordered lists could keep their shape while the signals they name vanish.
if j16_region "$AGENT" 'func[ ]+applyProxyReadinessActions[ ]*[(]' '{' '}'; then
    j16_require "$AGENT" 'notifyProxyEnable[ ]*[(]' \
        "the readiness interpreter no longer posts proxyEnable"
    j16_require "$AGENT" 'notifyProxyDisable[ ]*[(]' \
        "the readiness interpreter no longer posts proxyDisable"
    j16_require "$AGENT" 'notifyBypassEnable[ ]*[(]' \
        "the readiness interpreter no longer posts bypassEnable"
    j16_require "$AGENT" 'notifyBypassDisable[ ]*[(]' \
        "the readiness interpreter no longer posts bypassDisable"
    j16_require "$AGENT" 'setProxyBypassRequested[ ]*[(]' \
        "the readiness interpreter no longer publishes the resolver's bypass request"
    # Which of the two bypass signals `.wakeBypassProbe` posts is decided by
    # whether the list also requests bypass. That mapping is what makes the
    # per-list order below mean proxyEnable -> bypassDisable / bypassEnable ->
    # proxyDisable, so it is anchored explicitly.
    j16_require "$AGENT" 'contains[ ]*[(][.]setBypassRequested[ ]*[(]true[)][)]' \
        "the bypass probe no longer chooses its signal from the list's bypass request"
fi

# 4. Start list: proxyEnable, then the bypass probe. The probe posts
#    bypassDisable only because the list does not request bypass, hence the
#    deny below.
if j16_region "$POLICY" 'func[ ]+startActions[ ]*[(]' '{' '}'; then
    j16_order "$POLICY" \
        '[.]notifyProxyEnable' 'proxyEnable' \
        '[.]wakeBypassProbe' 'bypassDisable (the bypass probe)'
    j16_deny "$POLICY" '[.]setBypassRequested[ ]*[(]true[)]' \
        "the start list requests bypass, so its probe would post bypassEnable and the resolver would never intercept"
fi

# 5. Stop list: bypass requested, the probe raises bypassEnable, then
#    proxyDisable.
if j16_region "$POLICY" 'stopActions[ ]*:' '[' ']'; then
    j16_order "$POLICY" \
        '[.]setBypassRequested[ ]*[(]true[)]' 'the bypass request' \
        '[.]wakeBypassProbe' 'bypassEnable (the bypass probe)'
    j16_order "$POLICY" \
        '[.]wakeBypassProbe' 'bypassEnable (the bypass probe)' \
        '[.]notifyProxyDisable' 'proxyDisable'
fi

rule_end

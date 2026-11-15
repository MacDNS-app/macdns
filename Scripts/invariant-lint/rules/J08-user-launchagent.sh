#!/bin/sh
# J8: the agent is a user LaunchAgent, not a root LaunchDaemon.
#
# Enforced mechanically as three properties:
#   1. no root-daemon registration, install path, or privileged-helper flow
#   2. nothing binds the privileged DNS port 53
#   3. positive anchor: registration still goes through SMAppService.agent
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J08 user launch agent" "user LaunchAgent, not a root LaunchDaemon"

INSTALLER="$REPO_ROOT/Sources/MacDNS/Services/AgentInstaller.swift"
AGENT_PLIST="$REPO_ROOT/Configuration/app.macdns.agent.plist"
require_file "$INSTALLER" || rule_end
require_file "$AGENT_PLIST" || rule_end

SWIFT=$(swift_files "$REPO_ROOT/Sources")
assert_plain_paths "$SWIFT"
PLISTS=$(find "$REPO_ROOT/Sources" "$REPO_ROOT/Configuration" -type f -name '*.plist' | sort)

# 1. Root-daemon and privileged-helper surfaces.
code_scan "root-daemon or privileged-helper surface in a user LaunchAgent build" \
    'SMAppService[.]daemon|/Library/LaunchDaemons|PrivilegedHelperTools|SMJobBless|AuthorizationCreate|AuthorizationExecuteWithPrivileges|setuid[(]|seteuid[(]' \
    $SWIFT

assert_plain_paths "$PLISTS"
lint_awk '
    /LaunchDaemons|SMPrivilegedExecutables|PrivilegedHelperTools|<key>UserName<|<key>GroupName</ {
        printf("%s\t%d\t%s\n", FILENAME, FNR, $0)
    }
' $PLISTS
report_stream "root-daemon key in a bundled property list"

# 2. Port 53 is the system resolver's; the agent listens on an unprivileged port.
# The pattern deliberately requires a port-shaped context (`port: 53`,
# `sin_port`, `Port(rawValue: 53)`, `htons(53)`) so DNS server IP literals such
# as "2620:119:53::53" are not mistaken for a bind.
code_scan "binds the privileged DNS port 53; a user LaunchAgent cannot" \
    'sin_port[^0-9]*53([^0-9]|$)|[pP]ort[ ]*[:=][ ]*53([^0-9]|$)|Port[(]rawValue:[ ]*53[)]|htons[(]53[)]' \
    $SWIFT

# 3. Positive anchors, so the rule cannot pass because the code vanished.
require_present "$INSTALLER" 'SMAppService[.]agent[(]' \
    "the agent is no longer registered through SMAppService.agent"
require_present "$AGENT_PLIST" '<string>app[.]macdns[.]agent</string>' \
    "the LaunchAgent job label is gone; the agent's registration model changed"

rule_end

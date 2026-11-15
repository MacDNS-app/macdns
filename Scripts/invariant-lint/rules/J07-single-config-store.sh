#!/bin/sh
# J7: `state.json` is the single source of truth for user config.
#
# Enforced mechanically as five properties:
#   1. PathResolver is the only place that names a config file or the support dir
#   2. every write to the state file happens inside StateFileLock
#   3. inside the App target, only the revision-aware store writes the state file
#   4. no parallel persistence store (UserDefaults & friends) holds config
#   5. positive anchors: PathResolver still owns state.json and the App store
#      still writes it under the lock
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J07 single config store" "single source of truth for user config"

PATH_RESOLVER="$REPO_ROOT/Sources/Shared/PathResolver.swift"
APP_STORE="$REPO_ROOT/Sources/MacDNS/Services/RevisionAwareConfigFileStore.swift"

require_file "$PATH_RESOLVER" || rule_end
require_file "$APP_STORE" || rule_end

SWIFT=$(swift_files "$REPO_ROOT/Sources")
APP_SWIFT=$(swift_files "$REPO_ROOT/Sources/MacDNS")
assert_plain_paths "$SWIFT"

STATE_WRITE_RE='to:[ ]*[A-Za-z0-9_.]*stateFile'

# 1. Config file paths and the support directory are PathResolver's alone.
lint_awk -v re='appendingPathComponent[(]"[^"]*[.]json"|Application Support' \
    -v skip='/Sources/Shared/PathResolver[.]swift$' \
    -f "$AWKLIB" -f "$GREP_CODE_AWK" $SWIFT
report_stream "config path built outside PathResolver — a second config location splits state"

# 2. Every state-file write is serialized through StateFileLock.
lint_awk -v write_re="$STATE_WRITE_RE" \
    -f "$AWKLIB" -f "$LINT_DIR/lib/J07-state-write-lock.awk" $SWIFT
report_stream "state-file write outside StateFileLock.withExclusiveLock"

# 3. The App target's file fallback writes the state file from one place only.
lint_awk -v re="$STATE_WRITE_RE" \
    -v skip='/RevisionAwareConfigFileStore[.]swift$' \
    -f "$AWKLIB" -f "$GREP_CODE_AWK" $APP_SWIFT
report_stream "App-side state-file write outside RevisionAwareConfigFileStore"

# 4. No parallel persistence store for configuration.
#
# Allowlist, presentation timestamps only:
#   sendNotificationOnce  AppViewModel's 24h notification cooldown timestamp.
#                         A presentation timestamp, never read back as config.
#   persistedUpdatePromptHistory  UpdatePromptHistory's version + prompt date.
#                                 Scoped to its file, never read back as config.
lint_awk -v store_re='UserDefaults|NSUbiquitousKeyValueStore|AppStorage|CFPreferences[A-Za-z]*[(]|SecItemAdd|NSKeyedArchiver' \
    -v allowed='sendNotificationOnce' \
    -v scoped_file='/Sources/MacDNS/Services/UpdatePromptHistory[.]swift$' \
    -v scoped_function='persistedUpdatePromptHistory' \
    -f "$AWKLIB" -f "$LINT_DIR/lib/J07-parallel-store.awk" $SWIFT
report_stream "parallel persistence store outside the allowlist"

# 5. Positive anchors, so the rule cannot pass because the code vanished.
require_present "$PATH_RESOLVER" 'appendingPathComponent[(]"state[.]json"[)]' \
    "PathResolver no longer defines state.json; checks 1-3 have lost their subject"
require_present "$APP_STORE" 'StateFileLock[.]withExclusiveLock' \
    "the App-side config store no longer takes StateFileLock"

rule_end

#!/bin/sh
# J9: DNS Proxy always returns `true` from `handleNewFlow`, uses BSD sockets and
# `pthread_rwlock`, and keeps Network.framework / SCDynamicStore work off the
# query hot path.
#
# Enforced mechanically as five properties:
#   1. `handleNewFlow` contains no `return false`, and does return true
#   2. `handleNewFlow` touches neither SCDynamicStore nor Network.framework
#   3. the hot-path state manager keeps pthread_rwlock and no other lock type
#   4. no Network.framework symbol anywhere in the DNS Proxy extension
#   5. SCDynamicStore work stays inside the dedicated ConfigurationWorker
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J09 dns proxy hot path" 'always return `true` from `handleNewFlow`'

PROVIDER="$REPO_ROOT/Sources/DNSProxyExtension/DNSProxyProvider.swift"
require_file "$PROVIDER" || rule_end

EXT_SWIFT=$(swift_files "$REPO_ROOT/Sources/DNSProxyExtension")
assert_plain_paths "$EXT_SWIFT"

FLOW_ANCHOR='func handleNewFlow'
STATE_ANCHOR='class ProxyStateManager'
WORKER_ANCHOR='class ConfigurationWorker'

# 1. handleNewFlow always returns true.
scan_region "$PROVIDER" "$FLOW_ANCHOR" 'return[ ]+false' \
    "handleNewFlow must always return true; a false return drops the flow to the system resolver"
require_region_present "$PROVIDER" "$FLOW_ANCHOR" 'return[ ]+true' \
    "handleNewFlow no longer returns true on any path"

# 2. No configd or Network.framework work inside handleNewFlow.
scan_region "$PROVIDER" "$FLOW_ANCHOR" 'SCDynamicStore|NWConnection|NWListener|NWPathMonitor|NWBrowser|NWParameters' \
    "configd / Network.framework work on the flow hot path"

# 3. The hot-path state manager keeps the reader-writer lock.
require_region_present "$PROVIDER" "$STATE_ANCHOR" 'pthread_rwlock_t' \
    "the hot-path state manager no longer uses pthread_rwlock_t"
require_region_present "$PROVIDER" "$STATE_ANCHOR" 'pthread_rwlock_rdlock' \
    "the hot-path state manager no longer takes a read lock"
require_region_present "$PROVIDER" "$STATE_ANCHOR" 'pthread_rwlock_wrlock' \
    "the hot-path state manager no longer takes a write lock"
scan_region "$PROVIDER" "$STATE_ANCHOR" 'NSLock|NSRecursiveLock|os_unfair_lock|DispatchSemaphore|pthread_mutex|[.]sync[ ]*[{]|await ' \
    "lock type changed on the query hot path; readers must never block each other"

# 4. Network.framework stays out of the whole extension.
#
# Allowlist, one entry:
#   NWHostEndpoint  a NetworkExtension type (NEAppProxyFlow endpoints), not
#                   Network.framework. Neutralized before the NW* sweep.
lint_awk -v re='NW[A-Z][A-Za-z]+' -v neutralize='NWHostEndpoint' \
    -f "$AWKLIB" -f "$GREP_CODE_AWK" $EXT_SWIFT
report_stream "Network.framework symbol in the DNS Proxy; the data path is BSD sockets"

# 5. configd access is confined to the dedicated worker.
require_region_present "$PROVIDER" "$WORKER_ANCHOR" 'SCDynamicStoreCreate' \
    "the ConfigurationWorker no longer owns SCDynamicStore access"

rule_end

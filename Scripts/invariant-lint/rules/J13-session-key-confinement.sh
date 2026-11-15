#!/bin/sh
# J13: the HMAC session key is ephemeral and memory-only: never persisted,
# logged, sent to the App, or put in `state.json`.
#
# Enforced mechanically as six properties:
#   1. no session-key identifier anywhere in the App target (UI + view models)
#   2. inside Shared, the key exists only in the proxy-control transport types,
#      never in a Codable state model
#   3. no logging call on a line that names the key
#   4. no persistence call on a line that names the key
#   5. the Rust side keeps the session in proxy_control.rs, with no logging,
#      serde, or filesystem access in that module
#   6. the key's storage is wiping storage in all three processes, and the
#      session is cleared on shutdown as well as on init
set -u

LINT_DIR=$(cd "$(dirname "$0")/.." && pwd)
. "$LINT_DIR/lib/common.sh"

rule_begin "J13 session key confinement" "HMAC session key is ephemeral and memory-only"

SESSION="$REPO_ROOT/Sources/DNSProxyExtension/ProxyControlSession.swift"
AGENT_CLIENT="$REPO_ROOT/Sources/MacDNSAgent/Services/ProxyControlClient.swift"
RUST_CONTROL="$REPO_ROOT/rust-resolver/crates/macdns-resolver/src/proxy_control.rs"
RUST_LIB="$REPO_ROOT/rust-resolver/crates/macdns-resolver/src/lib.rs"
require_file "$SESSION" || rule_end
require_file "$AGENT_CLIENT" || rule_end
require_file "$RUST_CONTROL" || rule_end
require_file "$RUST_LIB" || rule_end

KEY_RE='hmacKey|hmac_key|sessionKey|session_key|symmetricKeyMaterial'

APP_SWIFT=$(swift_files "$REPO_ROOT/Sources/MacDNS")
SHARED_SWIFT=$(swift_files "$REPO_ROOT/Sources/Shared")
ALL_SWIFT=$(swift_files "$REPO_ROOT/Sources")
RUST_OTHER=$(rust_files "$REPO_ROOT/rust-resolver/crates" | grep -v '/proxy_control[.]rs$')
assert_plain_paths "$ALL_SWIFT"
assert_plain_paths "$RUST_OTHER"

# 1. The App never sees the key.
code_scan "session key referenced in the App target; the key must never reach the App" \
    "$KEY_RE" $APP_SWIFT

# 2. Inside Shared the key belongs to the transport types only, never to a model
#    that gets encoded into state.json.
lint_awk -v re="$KEY_RE" \
    -v skip='/Sources/Shared/ProxyControl' \
    -f "$AWKLIB" -f "$GREP_CODE_AWK" $SHARED_SWIFT
report_stream "session key in a Shared type outside the proxy-control transport"

# 3. Never logged.
lint_awk -v re="$KEY_RE" \
    -v also='logger[.]|AgentLogger|os_log|NSLog|print[(]|debugPrint|[.]debug[(]|[.]info[(]|[.]notice[(]|[.]warning[(]|[.]error[(]' \
    -f "$AWKLIB" -f "$GREP_CODE_AWK" $ALL_SWIFT
report_stream "session key on a logging call"

# 4. Never persisted.
lint_awk -v re="$KEY_RE" \
    -v also='[.]write[(]|write[(]to:|UserDefaults|SecItemAdd|SecItemUpdate|Keychain|FileManager|[.]synchronize[(]' \
    -f "$AWKLIB" -f "$GREP_CODE_AWK" $ALL_SWIFT
report_stream "session key on a persistence call"

# 5. Rust: the session stays in proxy_control.rs, and that module neither logs,
#    serializes, nor touches the filesystem. `format!` is allowed: it builds the
#    TXT response and the hex session id, neither of which leaves the resolver.
code_scan "HMAC session material outside rust proxy_control.rs" \
    'ring::hmac|hmac::Key' $RUST_OTHER
code_scan "logging, serde, or filesystem access in the session-key module" \
    'println!|eprintln!|log::|tracing::|(^|[^A-Za-z0-9_])(info|warn|error|debug|trace)!|serde|Serialize|Deserialize|std::fs|File::|OpenOptions' \
    "$RUST_CONTROL"

# 6. "Ephemeral and memory-only" is a property of the key's *storage*, so the
#    anchors assert that storage in each of the three processes that hold it.
#    Anchoring on "a key is generated somehow" would not: the provider also
#    generates a session id, which is not secret, and an anchor that a
#    non-secret satisfies keeps passing while the key itself regresses.

# Provider: the live key is CryptoKit storage, which wipes on release. A plain
# `Data` leaves the key readable in freed memory after the connection drops.
require_present "$SESSION" 'hmacKey: SymmetricKey' \
    "the provider's session key is no longer held in CryptoKit's wiping storage"
require_present "$SESSION" 'SymmetricKey[(]size:' \
    "the key is no longer generated straight into wiping storage"
# The bootstrap initializer legitimately takes the wire key as `Data`; only a
# stored property or local holding the live key is a violation.
code_scan "the session key is kept in an unwipeable Data buffer" \
    '(^|[^A-Za-z0-9_])(let|var)[ ]+hmacKey[ ]*:[ ]*Data' "$SESSION"

# Agent: it stages the key only long enough to hand it to the resolver.
require_present "$AGENT_CLIENT" 'configureProxyControl[(]' \
    "the agent no longer installs the session key; checks 1-4 lost their subject"
require_present "$AGENT_CLIENT" 'hmacKey[.]resetBytes[(]' \
    "the agent no longer wipes its staged copy of the key after installing it"

# Resolver: the session owns zeroizing storage and scrubs the buffer it was
# handed, so neither copy survives the session.
require_present "$RUST_CONTROL" 'hmac::Key' \
    "the resolver no longer holds the HMAC session; checks 1-5 lost their subject"
require_present "$RUST_CONTROL" 'key:[ ]*Zeroizing<' \
    "the resolver's session key is no longer in zeroizing storage"
require_present "$RUST_CONTROL" 'key_bytes[.]zeroize[(]' \
    "the resolver no longer scrubs the key buffer it was handed"

# The install/clear FFI pair still exists, and clearing happens on shutdown as
# well as on init. Otherwise the key outlives its session on a stop/start cycle.
require_present "$RUST_LIB" 'dns_configure_proxy_control' \
    "the session-install FFI entrypoint is gone"
require_present "$RUST_LIB" 'dns_clear_proxy_control' \
    "the session-clear FFI entrypoint is gone; the key could outlive its session"
require_any_region_present "$RUST_LIB" 'fn dns_init[A-Za-z0-9_]*[ ]*[(]' \
    'proxy_control::clear[(]' \
    "the init path no longer clears the session before listeners open"
require_any_region_present "$RUST_LIB" 'fn dns_shutdown[A-Za-z0-9_]*[ ]*[(]' \
    'proxy_control::clear[(]' \
    "the shutdown path no longer clears the session; the key would survive stop-then-start"

rule_end

# J13 — the HMAC session key is ephemeral and memory-only.

SESSION=Sources/DNSProxyExtension/ProxyControlSession.swift
CLIENT=Sources/MacDNSAgent/Services/ProxyControlClient.swift
RUST=rust-resolver/crates/macdns-resolver/src/proxy_control.rs
RUSTLIB=rust-resolver/crates/macdns-resolver/src/lib.rs

begin "J13 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'HMAC session key is ephemeral and memory-only'
expect J13 fail "no longer in AGENTS.md"

begin "J13 catches the key reaching the App target"
add Sources/MacDNS/ViewModels/AppViewModel.swift 'var hmacKey: Data?'
expect J13 fail "session key referenced in the App target"

begin "J13 catches the key in a Shared model outside the transport types"
add Sources/Shared/MacDNSXPCProtocol.swift 'struct AgentState: Codable { let sessionKey: Data }'
expect J13 fail "session key in a Shared type outside the proxy-control transport"

begin "J13 catches the key on a logging call"
add Sources/DNSProxyExtension/ProxyControlListener.swift 'logger.debug("key \(session.hmacKey)")'
expect J13 fail "session key on a logging call"

begin "J13 catches the key on a persistence call"
add "$SESSION" 'try hmacKey.write(to: cacheURL)'
expect J13 fail "session key on a persistence call"

# --- storage, not generation -------------------------------------------------
#
# These three are the reason the positive anchor is no longer "a key is generated
# somehow". The provider also generates a non-secret session id, so an anchor on
# SecRandomCopyBytes kept passing while the key's storage regressed. Each case
# below leaves session-id generation untouched.

begin "J13 catches the live key moving out of CryptoKit's wiping storage"
swap "$SESSION" 'let hmacKey: SymmetricKey' '    let hmacKey: Data'
expect J13 fail "no longer held in CryptoKit's wiping storage"

begin "J13 catches key generation leaving wiping storage"
swap "$SESSION" 'key: SymmetricKey(size: .bits256))' \
    '        return ProxyControlSession(version: 1, sessionID: id, hmacKey: randomKeyBytes())'
expect J13 fail "no longer generated straight into wiping storage"

begin "J13 catches an unwipeable Data copy of the key in the session type"
add "$SESSION" 'var hmacKey: Data = Data(count: 32)'
expect J13 fail "unwipeable Data buffer"

# The bootstrap payload is a serialized wire type, so `Data` is correct there:
# the check is scoped to the type that owns the live key, not to the identifier.
begin "J13 does not flag the wire type's Data-encoded key"
add Sources/Shared/ProxyControlProtocol.swift 'var hmacKey: Data = Data()'
expect J13 ok

begin "J13 catches the agent keeping its staged copy of the key"
drop "$CLIENT" 'boot.hmacKey.resetBytes'
expect J13 fail "no longer wipes its staged copy"

# --- resolver ----------------------------------------------------------------

begin "J13 catches the resolver key leaving zeroizing storage"
swap "$RUST" 'key: Zeroizing<[u8; 32]>,' '    key: [u8; 32],'
expect J13 fail "no longer in zeroizing storage"

begin "J13 catches the resolver keeping the buffer it was handed"
drop "$RUST" 'key_bytes.zeroize();'
expect J13 fail "no longer scrubs the key buffer"

begin "J13 catches logging in the session-key module"
add "$RUST" 'fn dump() { println!("{:?}", session_slot()); }'
expect J13 fail "logging, serde, or filesystem access in the session-key module"

begin "J13 catches serde reaching the session-key module"
add "$RUST" 'use serde::Serialize;'
expect J13 fail "logging, serde, or filesystem access in the session-key module"

# format! renders the outbound TXT tag, which is what the provider is meant to
# receive; it is deliberately not part of the logging ban.
begin "J13 does not flag format! in the session-key module"
add "$RUST" 'fn tag(b: u8) -> String { format!("{:02x}", b) }'
expect J13 ok

begin "J13 catches HMAC material outside the session module"
add "$RUSTLIB" 'fn forge(a: &[u8], b: &[u8]) { let k = hmac::Key::new(a, b); }'
expect J13 fail "HMAC session material outside rust proxy_control.rs"

# --- lifecycle ---------------------------------------------------------------
#
# Both entrypoints delegate through guarded/inner helpers, so these prove the
# check follows the function family instead of one exact name.

begin "J13 catches the init path no longer clearing the session"
swap_after "$RUSTLIB" 'fn dns_init_guarded' 'proxy_control::clear();' '    // cleared elsewhere'
expect J13 fail "init path no longer clears the session"

begin "J13 catches the shutdown path no longer clearing the session"
swap_after "$RUSTLIB" 'fn dns_shutdown_inner' 'proxy_control::clear();' '    // cleared elsewhere'
expect J13 fail "shutdown path no longer clears the session"

begin "J13 fails when the session-clear FFI entrypoint is gone"
drop "$RUSTLIB" 'pub extern "C" fn dns_clear_proxy_control'
expect J13 fail "session-clear FFI entrypoint is gone"

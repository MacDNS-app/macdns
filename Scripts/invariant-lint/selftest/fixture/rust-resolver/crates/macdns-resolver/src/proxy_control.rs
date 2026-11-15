//! In-memory, per-session HMAC material for the DNS Proxy control plane.
//!
//! The key lives only in memory and is cleared on both init and shutdown. This
//! module deliberately has no logging, no serde, and no filesystem access.

use arc_swap::ArcSwapOption;
use ring::hmac;
use std::sync::{Arc, OnceLock};
use zeroize::{Zeroize, Zeroizing};

const DOMAIN_SEPARATOR: &[u8] = b"macdns-proxy-control-v1";

struct Session {
    id: [u8; 16],
    /// Raw key bytes rather than a `ring::hmac::Key`: the wrapper scrubs them
    /// when the session is dropped, and `ring` does not zeroize its derived
    /// key state.
    key: Zeroizing<[u8; 32]>,
}

static SESSION: OnceLock<ArcSwapOption<Session>> = OnceLock::new();

fn session_slot() -> &'static ArcSwapOption<Session> {
    SESSION.get_or_init(ArcSwapOption::empty)
}

pub fn configure(id: [u8; 16], mut key_bytes: [u8; 32]) {
    let key = Zeroizing::new(key_bytes);
    key_bytes.zeroize();
    session_slot().store(Some(Arc::new(Session { id, key })));
}

pub fn clear() {
    session_slot().store(None);
}

/// Builds the authenticated TXT response. `format!` is intentionally fine here:
/// it renders the hex tag, which is what the provider is meant to receive.
pub fn build_response(nonce: &[u8; 32], ready: bool) -> Option<String> {
    let session = session_slot().load_full()?;
    let mut payload = Vec::with_capacity(DOMAIN_SEPARATOR.len() + 16 + 1 + 32);
    payload.extend_from_slice(DOMAIN_SEPARATOR);
    payload.extend_from_slice(&session.id);
    payload.push(if ready { 1 } else { 0 });
    payload.extend_from_slice(nonce);
    let key = hmac::Key::new(hmac::HMAC_SHA256, session.key.as_ref());
    let tag = hmac::sign(&key, &payload);
    Some(hex(tag.as_ref()))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

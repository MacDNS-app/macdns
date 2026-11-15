// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! In-memory, per-session HMAC material for the DNS Proxy control plane.
//!
//! The provider hands the agent a random session id and key over authenticated
//! XPC, and the agent installs it here. The resolver answers authenticated probe
//! names with an HMAC-SHA256 the fake-listener attacker cannot forge. The key
//! lives only in memory and is cleared on every `dns_init` and shutdown.

use arc_swap::ArcSwapOption;
use ring::hmac;
use std::sync::{Arc, OnceLock};
use zeroize::{Zeroize, Zeroizing};

const DOMAIN_SEPARATOR: &[u8] = b"macdns-proxy-control-v1";
const VERSION: u16 = 1;

struct Session {
    id: [u8; 16],
    /// Raw key bytes rather than a `ring::hmac::Key`: the wrapper scrubs them
    /// when the session is dropped, and `ring` does not zeroize its derived
    /// key state. The per-signature `hmac::Key` is rebuilt from these bytes.
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

/// Builds the `v1 <session-hex> <transport> <ready> <hmac-hex>` TXT string.
/// Returns `None` when no session is installed (fail closed).
pub fn build_response(
    nonce: &[u8; 32],
    transport_tag: u8,
    ready: bool,
    question_wire: &[u8],
) -> Option<String> {
    let session = session_slot().load_full()?;
    let transport_label = match transport_tag {
        b'u' => "u",
        b't' => "t",
        _ => return None,
    };
    let question_hash = ring::digest::digest(&ring::digest::SHA256, question_wire);

    let mut payload = Vec::with_capacity(DOMAIN_SEPARATOR.len() + 2 + 16 + 1 + 1 + 32 + 32);
    payload.extend_from_slice(DOMAIN_SEPARATOR);
    payload.extend_from_slice(&VERSION.to_be_bytes());
    payload.extend_from_slice(&session.id);
    payload.push(transport_tag);
    payload.push(if ready { 0x01 } else { 0x00 });
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(question_hash.as_ref());

    let mac = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, &session.key[..]),
        &payload,
    );
    Some(format!(
        "v{} {} {} {} {}",
        VERSION,
        hex_lower(&session.id),
        transport_label,
        if ready { "1" } else { "0" },
        hex_lower(mac.as_ref()),
    ))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// The session is process-global. Any test that installs or clears it, here
/// or in `query`, must hold this lock so parallel execution cannot race the
/// install or clear of one test against the assertions of another.
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Immutable cross-language golden vector. The exact same session id, key,
    // nonce, question wire and MACs are asserted against the production Swift
    // verifier in `Tests/MacDNSTests/ProxyControlChallengeClientTests.swift`.
    // Both sides compare to these fixed MACs instead of recomputing them, so a
    // one-sided change to the signing payload fails the tests of that language
    // instead of holding the DNS Proxy in permanent bypass.
    const GOLDEN_SESSION_HEX: &str = "000102030405060708090a0b0c0d0e0f";
    const GOLDEN_QUESTION_UDP_HEX: &str = "\
2038303831383238333834383538363837383838393861386238633864386538662039303931\
39323933393439353936393739383939396139623963396439653966017506\
5f70726f6265066d6163646e730000100001";
    const GOLDEN_QUESTION_TCP_HEX: &str = "\
2038303831383238333834383538363837383838393861386238633864386538662039303931\
39323933393439353936393739383939396139623963396439653966017406\
5f70726f6265066d6163646e730000100001";
    const GOLDEN_MAC_UDP_READY: &str =
        "932f0757f407dddec98e0e50f5eda85c9f6353f6d024fe959b84aa270ab4fbc4";
    const GOLDEN_MAC_TCP_READY: &str =
        "748a6996702f4bbcdce1d813fe1bd5c8a0b0a33a251e916043517590c7668062";
    const GOLDEN_MAC_UDP_NOT_READY: &str =
        "bd968864578c6298a2a60ec0ccc7a96ed47e1593fc9951086e2009c46fdf4b9e";

    fn golden_session_id() -> [u8; 16] {
        std::array::from_fn(|i| i as u8)
    }

    fn golden_key() -> [u8; 32] {
        std::array::from_fn(|i| 0x40 + i as u8)
    }

    fn golden_nonce() -> [u8; 32] {
        std::array::from_fn(|i| 0x80 + i as u8)
    }

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn golden_vector_matches_the_cross_language_wire_contract() {
        let _guard = super::test_lock();
        configure(golden_session_id(), golden_key());
        for (tag, label, ready, question_hex, expected_mac) in [
            (
                b'u',
                "u",
                true,
                GOLDEN_QUESTION_UDP_HEX,
                GOLDEN_MAC_UDP_READY,
            ),
            (
                b't',
                "t",
                true,
                GOLDEN_QUESTION_TCP_HEX,
                GOLDEN_MAC_TCP_READY,
            ),
            (
                b'u',
                "u",
                false,
                GOLDEN_QUESTION_UDP_HEX,
                GOLDEN_MAC_UDP_NOT_READY,
            ),
        ] {
            let out = build_response(&golden_nonce(), tag, ready, &unhex(question_hex))
                .expect("golden session installed");
            assert_eq!(
                out,
                format!(
                    "v1 {} {} {} {}",
                    GOLDEN_SESSION_HEX,
                    label,
                    if ready { "1" } else { "0" },
                    expected_mac
                ),
                "signing payload drifted from the golden vector"
            );
        }
        clear();
    }

    fn install() -> ([u8; 16], [u8; 32]) {
        let id = [3u8; 16];
        let key = [7u8; 32];
        configure(id, key);
        (id, key)
    }

    #[test]
    fn no_session_returns_none() {
        let _guard = super::test_lock();
        clear();
        assert!(build_response(&[0u8; 32], b'u', true, b"q").is_none());
    }

    #[test]
    fn response_shape_is_stable() {
        let _guard = super::test_lock();
        let (id, _) = install();
        let out = build_response(&[9u8; 32], b'u', true, b"question").unwrap();
        let tokens: Vec<&str> = out.split(' ').collect();
        assert_eq!(tokens.len(), 5);
        assert_eq!(tokens[0], "v1");
        assert_eq!(tokens[1], hex_lower(&id));
        assert_eq!(tokens[2], "u");
        assert_eq!(tokens[3], "1");
        assert_eq!(tokens[4].len(), 64);
        clear();
    }

    #[test]
    fn transport_and_ready_change_mac() {
        let _guard = super::test_lock();
        install();
        let a = build_response(&[9u8; 32], b'u', true, b"q").unwrap();
        let b = build_response(&[9u8; 32], b't', true, b"q").unwrap();
        let c = build_response(&[9u8; 32], b'u', false, b"q").unwrap();
        let mac = |s: &str| s.split(' ').nth(4).unwrap().to_string();
        assert_ne!(mac(&a), mac(&b));
        assert_ne!(mac(&a), mac(&c));
        clear();
    }

    #[test]
    fn unknown_transport_tag_returns_none() {
        let _guard = super::test_lock();
        install();
        assert!(build_response(&[9u8; 32], b'x', true, b"q").is_none());
        clear();
    }
}

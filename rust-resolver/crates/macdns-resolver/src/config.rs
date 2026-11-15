// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use arc_swap::ArcSwap;
use std::sync::{Arc, OnceLock};

pub const BLOCK_REBINDING: bool = true;
pub const RRSET_ROUNDROBIN: bool = true;
pub const SERVE_EXPIRED_CLIENT_TIMEOUT_MS: u32 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoHProviderId {
    Cloudflare,
    Google,
    Quad9,
}

impl DoHProviderId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::Google => "google",
            Self::Quad9 => "quad9",
        }
    }

    pub fn parse_raw(raw: &str) -> Option<Self> {
        match raw {
            "cloudflare" => Some(Self::Cloudflare),
            "google" => Some(Self::Google),
            "quad9" => Some(Self::Quad9),
            _ => None,
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::Cloudflare => "Cloudflare",
            Self::Google => "Google",
            Self::Quad9 => "Quad9",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchMode {
    Parallel,
    StaggeredParallel,
    SequentialTimeout,
}

impl DispatchMode {
    pub fn from_ffi(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Parallel),
            1 => Some(Self::StaggeredParallel),
            2 => Some(Self::SequentialTimeout),
            _ => None,
        }
    }
}

pub fn canonical_provider_order() -> [DoHProviderId; 3] {
    [
        DoHProviderId::Cloudflare,
        DoHProviderId::Google,
        DoHProviderId::Quad9,
    ]
}

pub fn default_provider_ids() -> Vec<DoHProviderId> {
    canonical_provider_order().to_vec()
}

pub fn canonicalize_provider_ids(raw: &[DoHProviderId]) -> Vec<DoHProviderId> {
    let selected: Vec<_> = canonical_provider_order()
        .into_iter()
        .filter(|id| raw.contains(id))
        .collect();
    if selected.is_empty() {
        default_provider_ids()
    } else {
        selected
    }
}

/// Resolver options forwarded from the `state.json` toggles, set by
/// `dns_set_resolver_options` before `dns_init`. `prefetch` refills an entry
/// in the background (`query.rs::prefetch_refill`) once it has
/// `min(10s, TTL/3)` left, found by the periodic scan or by a cache hit, with
/// one refill in flight per entry. Entries unused for 4 hours drop out,
/// except keys in the lookup history's popular set (`history::popular()`).
/// `serve_expired` follows RFC 8767. On a cache miss with a stale entry
/// present, the hedge races against `SERVE_EXPIRED_CLIENT_TIMEOUT_MS` and
/// returns the stale entry (stale TTL + EDE 3) if the timeout wins. When every
/// upstream fails, `serve_stale` returns any entry still inside the
/// compile-time serve-expired grace window.
/// Internal safety and policy knobs stay Rust constants so users cannot change
/// them through `state.json`.
#[derive(Clone, Debug)]
pub struct ResolverOptions {
    pub dnssec: bool,
    pub log_queries: bool,
    pub log_replies: bool,
    pub prefetch: bool,
    pub serve_expired: bool,
    pub doh_providers: Vec<DoHProviderId>,
    pub dispatch_mode: DispatchMode,
    pub answer_refinement: bool,
}

impl Default for ResolverOptions {
    fn default() -> Self {
        Self {
            dnssec: true,
            log_queries: false,
            log_replies: false,
            prefetch: true,
            serve_expired: true,
            doh_providers: default_provider_ids(),
            dispatch_mode: DispatchMode::StaggeredParallel,
            answer_refinement: true,
        }
    }
}

impl ResolverOptions {
    pub fn selected_providers_in_canonical_order(&self) -> Vec<DoHProviderId> {
        canonicalize_provider_ids(&self.doh_providers)
    }
}

static OPTIONS: OnceLock<ArcSwap<ResolverOptions>> = OnceLock::new();

fn slot() -> &'static ArcSwap<ResolverOptions> {
    OPTIONS.get_or_init(|| ArcSwap::from_pointee(ResolverOptions::default()))
}

pub fn set(opts: ResolverOptions) {
    slot().store(Arc::new(opts));
}

pub fn current() -> Arc<ResolverOptions> {
    slot().load_full()
}

/// Sets the global resolver options for the duration of a test and restores
/// the previous value on drop, including on panic. The mutex serialises tests
/// that go through this guard. It does not serialise every test that touches
/// global config (several call `config::set` directly), so the guarantee holds
/// for guard users only, and single-threaded CI covers the rest. Do not
/// add a second guard type with its own lock.
#[cfg(test)]
pub(crate) struct ConfigGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    previous: ResolverOptions,
}

#[cfg(test)]
static CONFIG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
impl ConfigGuard {
    pub(crate) fn new(options: ResolverOptions) -> Self {
        let lock = CONFIG_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let previous = (*current()).clone();
        set(options);
        Self {
            _lock: lock,
            previous,
        }
    }
}

#[cfg(test)]
impl Default for ConfigGuard {
    fn default() -> Self {
        Self::new(ResolverOptions::default())
    }
}

#[cfg(test)]
impl Drop for ConfigGuard {
    fn drop(&mut self) {
        set(self.previous.clone());
    }
}

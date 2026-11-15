// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use crate::cache::DnsCache;
use crate::forward::ForwardResolver;
use crate::local_zones::LocalZones;
use crate::network_profile::NetworkProfileStore;
use crate::policy::RuntimePolicySnapshot;
use crate::providers::ProviderPool;
use crate::zones::ForwardZones;
use arc_swap::ArcSwap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, OnceLock};

pub struct ModuleState {
    pub pool: Arc<ProviderPool>,
    pub cache: Arc<DnsCache>,
    /// Overrides and forward zones published as one coherent unit. A query
    /// loads this once so it never mixes new overrides with old zones.
    pub policy: ArcSwap<RuntimePolicySnapshot>,
    /// Routes derived from the attached network's DHCP search domains.
    /// Runtime-derived and never persisted to `state.json`. Replaced as a
    /// whole table on every network change and cleared when the host publishes
    /// an empty set.
    pub ephemeral_zones: ArcSwap<Arc<ForwardZones>>,
    pub local_zones: Arc<LocalZones>,
    pub forward: ArcSwap<Option<Arc<ForwardResolver>>>,
    pub forward_generation: AtomicU64,
    /// Facts about the attached network and its NAT64 status. Runtime-derived,
    /// never persisted, and replaced by every host snapshot.
    pub network: Arc<NetworkProfileStore>,
}

/// The state slot is swappable, not a plain OnceLock over the Arc, so each
/// `dns_init` after a `dns_shutdown` rebuilds cache, providers, overrides,
/// zones and the forward resolver from scratch. Nothing leaks from one session
/// into the next when the `useDNSProxy` flag is toggled and services restart.
static STATE: OnceLock<ArcSwap<Option<Arc<ModuleState>>>> = OnceLock::new();

fn slot() -> &'static ArcSwap<Option<Arc<ModuleState>>> {
    STATE.get_or_init(|| ArcSwap::from_pointee(None))
}

pub fn init_state(state: ModuleState) -> Arc<ModuleState> {
    let arc = Arc::new(state);
    slot().store(Arc::new(Some(arc.clone())));
    arc
}

pub fn clear_state() {
    slot().store(Arc::new(None));
}

pub fn get_state() -> Option<Arc<ModuleState>> {
    slot().load().as_ref().as_ref().cloned()
}

/// Serializes tests that install, replace or clear the process-wide state
/// slot. Without it the parallel test runner lets a lifecycle test observe or
/// tear down the state another test installed.
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

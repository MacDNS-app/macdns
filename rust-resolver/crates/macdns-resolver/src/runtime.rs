// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::runtime::{Runtime, RuntimeFlavor};
use tokio_util::sync::CancellationToken;

pub struct RuntimeHandle {
    pub runtime: Runtime,
    pub cancel: CancellationToken,
}

static RUNTIME: OnceLock<Mutex<Option<RuntimeHandle>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<RuntimeHandle>> {
    RUNTIME.get_or_init(|| Mutex::new(None))
}

pub fn start_runtime() -> Result<(), String> {
    let mut guard = slot().lock().map_err(|e| e.to_string())?;
    if guard.is_some() {
        return Ok(());
    }
    // A fixed 4 workers saturated one core on M-series Macs under bursty
    // browser load. Beyond 8 threads a localhost DNS proxy gains no latency
    // and context-switch overhead starts to dominate.
    let workers = num_cpus::get_physical().clamp(2, 8);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name("macdns-dns")
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    *guard = Some(RuntimeHandle {
        runtime,
        cancel: CancellationToken::new(),
    });
    Ok(())
}

pub fn is_running() -> bool {
    slot().lock().map(|g| g.is_some()).unwrap_or(false)
}

pub fn cancel_token() -> Option<CancellationToken> {
    slot().lock().ok()?.as_ref().map(|h| h.cancel.clone())
}

pub fn spawn<F, T>(future: F) -> Result<tokio::task::JoinHandle<T>, String>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let handle = {
        let guard = slot().lock().map_err(|e| e.to_string())?;
        let h = guard.as_ref().ok_or("runtime not started")?;
        h.runtime.handle().clone()
    };
    Ok(handle.spawn(future))
}

/// Spawns on the runtime the caller is already running on, and on the
/// resolver runtime from outside any runtime. Background work that a query
/// starts (the hedge collector, answer refinement) runs where the query
/// runs: in the agent that is the resolver runtime itself, and a test can
/// drive the same path on its own runtime.
pub fn spawn_on_current_or_global<F, T>(future: F) -> Result<tokio::task::JoinHandle<T>, String>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => Ok(handle.spawn(future)),
        Err(_) => spawn(future),
    }
}

/// Runs a future to completion on the runtime, blocking the current thread.
/// For synchronous FFI entry points that need async setup, such as binding
/// tokio sockets, before they return success.
pub fn block_on<F, T>(future: F) -> Result<T, String>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let handle = {
        let guard = slot().lock().map_err(|e| e.to_string())?;
        let h = guard.as_ref().ok_or("runtime not started")?;
        h.runtime.handle().clone()
    };
    match tokio::runtime::Handle::try_current() {
        Ok(current) if current.runtime_flavor() == RuntimeFlavor::MultiThread => {
            Ok(tokio::task::block_in_place(|| handle.block_on(future)))
        }
        Ok(_) => std::thread::Builder::new()
            .name("macdns-block-on".into())
            .spawn(move || handle.block_on(future))
            .map_err(|e| e.to_string())?
            .join()
            .map_err(|_| "block_on helper thread panicked".to_string()),
        Err(_) => Ok(handle.block_on(future)),
    }
}

pub fn stop_runtime(shutdown_timeout: Duration) {
    let handle = {
        let mut guard = match slot().lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.take()
    };
    if let Some(h) = handle {
        h.cancel.cancel();
        h.runtime.shutdown_timeout(shutdown_timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The runtime is a process-wide singleton that `start_runtime` and
    // `stop_runtime` mutate directly. Cargo runs tests in parallel, so without
    // this lock one test's `stop_runtime` can shut down the singleton while
    // another test's `block_on` still uses it ("Tokio context is being
    // shutdown"). The lock is re-acquired through poison so one panicking test
    // does not fail the rest.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        match TEST_LOCK.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[test]
    fn start_then_stop_returns_ownership() {
        let _guard = lock();
        start_runtime().unwrap();
        assert!(is_running());
        stop_runtime(std::time::Duration::from_secs(2));
        assert!(!is_running());
    }

    #[test]
    fn double_start_is_idempotent() {
        let _guard = lock();
        start_runtime().unwrap();
        let second = start_runtime();
        assert!(second.is_ok());
        stop_runtime(std::time::Duration::from_secs(2));
    }

    #[test]
    fn restart_after_stop_succeeds() {
        let _guard = lock();
        start_runtime().unwrap();
        stop_runtime(std::time::Duration::from_secs(2));
        assert!(!is_running());
        start_runtime().unwrap();
        assert!(is_running());
        stop_runtime(std::time::Duration::from_secs(2));
    }

    #[test]
    fn spawn_during_block_on_does_not_deadlock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let _guard = lock();
        start_runtime().unwrap();

        let outer_done = Arc::new(AtomicBool::new(false));
        let outer_done_for_block = outer_done.clone();

        let result = block_on(async move {
            let flag = Arc::new(AtomicBool::new(false));
            let flag_for_task = flag.clone();
            let _ = spawn(async move {
                flag_for_task.store(true, Ordering::Release);
            });
            for _ in 0..50 {
                if flag.load(Ordering::Acquire) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            outer_done_for_block.store(true, Ordering::Release);
            flag.load(Ordering::Acquire)
        })
        .unwrap();

        assert!(result, "spawn from inside block_on must complete");
        assert!(outer_done.load(Ordering::Acquire));
        stop_runtime(std::time::Duration::from_secs(2));
    }

    #[test]
    fn block_on_from_runtime_worker_completes() {
        let _guard = lock();
        start_runtime().unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let handle = spawn(async move {
            let result = block_on(async { 42u8 });
            tx.send(result).unwrap();
        })
        .unwrap();

        let result = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("runtime worker must not deadlock in block_on");
        assert_eq!(result.unwrap(), 42);
        drop(handle);
        stop_runtime(std::time::Duration::from_secs(2));
    }

    #[test]
    fn block_on_from_current_thread_runtime_completes() {
        let _guard = lock();
        start_runtime().unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async { block_on(async { 7u8 }) });

        assert_eq!(result.unwrap(), 7);
        stop_runtime(std::time::Duration::from_secs(2));
    }
}

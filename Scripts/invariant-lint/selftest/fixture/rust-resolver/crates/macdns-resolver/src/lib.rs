use std::os::raw::{c_int, c_ushort};

mod proxy_control;

#[no_mangle]
pub extern "C" fn dns_init(port: c_ushort) -> c_int {
    catch_ffi_panic(|| dns_init_guarded(port))
}

fn dns_init_guarded(port: c_ushort) -> c_int {
    // The session must not survive a restart of the listeners.
    proxy_control::clear();
    start_runtime(port)
}

#[no_mangle]
pub extern "C" fn dns_shutdown() {
    let _ = dns_shutdown_v2(0);
}

#[no_mangle]
pub extern "C" fn dns_shutdown_v2(skip_snapshot: c_int) -> c_int {
    catch_ffi_panic(|| dns_shutdown_inner(skip_snapshot != 0))
}

fn dns_shutdown_inner(skip_snapshot: bool) -> c_int {
    // The agent's fail-safe stop path calls stop() without disconnecting the
    // control link first, so the session has to be dropped here too — otherwise
    // the key survives a stop-then-start cycle.
    proxy_control::clear();
    stop_runtime(skip_snapshot)
}

/// # Safety
/// `session_ptr`/`key_ptr` must reference at least the stated lengths for the
/// call duration, or be null (rejected as failure).
#[no_mangle]
pub unsafe extern "C" fn dns_configure_proxy_control(
    session_ptr: *const u8,
    session_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) -> c_int {
    catch_ffi_panic(|| {
        if session_ptr.is_null() || key_ptr.is_null() || session_len != 16 || key_len != 32 {
            return 0;
        }
        let mut id = [0u8; 16];
        // Zeroizing so the staged key does not survive this frame.
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        unsafe {
            std::ptr::copy_nonoverlapping(session_ptr, id.as_mut_ptr(), 16);
            std::ptr::copy_nonoverlapping(key_ptr, key.as_mut_ptr(), 32);
        }
        proxy_control::configure(id, *key);
        1
    })
}

/// Clears any installed control-plane session. Returns 1 on success.
#[no_mangle]
pub extern "C" fn dns_clear_proxy_control() -> c_int {
    catch_ffi_panic(|| {
        proxy_control::clear();
        1
    })
}

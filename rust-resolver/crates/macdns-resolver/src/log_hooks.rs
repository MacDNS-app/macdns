// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use arc_swap::ArcSwap;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// Callback strings are valid only for the call duration. Swift must copy
/// them before returning, and callbacks must not unwind across FFI.
pub type QueryCallback = extern "C" fn(domain: *const c_char, qtype: *const c_char);
pub type ReplyCallback = extern "C" fn(
    domain: *const c_char,
    qtype: *const c_char,
    rcode: *const c_char,
    answers: u32,
    provider: *const c_char,
    data: *const c_char,
);
/// Invoked on every SERVFAIL the proxy emits (`all-upstream-failed`,
/// `upstream-response-failure`, `upstream-timeout` and others. Grep
/// `report_servfail` for the current set). A dedicated channel, like
/// `QueryCallback` and `ReplyCallback`, lets the Swift host route these lines
/// into a distinct os.log subsystem, so SERVFAILs can be filtered without
/// grepping free-form warn text.
pub type ServfailCallback =
    extern "C" fn(domain: *const c_char, qtype: *const c_char, reason: *const c_char);
/// Level mapping matches `log::Level as i32 - 1`: 0=Error, 1=Warn, 2=Info,
/// 3=Debug, 4=Trace. Kept stable so the Swift side can rely on it.
pub type LogCallback = extern "C" fn(level: i32, target: *const c_char, message: *const c_char);

// ArcSwap<Option<Fn>> rather than `OnceLock<Fn>` because the Swift host
// re-registers callbacks on every `start()`, and the agent reuses the loaded
// dylib across stop/start cycles. A second `OnceLock::set` fails silently and
// leaves the new cycle on the first cycle's callbacks, which would drop
// observability if the host ever passed different ones.
static QUERY_CB: OnceLock<ArcSwap<Option<QueryCallback>>> = OnceLock::new();
static REPLY_CB: OnceLock<ArcSwap<Option<ReplyCallback>>> = OnceLock::new();
static SERVFAIL_CB: OnceLock<ArcSwap<Option<ServfailCallback>>> = OnceLock::new();
static LOG_CB: OnceLock<ArcSwap<Option<LogCallback>>> = OnceLock::new();

fn query_slot() -> &'static ArcSwap<Option<QueryCallback>> {
    QUERY_CB.get_or_init(|| ArcSwap::from_pointee(None))
}

fn reply_slot() -> &'static ArcSwap<Option<ReplyCallback>> {
    REPLY_CB.get_or_init(|| ArcSwap::from_pointee(None))
}

fn servfail_slot() -> &'static ArcSwap<Option<ServfailCallback>> {
    SERVFAIL_CB.get_or_init(|| ArcSwap::from_pointee(None))
}

fn log_slot() -> &'static ArcSwap<Option<LogCallback>> {
    LOG_CB.get_or_init(|| ArcSwap::from_pointee(None))
}

pub fn set_query_callback(cb: QueryCallback) {
    query_slot().store(Arc::new(Some(cb)));
}

pub fn set_reply_callback(cb: ReplyCallback) {
    reply_slot().store(Arc::new(Some(cb)));
}

pub fn set_servfail_callback(cb: ServfailCallback) {
    servfail_slot().store(Arc::new(Some(cb)));
}

pub fn set_log_callback(cb: LogCallback) {
    log_slot().store(Arc::new(Some(cb)));
}

pub fn emit_log(level: log::Level, target: &str, message: &str) {
    let guard = log_slot().load();
    let Some(cb) = **guard else { return };
    let Ok(t) = CString::new(target) else { return };
    let Ok(m) = CString::new(message) else { return };
    let lvl = match level {
        log::Level::Error => 0,
        log::Level::Warn => 1,
        log::Level::Info => 2,
        log::Level::Debug => 3,
        log::Level::Trace => 4,
    };
    cb(lvl, t.as_ptr(), m.as_ptr());
}

pub fn emit_query(domain: &str, qtype_str: &str) {
    let guard = query_slot().load();
    let Some(cb) = **guard else { return };
    if let (Ok(d), Ok(t)) = (CString::new(domain), CString::new(qtype_str)) {
        cb(d.as_ptr(), t.as_ptr());
    }
}

/// Emits a SERVFAIL line through the dedicated servfail callback. `reason` is
/// a short stable identifier, never a free-form error string, so Swift parsers
/// and dashboards can bucket SERVFAILs without matching on free text. Grep
/// `report_servfail` for the identifiers currently in use.
pub fn emit_servfail(domain: &str, qtype_str: &str, reason: &str) {
    let guard = servfail_slot().load();
    let Some(cb) = **guard else { return };
    if let (Ok(d), Ok(t), Ok(r)) = (
        CString::new(domain),
        CString::new(qtype_str),
        CString::new(reason),
    ) {
        cb(d.as_ptr(), t.as_ptr(), r.as_ptr());
    }
}

/// Installs a process-wide panic hook that routes the panic message +
/// backtrace through `emit_log` (Error level) before the panic unwinds into
/// the FFI sentinel guard. Unwinding keeps `MacDNSAgent` alive but discards
/// the panic site, so without this hook a panic in any tokio worker leaves no
/// evidence in os.log (the 2026-04-21 VPN-stop incident could not be traced
/// for this reason). Idempotent: only the first caller installs the hook.
pub fn install_panic_hook() {
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown location>".into());
        let payload: &str = info
            .payload()
            .downcast_ref::<&'static str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("<non-string panic payload>");
        let backtrace = std::backtrace::Backtrace::force_capture();
        let message = format!(
            "panic at {}: {}\nthread: {}\nbacktrace:\n{}",
            location,
            payload,
            std::thread::current().name().unwrap_or("<unnamed>"),
            backtrace
        );
        emit_log(log::Level::Error, "panic", &message);
        default(info);
    }));
}

pub fn emit_reply(
    domain: &str,
    qtype_str: &str,
    rcode_str: &str,
    answers: u32,
    provider: &str,
    data: &str,
) {
    let guard = reply_slot().load();
    let Some(cb) = **guard else { return };
    if let (Ok(d), Ok(t), Ok(r), Ok(p), Ok(ds)) = (
        CString::new(domain),
        CString::new(qtype_str),
        CString::new(rcode_str),
        CString::new(provider),
        CString::new(data),
    ) {
        cb(
            d.as_ptr(),
            t.as_ptr(),
            r.as_ptr(),
            answers,
            p.as_ptr(),
            ds.as_ptr(),
        );
    }
}

/// Test seam: `cb` receives every log line until the guard drops, which
/// clears the callback. Guards are exclusive because the callback slot is
/// process-wide, so a test reading logs never loses them to another test's
/// callback.
#[cfg(test)]
pub(crate) struct TestLogCallback {
    _exclusive: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
pub(crate) fn install_test_log_callback(cb: LogCallback) -> TestLogCallback {
    static EXCLUSIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let exclusive = EXCLUSIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    crate::install_ffi_logger();
    set_log_callback(cb);
    TestLogCallback {
        _exclusive: exclusive,
    }
}

#[cfg(test)]
impl Drop for TestLogCallback {
    fn drop(&mut self) {
        log_slot().store(Arc::new(None));
    }
}

#[cfg(test)]
pub(crate) fn capture_logs(run: impl FnOnce()) -> Vec<(i32, String)> {
    use std::cell::RefCell;
    use std::ffi::CStr;

    thread_local! {
        static LINES: RefCell<Option<Vec<(i32, String)>>> = const { RefCell::new(None) };
    }
    extern "C" fn capture(level: i32, _: *const c_char, message: *const c_char) {
        LINES.with(|lines| {
            if let Some(lines) = lines.borrow_mut().as_mut() {
                // SAFETY: the logging callback owns a valid C string for this call.
                let message = unsafe { CStr::from_ptr(message) }
                    .to_string_lossy()
                    .into_owned();
                lines.push((level, message));
            }
        });
    }

    let _callback = install_test_log_callback(capture);
    LINES.with(|lines| *lines.borrow_mut() = Some(Vec::new()));
    run();
    LINES.with(|lines| lines.borrow_mut().take().unwrap())
}

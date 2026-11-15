# J21 — the FFI contract between the agent and libmacdns_resolver.dylib.
#
# The shared fixture's lib.rs calls `catch_ffi_panic` without defining it and
# hands no owned C string across the boundary, so it carries neither of J21's
# subjects. Each case lays them down first: the helper, an owned-C-string
# producer with its matching free function, and the Swift binding that releases
# it in a `defer`. They live here rather than in the shared fixture so this case
# owns the shapes it asserts on, and so no other case has to stay compatible
# with them.

RUSTLIB=rust-resolver/crates/macdns-resolver/src/lib.rs
RESOLVER=Sources/MacDNSAgent/Services/ResolverModule.swift

# j21_add_rust — appends a heredoc of Rust to the fixture crate.
j21_add_rust() {
    cat >>"$W/$RUSTLIB"
}

# j21_begin <case-name> — a fixture that satisfies J21 in full.
j21_begin() {
    begin "$1"
    j21_add_rust <<'RUST'

fn catch_ffi_panic(operation: impl FnOnce() -> c_int) -> c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)).unwrap_or(0)
}

/// Returns a heap-allocated NUL-terminated JSON array of allowlisted domains.
/// The caller owns the pointer and must release it through `dns_allowlist_free_json`.
/// Returns NULL on any error.
#[no_mangle]
pub extern "C" fn dns_allowlist_list() -> *mut c_char {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Option<CString> {
        CString::new("[]").ok()
    }));
    match result {
        Ok(Some(cs)) => cs.into_raw(),
        Ok(None) => std::ptr::null_mut(),
        Err(_) => {
            log::error!("dns_allowlist_list: panic");
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// `ptr` must be either NULL or a pointer previously returned by
/// `dns_allowlist_list`. Passing any other value is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn dns_allowlist_free_json(ptr: *mut c_char) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if ptr.is_null() {
            return;
        }
        let _ = unsafe { CString::from_raw(ptr) };
    }))
    .map_err(|_| log::error!("dns_allowlist_free_json: panic"));
}
RUST
    put "$RESOLVER" 'import Foundation'
    cat >>"$W/$RESOLVER" <<'SWIFT'

/// Stand-in for the agent's dlopen/dlsym bridge to libmacdns_resolver.dylib.
final class ResolverModule {
    typealias DnsAllowlistListFn = @convention(c) () -> UnsafeMutablePointer<CChar>?
    typealias DnsAllowlistFreeJsonFn = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void

    private var handle: UnsafeMutableRawPointer?
    private var fnAllowlistList: DnsAllowlistListFn?
    private var fnAllowlistFreeJson: DnsAllowlistFreeJsonFn?

    private func bind() {
        fnAllowlistList = sym("dns_allowlist_list")
        fnAllowlistFreeJson = sym("dns_allowlist_free_json")
    }

    func listAllowedDomains() -> [String] {
        guard let list = fnAllowlistList, let freeJson = fnAllowlistFreeJson else {
            return []
        }
        guard let ptr = list() else {
            return []
        }
        defer { freeJson(ptr) }
        let json = String(cString: ptr)
        guard let data = json.data(using: .utf8) else {
            return []
        }
        return (try? JSONDecoder().decode([String].self, from: data)) ?? []
    }

    private func sym<T>(_ name: String) -> T? {
        guard let handle, let raw = dlsym(handle, name) else { return nil }
        return unsafeBitCast(raw, to: T.self)
    }
}
SWIFT
}

# j21_duplicate_binding <rel> — add a separate binding and its release site.
j21_duplicate_binding() {
    sed -e 's/ResolverModule/OtherResolverModule/g' \
        -e 's/fnAllowlistList/fnOtherList/g' \
        -e 's/fnAllowlistFreeJson/fnOtherFreeJson/g' \
        "$W/$RESOLVER" >"$WORK/other-binding.swift"
    mkdir -p "$(dirname "$W/$1")"
    cat "$WORK/other-binding.swift" >>"$W/$1"
}

# --- green -------------------------------------------------------------------

j21_begin "J21 is green on a compliant FFI surface"
expect J21 ok

# The rule reads the sentinel off the method chain applied to catch_unwind, not
# off any `unwrap_or` in the body. Without that, an export doing ordinary
# saturating arithmetic — which production's dns_snapshot_cache does — would be
# reported for a sentinel it never claimed.
j21_begin "J21 does not mistake unrelated arithmetic for the panic path"
j21_add_rust <<'RUST'

#[no_mangle]
pub extern "C" fn dns_count_entries(n: usize) -> c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        c_int::try_from(n).unwrap_or(c_int::MAX)
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_count_entries: panic");
        -1
    })
}
RUST
expect J21 ok

# A status code returned from inside the guarded closure is the export's own
# protocol, not the panic path. Production's SNAPSHOT_TIMED_OUT (-2) is exactly
# this shape.
j21_begin "J21 leaves an in-band status code from inside the guard alone"
j21_add_rust <<'RUST'

#[no_mangle]
pub extern "C" fn dns_snapshot_cache() -> c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| SNAPSHOT_TIMED_OUT))
        .unwrap_or_else(|_| {
            log::error!("dns_snapshot_cache: panic");
            -1
        })
}
RUST
expect J21 ok

# --- panic guard and sentinel ------------------------------------------------

j21_begin "J21 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'must catch panics and return a sentinel'
expect J21 fail "no longer in AGENTS.md"

j21_begin "J21 catches an export with no panic guard at all"
j21_add_rust <<'RUST'

#[no_mangle]
pub extern "C" fn dns_unguarded(flag: c_int) -> c_int {
    if flag == 0 {
        return 0;
    }
    1
}
RUST
expect J21 fail "dns_unguarded: no panic guard"

j21_begin "J21 catches an integer export whose panic path returns success"
j21_add_rust <<'RUST'

#[no_mangle]
pub extern "C" fn dns_wrong_int_sentinel() -> c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| 1)).unwrap_or_else(|_| {
        log::error!("dns_wrong_int_sentinel: panic");
        1
    })
}
RUST
expect J21 fail "dns_wrong_int_sentinel: panic path yields"

j21_begin "J21 catches a pointer export whose panic path is not NULL"
j21_add_rust <<'RUST'

/// Caller must release the result through `dns_allowlist_free_json`.
#[no_mangle]
pub extern "C" fn dns_wrong_ptr_sentinel() -> *mut c_char {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| std::ptr::null_mut()))
        .unwrap_or_else(|_| 1 as *mut c_char)
}
RUST
expect J21 fail "not a NULL pointer sentinel"

j21_begin "J21 catches a guard that re-raises the panic"
j21_add_rust <<'RUST'

#[no_mangle]
pub extern "C" fn dns_reraises() {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {})).unwrap()
}
RUST
expect J21 fail "re-raises the panic instead of returning a sentinel"

j21_begin "J21 catches an integer export that discards the guard result"
j21_add_rust <<'RUST'

#[no_mangle]
pub extern "C" fn dns_discards_result() -> c_int {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| 1));
    1
}
RUST
expect J21 fail "the catch_unwind result is discarded"

j21_begin "J21 catches a wrapper delegating to an unguarded function"
j21_add_rust <<'RUST'

#[no_mangle]
pub extern "C" fn dns_bad_wrapper() {
    let _ = dns_plain_helper(0);
}

fn dns_plain_helper(_v: c_int) -> c_int {
    0
}
RUST
expect J21 fail "which is not a panic-guarded export"

j21_begin "J21 refuses a return type whose sentinel it cannot judge"
j21_add_rust <<'RUST'

#[no_mangle]
pub extern "C" fn dns_returns_bool() -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| true)).unwrap_or(false)
}
RUST
expect J21 fail "unsupported FFI return type"

# --- CString ownership -------------------------------------------------------

j21_begin "J21 catches an owned allocation escaping a non-pointer export"
j21_add_rust <<'RUST'

#[no_mangle]
pub extern "C" fn dns_leaks_cstring() -> c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _escaped = CString::new("leak").unwrap().into_raw();
        1
    }))
    .unwrap_or(0)
}
RUST
expect J21 fail "leaks an owned allocation"

j21_begin "J21 catches a reclaimer that is not the matching free function"
j21_add_rust <<'RUST'

/// # Safety
/// `ptr` must come from `dns_allowlist_list`.
#[no_mangle]
pub unsafe extern "C" fn dns_release_json(ptr: *mut c_char) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = unsafe { CString::from_raw(ptr) };
    }));
}
RUST
expect J21 fail "is not a dns_*_free_* export"

j21_begin "J21 catches a free function that frees nothing"
j21_add_rust <<'RUST'

#[no_mangle]
pub unsafe extern "C" fn dns_allowlist_free_stats(_ptr: *mut c_char) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {}));
}
RUST
expect J21 fail "never calls CString::from_raw"

j21_begin "J21 catches a producer that does not declare its reclaimer"
swap "$RUSTLIB" 'must release it through' '/// The caller owns the pointer.'
expect J21 fail "does not name the dns_*_free_* function"

# --- Swift release site ------------------------------------------------------

j21_begin "J21 catches a Swift call site with no defer"
drop "$RESOLVER" 'defer { freeJson(ptr) }'
expect J21 fail "without a \`defer\` releasing the result"

j21_begin "J21 rejects a free invocation written only in a string"
swap "$RESOLVER" 'defer { freeJson(ptr) }' '        defer { print("freeJson(ptr)") }'
expect J21 fail "without a \`defer\` releasing the result"

j21_begin "J21 rejects a free alias mentioned without invoking it"
swap "$RESOLVER" 'defer { freeJson(ptr) }' '        defer { _ = freeJson }'
expect J21 fail "without a \`defer\` releasing the result"

j21_begin "J21 rejects a matching free called with a different pointer"
swap "$RESOLVER" 'defer { freeJson(ptr) }' '        defer { freeJson(otherPtr) }'
expect J21 fail "without a \`defer\` releasing the result"

j21_begin "J21 rejects a second producer result without its own release"
swap "$RESOLVER" 'let json = String(cString: ptr)' '        let otherPtr = list()'
expect J21 fail "without a \`defer\` releasing the result"

j21_begin "J21 accepts multiple results with their own matching releases"
swap "$RESOLVER" 'let json = String(cString: ptr)' '        let otherPtr = list(); defer { freeJson(otherPtr) }'
expect J21 ok

j21_begin "J21 rejects a shadowed free alias it cannot resolve"
swap "$RESOLVER" 'defer { freeJson(ptr) }' '        defer { let freeJson = unrelatedFree; freeJson(ptr) }'
expect J21 fail "alias is shadowed or reassigned"

j21_begin "J21 rejects a typed shadow of a free alias"
swap "$RESOLVER" 'defer { freeJson(ptr) }' '        defer { let freeJson: DnsAllowlistFreeJsonFn = unrelatedFree; freeJson(ptr) }'
expect J21 fail "alias is shadowed or reassigned"

j21_begin "J21 rejects a typed shadow of a producer result"
swap "$RESOLVER" 'defer { freeJson(ptr) }' '        defer { let ptr: UnsafeMutablePointer<CChar> = unrelatedPointer; freeJson(ptr) }'
expect J21 fail "alias is shadowed or reassigned"

j21_begin "J21 rejects a typed variable shadow of a free alias"
swap "$RESOLVER" 'defer { freeJson(ptr) }' '        defer { var freeJson: DnsAllowlistFreeJsonFn = unrelatedFree; freeJson(ptr) }'
expect J21 fail "alias is shadowed or reassigned"

j21_begin "J21 rejects a free property shadowed by a function parameter"
swap "$RESOLVER" 'func listAllowedDomains()' '    func listAllowedDomains(fnAllowlistFreeJson: DnsAllowlistFreeJsonFn) -> [String] {'
expect J21 fail "alias is shadowed or reassigned"

j21_begin "J21 rejects a free alias shadowed by a closure parameter"
swap "$RESOLVER" 'defer { freeJson(ptr) }' '        defer { unrelated.forEach { freeJson in freeJson(ptr) } }'
expect J21 fail "alias is shadowed or reassigned"

j21_begin "J21 rejects a nested function scope it cannot resolve"
swap "$RESOLVER" 'let json = String(cString: ptr)' '        func nested() { let otherPtr = list() }'
expect J21 fail "nested function scope"

j21_begin "J21 accepts multiple valid bindings in one file"
j21_duplicate_binding "$RESOLVER"
expect J21 ok

j21_begin "J21 checks a second producer binding in the same file"
j21_duplicate_binding "$RESOLVER"
swap_after "$RESOLVER" 'final class OtherResolverModule' 'defer { freeJson(ptr) }' '        defer { }'
expect J21 fail "without a \`defer\` releasing the result"

j21_begin "J21 rejects a second binding with its symbol on the next line"
j21_duplicate_binding "$RESOLVER"
cp "$W/$RESOLVER" "$WORK/before"
awk 'index($0, "fnOtherList = sym(") {
    print "        fnOtherList = sym("
    print "            \"dns_allowlist_list\")"
    next
} { print }' "$WORK/before" >"$W/$RESOLVER"
_changed "$RESOLVER" 'fnOtherList = sym('
expect J21 fail "unsupported sym binding"

j21_begin "J21 rejects a second binding with its opening parenthesis on the next line"
j21_duplicate_binding "$RESOLVER"
cp "$W/$RESOLVER" "$WORK/before"
awk 'index($0, "fnOtherList = sym(") {
    print "        fnOtherList = sym"
    print "            (\"dns_allowlist_list\")"
    next
} { print }' "$WORK/before" >"$W/$RESOLVER"
_changed "$RESOLVER" 'fnOtherList = sym('
expect J21 fail "unsupported sym binding"

OTHER_RESOLVER=Sources/MacDNSAgent/Services/ZDuplicateBinding.swift

j21_begin "J21 accepts valid bindings in separate files"
j21_duplicate_binding "$OTHER_RESOLVER"
expect J21 ok

j21_begin "J21 checks a second producer binding in a separate file"
j21_duplicate_binding "$OTHER_RESOLVER"
drop "$OTHER_RESOLVER" 'defer { freeJson(ptr) }'
expect J21 fail "ZDuplicateBinding.swift:"

j21_begin "J21 rejects ambiguous bindings that reuse a property name"
add "$RESOLVER" 'fnAllowlistFreeJson = sym("dns_unrelated_release")'
expect J21 fail "unsupported ambiguous sym binding"

j21_begin "J21 does not accept a commented-out second free binding"
j21_duplicate_binding "$OTHER_RESOLVER"
swap "$OTHER_RESOLVER" 'fnOtherFreeJson = sym(' '        // fnOtherFreeJson = sym("dns_allowlist_free_json")'
expect J21 fail "are not both bound as sym() properties here"

j21_begin "J21 catches a pointer released by free() instead of its free function"
swap "$RESOLVER" 'defer { freeJson(ptr) }' '        free(ptr)'
expect J21 fail "instead of dns_allowlist_free_json"

# --- positive anchors --------------------------------------------------------
#
# A rule that passes because its subject disappeared is a rule nobody is running.

j21_begin "J21 fails when Swift stops calling the producer"
swap "$RESOLVER" 'guard let list = fnAllowlistList' '        guard let list = fnAllowlistUnused, let freeJson = fnAllowlistFreeJson else {'
expect J21 fail "has lost its anchor"

j21_begin "J21 fails when the owned-C-string hand-off disappears"
swap "$RUSTLIB" 'Ok(Some(cs)) => cs.into_raw(),' '        Ok(Some(_cs)) => std::ptr::null_mut(),'
expect J21 fail "has lost its subject"

j21_begin "J21 fails when the export scanner stops matching the crate"
put "$RUSTLIB" 'fn main() {}'
expect J21 fail "no longer matches the crate"

# --- engine ------------------------------------------------------------------
#
# Both halves run through lint_awk, so a crashed scanner must surface as an
# internal error rather than as findings invented from its empty output.
j21_begin "J21 reports a crashed scanner as an error, never as a finding"
broken=$(clone_lint broken-awk-j21)
printf '\nfunction il_reserved(s, close) { return s }\n' >>"$broken/lib/awklib.awk"
expect_in "$broken" J21 error "scanner failed" "FAIL"

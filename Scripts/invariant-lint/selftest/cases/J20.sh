# J20 — the resolver dylib is opened once per agent lifetime and never released.
#
# The shared fixture has no dlopen at all, so every case lays down its own
# loader first: the cached-handle property, the idempotence guard, the single
# `dlopen`, the nested `sym` helper doing `dlsym` lookups, and a `stop()` that
# tears down state without touching the handle.
#
# NOTE for whoever edits this file: three of J18's RED cases originally passed
# green because the violating call sat alone in a one-line function and the
# delegating-wrapper shape legitimately absorbed it — the rule was right and the
# cases were wrong. Write violating code the way it would really be written.

RESOLVER=Sources/MacDNSAgent/Services/ResolverModule.swift

j20_write() {
    mkdir -p "$(dirname "$W/$1")"
    cat >"$W/$1"
}

j20_append() {
    cat >>"$W/$1"
}

j20_begin() {
    begin "$1"

    j20_write "$RESOLVER" <<'SWIFT'
import Foundation

final class ResolverModule {
    static let shared = ResolverModule()

    typealias DnsIntFn = @convention(c) () -> Int32

    private var handle: UnsafeMutableRawPointer?
    private var fnInit: DnsIntFn?
    private var fnShutdown: DnsIntFn?
    private var started = false

    private init() {}

    private var isBound: Bool {
        fnInit != nil && fnShutdown != nil
    }

    /// Resolves the dylib handle + FFI symbols. Idempotent — the handle is
    /// cached on `self`. `RTLD_NODELETE` is intentionally omitted because we
    /// never `dlclose`: the handle lives for the whole agent lifetime.
    private func load() -> Bool {
        guard handle == nil else {
            return isBound
        }
        let path = PathResolver.resolverDylib
        guard let h = dlopen(path, RTLD_LAZY | RTLD_LOCAL) else {
            let errMsg = dlerror().map { String(cString: $0) } ?? "unknown"
            AgentLogger.shared.error("dlopen failed: \(errMsg)")
            return false
        }
        handle = h
        func sym<T>(_ name: String) -> T? {
            guard let p = dlsym(h, name) else { return nil }
            return unsafeBitCast(p, to: T.self)
        }
        fnInit = sym("dns_init")
        fnShutdown = sym("dns_shutdown")
        return fnInit != nil && fnShutdown != nil
    }

    func start() -> Bool {
        guard load() else { return false }
        started = true
        return fnInit?() == 1
    }

    /// Tears down tasks and the Tokio runtime. The handle is untouched: a later
    /// `start()` reuses it.
    func stop() {
        guard started else { return }
        _ = fnShutdown?()
        started = false
    }
}
SWIFT
}

# --- green -------------------------------------------------------------------

j20_begin "J20 is green on a loader that opens once and never releases"
expect J20 ok

# The real loader logs "dlopen failed: …" on the failure path and documents in a
# comment that it never dlcloses. Both would be false positives without the
# decomment/string-blanking pass, so pin them.
j20_begin "J20 does not count dlopen or dlclose named in a comment or a log line"
j20_append "$RESOLVER" <<'SWIFT'

extension ResolverModule {
    func reportLoadFailure(path: String) {
        // Recovery is a restart: we never call dlclose(handle) to retry a load.
        AgentLogger.shared.error("dlopen(\(path)) failed; the resolver is unavailable")
    }
}
SWIFT
expect J20 ok

# Adding FFI entrypoints means more `dlsym`, which is exactly what an open
# handle is for. This rule must never make new exports look like a violation.
j20_begin "J20 stays green when new FFI symbols are looked up on the open handle"
j20_append "$RESOLVER" <<'SWIFT'

extension ResolverModule {
    func bindStatsSymbols() {
        guard let h = handle else { return }
        fnStats = unsafeBitCast(dlsym(h, "dns_get_stats"), to: DnsIntFn.self)
        fnStatsFree = unsafeBitCast(dlsym(h, "dns_stats_free"), to: DnsIntFn.self)
        fnFilteringDegraded = unsafeBitCast(dlsym(h, "dns_filtering_degraded_count"), to: DnsIntFn.self)
    }
}
SWIFT
expect J20 ok

# --- the invariant text ------------------------------------------------------

j20_begin "J20 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'loaded once per agent lifetime'
expect J20 fail "no longer in AGENTS.md"

# --- opened once -------------------------------------------------------------

j20_begin "J20 catches a second dlopen"
j20_append "$RESOLVER" <<'SWIFT'

extension ResolverModule {
    func loadFallback() -> Bool {
        guard handle == nil else { return true }
        guard let h = dlopen("/usr/local/lib/libmacdns_resolver.dylib", RTLD_LAZY) else {
            return false
        }
        handle = h
        return true
    }
}
SWIFT
expect J20 fail "call site 2 of 2"

j20_begin "J20 catches the loader losing its dlopen entirely"
swap "$RESOLVER" 'guard let h = dlopen(path, RTLD_LAZY | RTLD_LOCAL) else {' \
    '        guard let h = PathResolver.preloadedHandle(path) else {'
expect J20 fail "no \`dlopen\` call in the agent target"

# --- the handle outlives the call --------------------------------------------

j20_begin "J20 catches a handle that is not a stored property"
swap "$RESOLVER" 'private var handle: UnsafeMutableRawPointer?' \
    '    private var handleWasRemoved = true'
expect J20 fail "not a \`var\` property outliving the call"

# The binding is followed, not pattern-matched by name: storing the result in a
# local is reported as the local it is, with the reason it does not survive.
j20_begin "J20 catches a handle parked in a local that dies with the call"
swap "$RESOLVER" '        handle = h' '        let cached = h'
expect J20 fail "stored in \`cached\`, which is not a \`var\` property outliving the call"

j20_begin "J20 refuses a dlopen result binding it cannot follow"
swap "$RESOLVER" 'guard let h = dlopen(path, RTLD_LAZY | RTLD_LOCAL) else {' \
    '        guard let h = ResolverModule.wrapHandle(dlopen(path, RTLD_LAZY)) else {'
expect J20 fail "unrecognised \`dlopen\` result binding"

# --- the idempotence guard ---------------------------------------------------

j20_begin "J20 catches a loader that lost its handle-nil guard"
swap "$RESOLVER" 'guard handle == nil else {' '        if !started {'
expect J20 fail "is not preceded by a \`guard handle == nil\` early exit in load()"

# A test on the handle that does not visibly exit is not a guard. It is reported
# as unrecognised rather than accepted — J20 will not assume control flow it
# cannot see.
j20_begin "J20 refuses a handle test that does not exit early"
swap "$RESOLVER" 'guard handle == nil else {' '        if handle != nil {'
swap "$RESOLVER" '            return isBound' '            AgentLogger.shared.error("already loaded")'
expect J20 fail "unrecognised \`handle\` nil-guard shape"

# --- never released ----------------------------------------------------------

j20_begin "J20 catches a dlclose"
j20_append "$RESOLVER" <<'SWIFT'

extension ResolverModule {
    func unloadLibrary() {
        if let h = handle {
            dlclose(h)
        }
    }
}
SWIFT
expect J20 fail "\`dlclose\` in the agent target"

j20_begin "J20 catches a teardown path that clears the handle"
j20_append "$RESOLVER" <<'SWIFT'

extension ResolverModule {
    func stopAndUnload() {
        _ = fnShutdown?()
        started = false
        handle = nil
    }
}
SWIFT
expect J20 fail "\`stop()\` tears down tasks and the Tokio runtime but leaves the handle intact"

# The property is what is protected, not a method called `stop`. Clearing the
# handle from anywhere defeats the idempotence guard just as thoroughly, so the
# rule does not need the method to keep its name to keep enforcing.
j20_begin "J20 catches the handle being cleared outside any stop method"
j20_append "$RESOLVER" <<'SWIFT'

extension ResolverModule {
    func recycle() {
        _ = fnShutdown?()
        handle = nil
    }
}
SWIFT
expect J20 fail "\`handle\` is cleared in recycle()"

# --- engine ------------------------------------------------------------------

j20_begin "J20 reports a crashed scanner as an error, never as a finding"
broken=$(clone_lint broken-awk-j20)
printf '\nfunction il_reserved(s, close) { return s }\n' >>"$broken/lib/awklib.awk"
expect_in "$broken" J20 error "scanner failed" "FAIL"

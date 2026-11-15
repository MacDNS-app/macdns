# MacDNS architecture

How MacDNS is built and why. Rules an agent must follow while coding, and the paths already rejected, are in `AGENTS.md`.

## Processes

- **MacDNS** (`Sources/MacDNS`). The SwiftUI menu-bar App. It talks to the Agent over XPC (`XPCClient`) and is the only process that touches `NEDNSProxyManager`. When the Agent is unavailable it reads and writes `state.json` directly, through the same revision guard and lock, and reads `license.json`.
- **MacDNSAgent** (`Sources/MacDNSAgent`). A user LaunchAgent registered through `SMAppService.agent`, Mach service `app.macdns.agent`. It owns configuration transactions and rollback, loads the resolver and runs every service under `Services/` (blocklist, allowlist, license, updates, network).
- **DNSProxyExtension**. A system extension that captures DNS flows and sends them to the resolver's loopback listener. It also hosts the proxy-control Mach service `group.app.macdns.proxy-control`, declared as `NEMachServiceName` inside the `NetworkExtension` dictionary of its Info.plist. The prefix is an App Group from the extension's entitlements, not the Team ID, and the Agent needs the same App Group to resolve it.
- **ContentFilterExtension**. A separate system extension that blocks DoT and known DoH endpoints for other processes. It is requested only when the user turns on "Block DoT & known DoH", which is off by default, so first run never asks for two extension approvals.
- **macdns-resolver** (`rust-resolver/crates/macdns-resolver`). The DNS engine, built as `libmacdns_resolver.dylib` and loaded into the Agent with `dlopen`. It is the only resolver: no child process, no generated config files, no helper binaries. Cache, blocklist downloads, the LMDB blocklist and allowlist, and lookup history all live here, behind the FFI.
- **Shared** (`Sources/Shared`). XPC protocol, models and path resolution, linked by the App, the Agent and the tests. The extensions never import it. The Makefile builds each extension with `swiftc` over its own folder plus `Sources/SharedExtensionKit`. The proxy-control constants therefore exist twice, and tests keep the copies equal: a drift still builds and leaves protection in permanent bypass.

## IPC between the Agent and the extensions

- The DNS Proxy is the XPC server and the Agent is the client. The system extension runs as root in the global bootstrap namespace and cannot look up a service in the user's `gui/<uid>` namespace, so the Agent never hosts a service the extension connects to.
- XPC is the only channel. App Group containers resolve to different paths for root and for the user, the sandbox blocks UNIX sockets, CFMessagePort has the same namespace problem, and a localhost TCP port accepts any local process.
- Trust comes only from the mutually code-sign-validated XPC connection and the memory-only HMAC session. The Agent reads provider state on demand. Configuration and DNS traffic never travel on this channel.

## Resolution model

- MacDNS is a DoH forwarder, not a recursive resolver. The provider does the recursion, so recursive-resolver hardening (QNAME minimisation, glue hardening, unwanted-reply thresholds) does not apply.
- DNSSEC is validated by the provider, never by MacDNS. The DNSSEC toggle decides whether the provider validates. When it is on, queries leave with CD=0 and the provider answers SERVFAIL for a signature that fails. When it is off, queries leave with CD=1 (`ProviderUpstream::lookup`).
- A client that sets CD itself always gets CD=1. With the toggle on, that answer is unvalidated, so it skips the shared cache and single-flight (`client_forces_unchecked_data`).
- Local validation was rejected for latency. It measured a median of 413 ms against 8 ms without it, and `validate=true` with empty trust anchors still fetched the chain (654 to 1269 ms).
- Upstream queries always carry DO=1 and the client's DO bit is never forwarded. The cache is keyed by name and type and single-flight shares one result, so a forwarded DO would let the first client decide whether later clients get RRSIGs. `finalize_wire` decides which DNSSEC records each client receives.
- Each provider slot is a hickory `CachingClient` over a `NameServerPool`, built directly. hickory's `Resolver` ties DO to local validation, and a raw pool would mean rewriting CNAME chasing, record filtering and TTL clamping. The accepted cost: `/etc/hosts` is not read on this path and the positive TTL ceiling is one day.
- Forward zones and the stub, DHCP and captive paths never validate (`validate=false`), whatever the toggle says. Split-DNS servers return unsigned negative answers, and validating them turns them into SERVFAIL. These paths also drop RRSIGs today. Fixing that means owning `DnsRequestOptions` in `upstream_lookup`, not turning validation on.
- The address family is chosen per connection slot by ranking and family gates. There is no IPv4 or IPv6 preference setting.

## Health and captive portals

- Only a direct dispatch to the provider pool (`probe_recursive_resolution`) proves that DoH works. The loopback listener, the cache, serve-stale, forwarding and DHCP DNS never count, because stale and forwarded answers made networks that block DoH look healthy. The provider path runs hickory with `cache_size=0`, so every probe reaches the provider.
- A cleartext captive-portal probe never authorizes a full bypass, because an on-path attacker controls the HTTP result. A suspected portal gets scoped forwarding, with the DNS Proxy, the blocklist and the Content Filter still on. Full bypass needs the user's approval, is bound to the network identity and lasts 900 s from the grant. A direct-DoH failure never grants full bypass, and a failure during scoped forwarding keeps the forwarding.

## Failure planes

- Filtering fails open. An unreadable blocklist category or allowlist counts as empty and is retried with backoff. It never turns into SERVFAIL. A corrupt allowlist is never repaired or deleted automatically, because it is user data that cannot be downloaded again.
- Licensing and the proxy-control plane fail closed. Neither plane is a model for the other.

## Upgrades

- **DNS Proxy extension.** The old provider must be gone before the new one is submitted. If it still owns `group.app.macdns.proxy-control` when launchd registers the new job, launchd strips the new job's `MachServices` until reboot. So the App cancels the replacement request, disables the proxy, waits for the old process to exit and resubmits. It cannot wait inline because the delegate runs on the main queue. The provider exits after `stopProxy` behind a generation guard, and a start watchdog kills a demand-launched process that never receives `startProxy`. The update check is gated on the configuration being installed, not enabled. A bounce cannot repair a stripped job, so a drain that is not confirmed goes straight to the restart-required notice. `providerVersion` cannot drive that notice because it arrives over the dead endpoint.
- **Agent.** The Agent counts as stopped once `SMAppService.unregister()` returns. The App never probes its PID, kills it or adds a wait. Recovery is one connection reset and at most one replacement per App process, and only before authoritative startup.

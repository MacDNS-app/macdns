# DNS Rebinding Defense

**Status:** always on · **Owner:** Marcus Grando · **Last reviewed:** 2026-07-24

MacDNS strips private-space addresses out of answers that came from the public resolver path. This
document states exactly what is filtered, which legitimate setups it breaks, how a user fixes those
setups today, and why the behavior is deliberately not a `state.json` setting.

Source of truth: `rust-resolver/crates/macdns-resolver/src/rebinding.rs`, gated by
`config.rs` `BLOCK_REBINDING: bool = true`.

---

## The attack being prevented

A hostile (or hijacked) public authoritative server answers a public name with an address inside the
user's LAN — `192.168.1.1`, `127.0.0.1`, `10.x`. The browser then treats that name as same-origin
with the router admin page, the local Kubernetes API, a printer, or any service that trusts "requests
from the LAN". Same-origin policy protects origins, not IP ranges, so the DNS answer is the whole
exploit. Filtering the answer at the resolver is the standard mitigation (`dnsmasq --stop-dns-rebind`,
Unbound `private-address`, Pi-hole).

## What is filtered

`ip_is_rebindable` rejects an address when it is:

- RFC 1918 private: `10/8`, `172.16/12`, `192.168/16`
- Loopback: `127/8`, `::1`
- Link-local: `169.254/16`, `fe80::/10`
- Unspecified: `0.0.0.0`, `::`
- IPv4 broadcast: `255.255.255.255`
- RFC 6598 carrier-grade NAT: `100.64/10`
- RFC 5737 documentation (`192.0.2/24`, `198.51.100/24`, `203.0.113/24`), RFC 2544 benchmarking
  (`198.18/15`), and reserved `240/4`
- IPv6 unique-local: `fc00::/7`
- Any IPv4-mapped (`::ffff:0:0/96`), 6to4 (`2002::/16`) or NAT64 (`64:ff9b::/96`) address that embeds
  one of the blocked IPv4 ranges

Anything else — including multicast and unusual-but-routable public space — passes.

`filter_rebindable_records` then applies that predicate in the **answer, authority and additional**
sections:

- Rebindable A and AAAA records are dropped whole.
- HTTPS and SVCB records lose rebindable addresses from `ipv4hint` and `ipv6hint`. An emptied hint
  key is removed. If that key is listed in `mandatory`, the whole record is dropped to preserve the
  record's required parameters.
- Other records are untouched. A CNAME pointing at a private-resolving name survives by
  design (`filter_keeps_cname_untouched`): the client re-queries the target and the filter runs again
  on that answer, so blocking the alias would only hide the reason for the block.
- If anything was stripped, `AD` (authentic data) is cleared — the signed RRset no longer matches its
  signature.
- If every *useful* answer record was stripped, the response is rebuilt as NODATA (NOERROR + empty
  answer) and **not** cached. Orphan `RRSIG`/`NSEC`/`NSEC3`/`SIG`/`OPT` records do not count as useful,
  so a DNSSEC signature cannot keep a fully filtered answer cacheable.
- A partially filtered answer (at least one useful answer record survived) *is* cached, together with its
  EDE 17 marker.

### Where the filter runs — and where it does not

Applied (public / upstream path only):

| Site | File |
| --- | --- |
| Hedge fast path (the normal DoH answer) | `query.rs` `process_hedge_outcome` |
| Background refine winner | `query.rs` |
| Prefetch refill | `query.rs` |
| Latency-probe candidate list (never probes into private space) | `probe.rs` |
| Cache-dump restore, as defense against a tampered dump | `cache_persist.rs` `filter_rebinding_for_restore` |

Not applied — these routes are operator-configured, resolve before the public path, and are never
inserted into the shared cache:

- **DNS overrides** (exact and wildcard), answered locally from `state.json`
- **Forward zones and stub zones**, resolved through the zone's own resolver
- **Captive-portal forwarding**, while the portal route is active
- **User local zones** and built-in RFC 6303/6761/6762 special-use handling

That asymmetry *is* the remediation: private answers are legitimate exactly when the user asked for
them.

## What this breaks

### 1. Public wildcard DNS that resolves into private space

Services that encode an IP in the hostname and answer over public DNS:

- `nip.io`, `sslip.io` — `192.168.1.10.nip.io` → `192.168.1.10`
- `lvh.me`, `localtest.me`, `vcap.me` → `127.0.0.1`

Common in local web development (TLS on a real hostname, OAuth redirect URIs, multi-tenant subdomain
testing). With MacDNS these return NODATA.

### 2. Vendor hostnames that point at a LAN appliance

Public names whose whole purpose is to carry a certificate for a device on the local network:

- `*.plex.direct` — Plex direct-connect over TLS to the local server
- `routerlogin.net` (NETGEAR), and equivalent vendor admin hostnames
- Some NAS remote-access and IoT onboarding domains

These are the exact shape of a rebinding attack — a public name answering with a LAN address. The
resolver cannot tell the vendor's intent from an attacker's, so it filters both.

### 3. Split-horizon corporate DNS reached over the public path

An internal name (`intranet.corp.example`, `git.corp.example`) that the company's own resolver answers
with `10.x`, while the same zone also exists publicly. If the query goes out over MacDNS's public DoH
path instead of a configured forward zone, the private answer is stripped and the client sees NODATA.

## Working around it today

Both remediations already exist in the App and bypass the filter by design.

**Case 1 / 2 — a single name, or a wildcard, that must resolve to a fixed private address.**
Use **Overrides** (Overrides tab → Add): `Domain` = `nas.plex.direct` (or `*.plex.direct`),
`Type` = `A`, `Value` = `192.168.1.10`. Wildcards use the `*.domain` form. The override answers
locally, ahead of the public path, and is never filtered.

**Case 3 — a whole internal namespace.**
Use **Zones** (Zones tab → Add Zone): `Domain` = `corp.example`, `DNS Server` = the internal
resolver's IP (for example `10.0.0.53`). Every name under that suffix is resolved by that server and
returned untouched, including private addresses. Forward zones take precedence over built-in
special-use handling, so split DNS keeps working for `.local`-style suffixes too.

Regression coverage for the override path:
`override_private_address_survives_rebinding_filter_on_the_wire` (`lib.rs`) drives a real UDP query
through the listener and asserts a `192.168.1.10` override reaches the client verbatim.

## Diagnosing a filtered answer

Three signals exist today, in decreasing order of usefulness to a user:

1. **Agent log** (always emitted):
   `rebinding: stripped N private address records for <domain> <qtype>`
2. **EDE 17 (Filtered)** on the wire, extra text `private-address filter`, visible with
   `dig @127.0.0.1 -p <port> name +edns`. Attached both to the partially filtered answer and to the
   synthesized NODATA. **Caveat:** RFC 6891 §6.1.1 forbids sending an OPT to a client that did not
   send one, so `finalize_wire` drops the OPT — and the EDE with it — for non-EDNS clients. Those
   clients see a bare NODATA with no explanation.
3. **`rebinding_filtered` counter** in `stats.rs`. It increments per stripped address, including
   HTTPS/SVCB hints. `dns_stats_snapshot` exports it over FFI, `ResolverModule.statsSnapshot()` maps
   it to `rebindingFiltered`, and the agent includes it as `resolverStats.rebindingFiltered` in the
   `getRuntimeState` snapshot (`AgentRuntimeStateSnapshot`). The App has no display for it yet.

Without a UI surface, a user hitting case 1 or 2 above experiences "this domain just doesn't resolve
in MacDNS" and has no path from the symptom to the fix. Closing that gap is the open part of this
work (see below).

## Why this is not a `state.json` setting

`AGENTS.md` states the invariant directly: DNS rebinding defense is Rust-internal resolver policy and
stays off `state.json`. The reasoning, not just the rule:

- **A global toggle is a security downgrade with no per-case precision.** "Allow private answers from
  public DNS" is exactly the attacker's requirement. A user who flips it to make `nip.io` work leaves
  their router admin page, local dashboards and Kubernetes API exposed to every hostile answer, for
  every domain, permanently.
- **A per-domain exception list would duplicate policy that already exists.** Overrides and forward
  zones already express "this name legitimately resolves into private space", with validation,
  revision guarding and UI. A `rebindingExceptions` key would be a third way to say the same thing,
  with its own drift and its own precedence questions against the first two.
- **Rebinding scope is a property of the resolver, not of a user's preferences.** Same class as cache
  TTL bounds, RRset round-robin and the built-in special-use zones: changing it changes what "public
  answer" means, which is engineering policy, reviewed in code, not a checkbox.
- **Fail-closed matches the rest of the product.** Proxy control, licensing and the content filter all
  default to the safe state.

If a future case genuinely cannot be expressed by an override or a forward zone, the fix is to extend
those mechanisms — not to add a rebinding switch.

## Open work

**UI surface (not implemented).** `Sources/MacDNS/UI/` is owned by other work in flight, so the copy
below is specified here and still needs wiring. Proposed strings, in the App's existing English UI
voice:

- Query-log / activity row badge (per filtered answer):
  - Badge: `Private address filtered`
  - Tooltip: `This public domain answered with a private network address (192.168.1.10). MacDNS
    removed it to prevent DNS rebinding attacks.`
- Inline remediation on that row (link/button): `How to allow this domain`
- Detail panel body:
  > **Private address filtered**
  >
  > `nas.plex.direct` resolved to `192.168.1.10`, a private network address. Public DNS should never
  > answer with an address inside your local network, so MacDNS removed it — this is the standard
  > defense against DNS rebinding attacks.
  >
  > If this domain is supposed to point at a device on your network, tell MacDNS about it explicitly:
  >
  > - **One hostname:** add an Override — Domain `nas.plex.direct`, Type `A`,
  >   Value `192.168.1.10`.
  > - **A whole internal domain** (for example your company network): add a Zone — Domain
  >   `corp.example`, DNS Server the address of the DNS server that serves it.
  >
  > Overrides and Zones are answered directly and are never filtered.
  - Buttons: `Add Override…` / `Add Zone…` (prefilled with the observed domain and address)
- General tab / diagnostics counter label: `Private addresses filtered` with secondary text
  `Answers from public DNS that pointed into your local network.`
- Deliberately **absent**: any enable/disable control for the filter.

Wiring that copy still requires:

1. Connect the diagnostics display to the existing `resolverStats.rebindingFiltered` runtime field.
   The per-query badge also needs the domain, address and filtering reason shown in the proposed copy.
2. A forward-zone regression test asserting that a private answer from a configured forward zone is
   returned unfiltered. It cannot live in `lib.rs`: forward targets are dialed on port 53
   (`NameServerConfig::udp_and_tcp(ip)` in `zones.rs`), which an unprivileged test cannot bind. It
   belongs in `query.rs`'s `stub_state` harness, driving a `PrePublicRoute::ForwardZone` answer that
   carries `10.0.0.5` and asserting the record survives. The override half of the remediation is
   already covered end-to-end (see above).

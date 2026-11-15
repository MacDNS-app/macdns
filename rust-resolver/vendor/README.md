# Hickory transport patches

These are copies of the published Hickory DNS 0.26.3 packages, selected with
`[patch.crates-io]` in the workspace manifest. The resolver keeps its existing
Hickory pool, exchange, TLS verification and HTTP/2 implementation. No replacement
connection pool or new production dependency is introduced.

## Provenance

Upstream: https://github.com/hickory-dns/hickory-dns

| Package | Original crates.io archive SHA-256 |
| --- | --- |
| `hickory-net` 0.26.3 | `c480823ed7c2c5d0f09c41020cb6b7c28029ce60ec42dc942158dcf22f8e0a4d` |
| `hickory-resolver` 0.26.3 | `3f3da5255c95d5a716857d54b5b8f4e8d67c3484d3beaaaae2ce25063b3ba981` |

The checksums were recorded from the application lockfile before applying the
path overrides. Each package retains its original `Cargo.toml.orig`,
`.cargo_vcs_info.json`, README, and MIT and Apache-2.0 licenses. Its original
package lockfile is retained as provenance and is not used by the app build.

## Local changes

- `hickory-net/src/h2.rs` preserves the typed HTTP/2 error when its driver stops,
  and reports a non-2xx HTTP status as the typed `NetError::HttpStatus` instead
  of a string carrying the response body. A response carrying an HTTP `Age`
  header has every DNS TTL, and the SOA MINIMUM, reduced by that age
  (RFC 8484 section 5.1). Response bodies return each DATA frame's
  flow-control credit as it is read (RFC 9113 section 6.9), instead of only
  when the stream ends.
- `hickory-net/src/xfer/dns_exchange.rs` closes the request queue and returns the
  observed driver error to queued requests before shutting down.
- `hickory-net/src/xfer/mod.rs` distinguishes a disconnected exchange from a busy
  queue. If no driver cause is available, a stopped exchange reports
  `Io(NotConnected)`. Dropping a caller's response does not close the exchange.
- `hickory-resolver/src/name_server.rs` serializes establishment and rechecks the
  pool after acquiring the guard. Reusable connections and multiplexed requests
  remain available while another transport establishes. One recoverable closure
  can be retried within the same pool, including a closure immediately after a
  successful handshake. A late successful response cannot revive failed state.
  A non-2xx HTTP status leaves the connection established: the exchange
  completed, so the next query reuses it instead of paying a handshake.
- `hickory-resolver/src/name_server_pool.rs` prevents the initial `NoConnections`
  sentinel from hiding an observed I/O error after recovery is exhausted.
- `hickory-net/src/error.rs` adds `NoRecords::cname_chain`, and
  `hickory-resolver/src/caching_client.rs` treats a response that carries the
  CNAME chain and an SOA as the terminal negative (RFC 2308 section 2). The
  chain travels in that field instead of being dropped, and the target is not
  queried a second time. A chain assembled from several responses keeps the
  RRSIG of each RRset, is marked AD only if every contributing response was
  (RFC 4035 section 3.2.3), and a negative reached through it carries the
  chain as well.
- `hickory-net/src/error.rs` keeps a server's Extended DNS Error options
  (RFC 8914) as `ExtendedErrors`, carried by `DnsError::ResponseCode` and
  `NoRecords::extended_errors`. Only option code 15 is kept, at most
  `MAX_EXTENDED_ERRORS` of them, each at most `MAX_EXTENDED_ERROR_LEN` bytes.
  `hickory-net/src/lib.rs` re-exports `ExtendedErrors` and both limits.
- `hickory-resolver/src/name_server.rs` and `hickory-resolver/src/recursor/handle.rs`
  call the atomic `try_update` instead of the deprecated `fetch_update`, so
  `hickory-resolver/Cargo.toml` raises its `rust-version` from 1.88 to 1.95.

The single reconnect budget belongs to Hickory. MacDNS does not add another
transport resend. Its original caller deadline wraps connection establishment
and both sends. Certificate, HTTP, DNS and timeout failures do not receive a
connection-closure retry.

## License

Both packages are licensed MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`),
and the local changes are released under the same terms. Each changed file
starts with a notice saying it was modified for MacDNS. `REUSE.toml` at the
repository root records the upstream copyright for every file in both packages.

## Validation and maintenance

`tests/transport.rs` is included by the application test build and runs in
`make ci`, using the application's existing dev dependencies:

```sh
cd rust-resolver
cargo test --locked --lib hickory_transport_tests -- --test-threads=1
cargo test --locked --lib doh_repro -- --test-threads=1
```

The first suite covers queued errors, driver and caller cancellation, bounded
recovery, concurrent establishment, a surviving sibling, and failure-state
races. The production-stack reproducer additionally exercises real TCP, TLS
and HTTP/2 closure behavior. Published package unit tests depend on unpublished
upstream test-support code, so they are not the local validation entry point.

Path dependencies have no registry source or archive checksum in `Cargo.lock`.
`make security-rust` creates a temporary audit-only copy of the current lockfile
with registry origins for these two packages, so `cargo audit` also checks their
pinned upstream versions. The build lockfile remains unchanged. Audit findings
cover upstream versions, while the local patch still requires code review.
Transitive dependencies remain pinned and covered by the same audit.

When upgrading Hickory, compare the changed files against the published source
and rerun both regression suites. Remove the path overrides and vendored copies
when a published version passes these regressions with the same behavior.

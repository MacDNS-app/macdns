# DNS Blocking and Search Domains

MacDNS uses NULL blocking by default. Blocked A and AAAA queries receive a successful DNS response
containing an unspecified address. This removes the negative A/AAAA response that triggers search
fallback in affected clients, reducing disclosure of blocked hostnames to resolvers for search
domains. Other query types and client behavior can still cause search expansion.

## Why NXDOMAIN caused hostname disclosure

A search list is applied by the client, before MacDNS sees the next query. Depending on the client,
search expansion can apply to names containing several labels, not only short names such as `nas`.
For example, with `tail123.ts.net` and `corp.example` in the search list:

1. A client queries `collector.github.com`.
2. A blocklist matches it. An NXDOMAIN blocking response says the name does not exist.
3. The client tries `collector.github.com.tail123.ts.net` and potentially
   `collector.github.com.corp.example`.
4. These are different DNS names. A configured forward zone can send them to another resolver,
   disclosing `collector.github.com` to that DNS infrastructure.

The resulting upstream error can obscure the cause. For example, a Tailscale forwarder without an
upstream for unknown names can return SERVFAIL for the expanded name. Changing forwarding rules
does not address the original negative response that triggered the retry.

## Responses for blocked names

The `"null"` action is a JSON string, not JSON `null` and not DNS record type NULL.

| Query type | Response code | Answer |
| --- | --- | --- |
| A | NOERROR | `0.0.0.0` |
| AAAA | NOERROR | `::` |
| HTTPS, SVCB, and all other types | NOERROR | No answer records (NODATA), with an SOA |

Address answers retain the existing blocking TTL of zero. NODATA retains the resolver's bounded
synthetic negative TTL. Responses are produced locally before public resolution, DNS64 synthesis,
and public-answer rebinding filtering. They are not marked as DNSSEC authenticated.

Unspecified addresses do not guarantee a failed connection. On macOS, a client connecting to
`0.0.0.0` or `::` can reach a listener on `127.0.0.1` or `::1` at the same port. That local service
can receive the blocked hostname through HTTP Host or TLS SNI. This is a tradeoff of NULL blocking.

An allowlist match still takes precedence over a blocklist match. Explicit `localhost` and custom IP
actions retain their behavior. Genuine NXDOMAIN responses from upstream DNS and local-zone policy
are unchanged. An unlisted single-label name such as `nas` follows normal resolution. If it receives
NXDOMAIN, the client can still try `nas` with its search suffixes. NULL answers apply only after a
blocklist match. MacDNS does not strip suffixes from incoming names, because a suffixed name can
be a legitimate hostname in a private zone.

## Client-dependent limits

NULL blocking removes the negative address response that triggers search fallback in affected
clients. It does not disable the client's search list or guarantee that every client stops searching.

- Chromium's built-in DNS resolver can append search suffixes to multi-label names after NXDOMAIN.
  Its DNS transaction stops on NOERROR, including NODATA.
- An isolated macOS `res_nsearch` probe with an explicit search list continued after NXDOMAIN and
  NODATA for A, AAAA, and HTTPS. NULL A and AAAA answers stopped that search. HTTPS NODATA still
  triggered expansion in that libc path.
- A separate native macOS DNS-SD lookup did not reproduce multi-label expansion. The original
  application's resolver path was not identified conclusively.

Clients can also query suffixed names first or issue independent lookups. Preventing all search
disclosure requires control of the client's search configuration or use of an absolute DNS name
ending in `.` where the application supports it. NULL blocking reduces disclosure caused by
blocking responses. It does not provide that broader guarantee.

## Existing installations and rollback

New categories and category-level changes use `"null"`. Every agent bootstrap normalizes category
actions equal to `"nxdomain"` to `"null"`, case-insensitively, including disabled categories. This
has no one-time migration marker.
Reintroducing `"nxdomain"` in an App category causes it to be rewritten at the next bootstrap.
Custom addresses and `"localhost"` are preserved.

Migration uses the existing `state.json` file lock, configuration revision increment, and transactional
projection writer. `state.json` remains authoritative. The scheduler's `blocklist_settings.json` is
regenerated from it. A later bootstrap does not increment the revision again once migration is
complete, unless a category has been changed back to `"nxdomain"`. Blocklist databases and normal
LMDB hot reload are unchanged.

The lower-level Rust runtime configuration still accepts an explicit `"nxdomain"` action. MacDNS
App categories do not retain that action across agent bootstrap.

Older builds cannot parse `"null"`. Downgrading with the blocklist enabled causes blocklist
configuration to fail, and the older agent stops its DNS services. The unchanged schema version
does not prevent that downgrade. MacDNS does not create a pre-upgrade backup automatically.

For a planned downgrade, turn off the blocklist in the current build before installing the older
build. Keep it disabled until the category actions are compatible. With the blocklist disabled, the
older resolver skips parsing category actions, so its DNS services can start without filtering.

To keep filtering enabled, or recover after a downgrade that already failed:

1. Turn DNS off in MacDNS and wait for the services to stop.
2. Choose **Quit and Remove Services**. This stops and unregisters the agent. **Quit MacDNS** only
   closes the App and leaves the agent running. Confirm the agent is no longer registered:
   `launchctl print "gui/$(id -u)/app.macdns.agent"` must report that the service cannot be found.
   If it still exists, do not edit the configuration yet.
3. Save a manual copy of `~/Library/Application Support/MacDNS/state.json` before editing it.
4. In that file, change only `blocklist.categories[].action` values equal to `"null"` back to
   `"nxdomain"`. Preserve custom addresses and `"localhost"`.
5. Install and open the older build, then turn DNS on. Registering the older agent runs its
   bootstrap, which regenerates `blocklist_settings.json` from `state.json` before services start.

The agent uses launchd `KeepAlive`, so killing its process or closing the App is insufficient.
Unregistering it prevents automatic restart during the edit. Do not open the newer build between
editing and starting the older agent, because the newer agent normalizes the actions to `"null"`.

Restoring a pre-upgrade `state.json` backup is also possible if one was saved manually. Editing or
restoring only the derived `blocklist_settings.json` is insufficient.

## References

- [Pi-hole blocking modes](https://docs.pi-hole.net/ftldns/blockingmode/), including its recommended
  NULL mode and NXDOMAIN/NODATA alternatives.
- [Chromium DNS transaction](https://github.com/chromium/chromium/blob/main/net/dns/dns_transaction.cc),
  `PrepareSearch` and the NXDOMAIN fallback in `ProcessAttemptResult`.
- [Chromium UDP DNS attempt](https://github.com/chromium/chromium/blob/main/net/dns/dns_udp_attempt.cc),
  response-code handling in `DoReadResponseComplete`.

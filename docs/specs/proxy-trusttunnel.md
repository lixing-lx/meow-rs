# TrustTunnel H2 outbound contribution candidate

Tracking proposal: [#727](https://github.com/meow-rs/meow-rs/issues/727).
The H2-only scope and runtime/test integration follow the maintainer's
[feedback](https://github.com/meow-rs/meow-rs/issues/727#issuecomment-5964286689).
Default-profile inclusion remains a separate measured decision.

The client protocol follows the [public specification](https://github.com/TrustTunnel/TrustTunnel/blob/master/PROTOCOL.md).
Configuration is compared with [Mihomo's adapter](https://github.com/MetaCubeX/mihomo/blob/Alpha/adapter/outbound/trusttunnel.go)
and [pool policy](https://github.com/MetaCubeX/mihomo/blob/Alpha/transport/trusttunnel/client.go).

## Build and configuration

`trusttunnel` is an opt-in feature in `meow-proxy`, `meow-config` and
`meow-app`. Existing `full` and `minimal` profile contents are unchanged
pending upstream's feature/profile decision.

```sh
cargo run -p meow-app --features trusttunnel -- -f config.yaml -t
```

```yaml
proxies:
  - name: TrustTunnel
    type: trusttunnel
    server: vpn.example.com
    port: 443
    username: your-user
    password: your-password
    sni: vpn.example.com
    quic: false
    udp: true
    skip-cert-verify: false
    max-connections: 8
    min-streams: 5
rules:
  - MATCH,TrustTunnel
```

Absent or all-zero pool fields use Mihomo's 8 connections / 5 active
streams threshold. Each pool field is applied independently: a positive
`max-connections` no longer zeroes the `min-streams` default, and a positive
`max-streams` is honoured as the per-connection ceiling rather than being
discarded. `max-streams` alone still selects Mihomo's legacy mode (below);
alongside either other field it is just the ceiling, and it is always raised
to at least `min-streams` so the two cannot contradict each other. `udp`,
`quic`, `health-check` and `skip-cert-verify`
default to false. Optional YAML nulls use these defaults; null/empty
unsupported policy declarations are inert. Nonempty unsupported policies
still fail explicitly. `sni` defaults to the server. Null or empty ALPN
lists default to `h2`; an explicit incompatible nonempty list is rejected.

An unavailable TT feature, malformed TT node, or unsupported TT policy must
not be silently dropped: a group that lists the name would otherwise shift
that traffic onto a sibling member, or — once no member survives — degrade
to a direct dial, which is the plaintext leak this closes. So the name stays
bound, to a permanently dead placeholder
([`UnavailableAdapter`](../../crates/meow-proxy/src/unavailable.rs)) whose
every dial fails naming the node and the reason. Runtime rebuilds and
provider payloads apply the same rule.

The damage is deliberately scoped to the node rather than the enclosing
`proxies:` block or provider payload. Rejecting the payload closes the same
hole, but it also fires for a protocol the running binary simply does not
contain — every official `full` release is built without
`--features trusttunnel`, and no edit the operator can make to their config
repairs that — and on a third-party provider payload, refetched on a timer,
it would hand that payload's operator a daemon-wide kill switch. This
follows the existing `MALFORMED_DIALER_PREFIX` precedent in `meow-config`:
the node loads, the dial fails. `strict` remains the opt-in that *does*
reject the payload, because there the operator has asked for every defect to
be fatal.

Because no payload-level gate remains, provider acquisition keeps its
pre-existing shape: the first fetch is spawned detached, both at startup
(after the listeners are up) and on an API commit, where an awaited download
would serialize every other commit behind one slow or blackholed provider
URL inside the `CONFIG_MUTATION` lane (issue #533). Offline `-t` still
validates provider declarations without fetching remote payloads, and
transient fetch failures retain existing offline-bootstrap behavior.

## Runtime boundaries

- TLS uses the existing BoringSSL transport and pluggable dialer; the
  protocol module creates no sockets. Shared physical sessions dial with
  `internal: false`, matching other pooled adapters: a session opened by
  housekeeping can later serve user streams without a new physical dial.
  This records front-group use so lazy probing remains active during reuse.
- Authenticated CONNECT multiplexes TCP, `_check`, and `_udp2` over H2.
  TCP writes respect flow control, support half-close, and reset unfinished
  streams on drop. A GOAWAY retires admission while successful streams drain;
  the dial then re-elects another pooled connection or dials a fresh one, so
  a routine server-side recycle is not a user-visible failure. That retry is
  safe because nothing had been written — the "no automatic replay" rule
  below covers a request that reached the peer, not one that never left.
- No application request or payload is automatically replayed. Authentication
  failure retires its session. Reset invalidates in-flight pool creation.
- Per-pool connections are capped at 16, per-session stream counts at 512,
  and UDP associations at 128. The effective per-connection ceiling is the
  lesser of the configured one and the peer's acknowledged
  `SETTINGS_MAX_CONCURRENT_STREAMS`, sampled from the connection driver:
  h2 reports that value only on the connection handle, and `poll_ready` on a
  fresh `SendRequest` answers `Ready` whatever the limit says, so without the
  sample a dial onto a connection already at the peer's limit would queue a
  pending-open stream and park until its whole deadline expired instead of
  taking a sibling connection. Official v1.1.0 send payloads are limited to
  65,434 bytes with an empty App Name; receive payloads accept 65,508 bytes
  (36-byte header plus 65,508 = 65,544 frame bytes, excluding the length prefix).
  These are different peer bounds, not a common IPv4 packet maximum.
  UDP send queues hold 32 frames; receive
  queues hold 16 per association with a shared 4 MiB receive-payload budget.
  Slow consumers can consume the shared budget and cause other associations'
  packets to drop. Budget and unmatched-reply drops are counted and logged
  at powers of two; reader/writer failures are logged before mux teardown.
  A short caller receive buffer consumes and truncates one datagram,
  matching the existing packet-connection convention.
  The outbound queue is separate: at most 32 frames (~2 MiB at maximum
  payload), plus one writer frame and one bounded reader frame. H2 also
  send buffers up to 128 KiB per TCP stream (128 MiB at default pool limits,
  up to 1 GiB at the hard limits); there is no global TCP buffer budget.
  Explicit pool/association admission pressure is a local resource error,
  preserving healthy group members while normal socket EAGAIN keeps its
  existing classification. Typed admission markers survive io/context/relay
  boundaries without being classified as errno-backed: multi-candidate
  error precedence retains its original errno-versus-context policy.
- UDP application-name fields are empty; actual process names are not sent,
  and neither is the client's own address: each association mints its own
  wire source tuple (unspecified address, per-association virtual port), so
  a LAN client's source IP and port are never disclosed to the endpoint
  operator. The tuple's only job is reply demultiplexing, which uniqueness
  alone satisfies.
  The fixed HTTP User-Agent `meow/<version>` identifies the client/version
  on TCP, `_udp2` and `_check`. This differs from the public spec/Mihomo
  per-stream OS user agents (`<os> _udp2` and `<os>` for `_check`); no
  fingerprint parity is claimed. The outer CONNECT deadline covers pool
  admission, TLS/H2 setup, `_check` and the requested CONNECT, with no
  second equal-duration health-check timer.
- A send larger than the endpoint's 65,434-byte limit is counted, logged at
  powers of two, and dropped — not reported as a write error, because
  `handle_udp` evicts the NAT entry on any `write_packet` failure and one
  jumbo datagram from one application must not tear down every flow sharing
  the association.
- Reply dispatch requires the reply Destination tuple to match the virtual
  source assigned to its association. Official v1.1.0 echoes this tuple.
  An endpoint that zeroes it cannot multiplex replies unambiguously; such
  replies are counted/dropped rather than guessed or broadcast. The public
  wire spec names the field without defining dispatch semantics, so this
  compatibility requirement is explicit and zero-destination endpoints
  have no interoperability claim.
- ICMP and H3 are outside this first contribution candidate.

## Intentional divergences (ADR-0002)

| Case | Class | Behavior and reason |
| --- | :---: | --- |
| `quic: true` and QUIC tuning fields | A | Explicit configuration error; this H2-only contribution cannot apply the requested transport. |
| Certificate pinning, client certificate/key, ECH, custom CA YAML fields, curve preferences | A | Explicit error naming the requested policy; these fields are not yet wired into this parser. |
| ALPN containing additional protocols | A | Requires exactly `[h2]` so the adapter cannot negotiate a different transport. |
| Mihomo's legacy unbounded pool mode (`max-streams` alone) | B | Warn with effective limits: 16 connections and `max-streams` as the spread threshold (`min-streams`), per-connection ceiling `max(128, max-streams)`, hard ceiling 512; overload returns a typed local admission error. |
| Explicit pool limits beyond the above bounds | B | Configuration error explaining invalid pool limits; no silent clamp. |
| `health-check: true` | B | Warn and check newly opened sessions only; Mihomo additionally checks idle sessions periodically. |
| Official v1.1.0 UDP `::1` decoding | A | The peer interprets this wire address as `0.0.0.1`; real-peer tests use IPv6-encoded mapped loopback. Global IPv6 interoperability remains unverified. |
| Empty or overlong credentials, username containing `:` | A | Explicit error; prevents ambiguous Basic authentication or unbounded credential headers. Credentials are never included in diagnostics. |

## Dependencies and checks

This candidate retains upstream's locked `h2 0.4.16`; the protocol feature
adds no package to `Cargo.lock` and does not change the existing version
range. The empty-DATA interoperability difference in 0.4.19 is discussed
separately with a standalone h2 reproducer in
[h2 #964](https://github.com/hyperium/h2/issues/964) and
[meow-rs #732](https://github.com/meow-rs/meow-rs/issues/732). Tests cover valid interspersed
empty DATA and an empty-frame flood without disabling flood protection.

```sh
cargo test -p meow-proxy --no-default-features --features trusttunnel --lib trusttunnel
cargo test -p meow-proxy --no-default-features --features trusttunnel --test trusttunnel_integration
cargo test -p meow-proxy --no-default-features --features trusttunnel --test trusttunnel_e2e
cargo test -p meow-config --features trusttunnel --test trusttunnel_config_test
cargo test -p meow-config --no-default-features --test trusttunnel_config_test
cargo test -p meow-api --features meow-config/trusttunnel --test api_test trusttunnel_provider
```

Tests use in-memory H2 peers and self-signed loopback TLS fixtures. The TLS
fixtures explicitly install their generated CA and include certificate/name
failure paths asserting actual X509 verification results. Non-TLS/socket
failures are separately checked not to be classified as certificate failures.
Tests also cover front-group use when internal TCP/UDP opens a session later
reused by user traffic, unchecked-session admission during a pending health
check, process-name privacy, pool saturation without dead-marking,
shared receive-budget drops/recovery, and a length guard independent of EOF;
examples retain normal certificate verification. The full
regression bar in `CONTRIBUTING.md` / `CLAUDE.md` is additionally required
before committing or pushing a contribution.

`trusttunnel_e2e` launches the official v1.1.0 endpoint and verifies H2 TCP,
IPv4 and IPv6-encoded mapped UDP, `_check`, shared connections, half-close,
certificate/auth rejection, slow-writer isolation, reset, and concurrent payload integrity.
Run `bash scripts/fetch-trusttunnel-endpoint.sh /tmp/meow-tt-peer` and set
`TRUSTTUNNEL_SERVER_BIN=/tmp/meow-tt-peer/trusttunnel_endpoint`. The missing
binary is a failure, not an ignored test. Only local runs may opt into
`MEOW_TRUSTTUNNEL_E2E_ALLOW_SKIP=1`; it is rejected when `CI` is set. CI
fetches the pinned official archive and verifies SHA-256 before every run.

The official v1.1.0 peer decodes UDP `::1` as zero-padded `0.0.0.1`, unlike
the current public specification's loopback exception. The real-peer fixture
therefore exercises IPv6 wire encoding with `::ffff:127.0.0.1`; generic IPv6
and the `::1` exception are additionally covered by the hermetic wire test.
This is not a claim of a real-peer global-IPv6 network-path test.

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
streams threshold. `udp`, `quic`, `health-check` and `skip-cert-verify`
default to false. Optional YAML nulls use these defaults; null/empty
unsupported policy declarations are inert. Nonempty unsupported policies
still fail explicitly. `sni` defaults to the server. Null or empty ALPN
lists default to `h2`; an explicit incompatible nonempty list is rejected. Positive `max-connections`
takes precedence over legacy `max-streams`, matching Mihomo.

An unavailable TT feature, malformed TT node, or unsupported TT policy fails
the containing configuration even in lenient mode. Runtime rebuilds apply
the same rule. Provider refreshes reject the complete payload and retain
the last-good generation; fetched invalid TT nodes also reject initial load.
New or changed runtime providers are acquired against the candidate route
registry before DNS, routing, or raw configuration is published. Typed TT
errors reject the entire mutation even under `force`, retaining the running
generation. Deferred startup acquisition finishes before listeners start.
Offline `-t` still validates provider declarations without fetching remote
payloads, and transient fetch failures retain existing offline-bootstrap
behavior.

## Runtime boundaries

- TLS uses the existing BoringSSL transport and pluggable dialer; the
  protocol module creates no sockets. Internal dial metadata is preserved.
- Authenticated CONNECT multiplexes TCP, `_check`, and `_udp2` over H2.
  TCP writes respect flow control, support half-close, and reset unfinished
  streams on drop. A GOAWAY retires admission while successful streams drain.
- No application request or payload is automatically replayed. Authentication
  failure retires its session. Reset invalidates in-flight pool creation.
- Per-pool connections are capped at 16, per-session stream counts at 512,
  and UDP associations at 128. UDP send queues hold 32 frames; receive
  queues hold 16 per association with a shared 4 MiB receive-payload budget.
  Slow consumers can consume the shared budget and cause other associations'
  packets to drop. Budget drops are counted and logged at powers of two.
  The outbound queue is separate: at most 32 frames (~2 MiB at maximum
  payload), plus one writer frame and one bounded reader frame. H2 also
  send buffers up to 128 KiB per TCP stream (128 MiB at default pool limits,
  up to 1 GiB at the hard limits); there is no global TCP buffer budget.
  Explicit pool/association admission pressure is a local resource error,
  preserving healthy group members while normal socket EAGAIN keeps its
  existing classification.
- UDP application-name fields are empty; actual process names are not sent.
  The fixed HTTP User-Agent `meow/<version>` does identify the client/version.
- ICMP and H3 are outside this first contribution candidate.

## Intentional divergences (ADR-0002)

| Case | Class | Behavior and reason |
| --- | :---: | --- |
| `quic: true` and QUIC tuning fields | A | Explicit configuration error; this H2-only contribution cannot apply the requested transport. |
| Certificate pinning, client certificate/key, ECH, custom CA YAML fields, curve preferences | A | Explicit error naming the requested policy; these fields are not yet wired into this parser. |
| ALPN containing additional protocols | A | Requires exactly `[h2]` so the adapter cannot negotiate a different transport. |
| Mihomo's legacy unbounded pool mode | B | Warn with effective limits: 16 connections and `max(128, max-streams)` streams per connection (hard ceiling 512); overload returns a typed local admission error. |
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
Tests also cover process-name privacy, pool saturation without dead-marking,
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

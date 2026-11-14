# Initial Plan

A minimal wstunnel-like tool in Go. One binary (`gotunnel`) with two subcommands. All tunneling runs over WebSocket (binary frames = raw TCP bytes). Designed to sit behind a reverse proxy (Caddy/Nginx) on the server side — the server itself speaks plain `ws://` on a local TCP listener (loopback by default) and TLS termination is the proxy's job.

## Decisions made

| Topic | Decision |
|---|---|
| Tunnel model | **One WebSocket per tunneled connection** — no multiplexing (Option A) |
| Server destination | Client-specified per connection; server constrains via optional allowlist |
| Auth | Custom header `X-Gotunnel-Key`, constant-time compared server-side |
| SSH ProxyCommand mode | **stdio mode** — client bridges stdin/stdout to the tunnel |
| HTTP proxy mode | **CONNECT + plain HTTP** (absolute-URI forwarding) |
| Destination signal | First WebSocket message after the upgrade (`host`, `host:port` or `[v6]:port`; nothing in the URL or headers); server replies with a single `ok` message **after** dialing the target, or sends the failure reason + close frame |
| Config | YAML file for server, CLI flags for client |
| Binary layout | Single binary with `server` and `client` subcommands |
| Insecure transport | **Not supported.** Client accepts only `wss://`; server listens on a local TCP address (default `localhost:2345`, for a reverse proxy) |

## Repository layout

```
gotunnel/
├── go.mod
├── cmd/gotunnel/main.go        # subcommand dispatch only
├── internal/config/config.go   # YAML loading, validation, env expansion
├── internal/server/server.go   # WS server: auth, allowlist, dial, pump
├── internal/client/
│   ├── client.go               # WS dial, auth header, reconnection helpers
│   ├── httpproxy.go            # local HTTP proxy (CONNECT + absolute-URI)
│   └── stdio.go                # ssh ProxyCommand mode
└── internal/tunnel/
    └── tunnel.go               # shared framing constants + copy loop
```

## Protocol design

### Handshake (client → server)

- `GET /ws`
- Headers: `X-Gotunnel-Key: <key>` (constant-time compared on the server). Nothing else travels in the HTTP request: the destination is deliberately kept out of the URL and headers, so request-line and header logging at the reverse proxy cannot leak it.

### After upgrade

- The client's **first message** is a binary message holding the destination address: `host`, `host:port` or `[v6-host]:port` (default port 80 when omitted).
- The server validates it against the optional `allow` list **before dialing** — an invalid or not-allowed destination fails fast (reason message + close frame, no dial attempt). Otherwise it dials the target and replies with one message only after the connection is up: `ok` on success, or the failure reason (`upstream dial failed: <cause>`) followed by a close frame (`StatusPolicyViolation`). `client.Dial` waits for that message, so a failed tunnel setup fails synchronously with a readable error; a successful ack means the tunnel is fully established. The client handshake timeout must exceed the server's `dial_timeout`. If the client never sends the destination, the server closes the tunnel after ~5 s with the same failure treatment.
- The WebSocket then becomes a **transparent byte pipe** — every subsequent binary message is forwarded to/from the dialed TCP connection.
- **One WS per proxied connection** (locked-in decision): no multiplexing. The HTTP proxy opens a new WS per `CONNECT` and per plain-HTTP request; each ssh session opens its own WS. This keeps the tunnel layer dramatically simpler than wstunnel's mux protocol. Trade-off accepted: ~1 extra handshake RTT per tunnel, more server-side FDs for chatty workloads; failure semantics stay trivial (WS close = TCP close).
- Message size: chunked reads (32 KiB) so a single WS frame never buffers a whole TCP stream.
- Control close: on tunnel error, the server sends a close frame with a short reason; the client closes the local socket. Ping/pong keepalives (~30 s) to survive idle proxy timeouts.

### Destination dialing

- Host parsed strictly — no scheme, no path. If no port is given, defaults to 80.
- IP-literal and hostname forms are accepted; the allowlist decides whether the destination is permitted.

## Server behavior

- Loads one YAML config:
  - `listen` (default `localhost:2345`) — TCP `host:port` address to listen on
  - `key`
  - optional `allow` — list of glob patterns matched against `host:port` / `host:*` (e.g. `*.internal.example:22`)
  - optional timeouts/limits: dial timeout, per-connection idle timeout, max concurrent tunnels
- Auth: reject non-matching key before the upgrade completes (constant-time compare; identical error for missing vs. wrong key to avoid oracle behavior).
- Allowlist: if `allow` is present, reject non-matching destinations with a close frame after the upgrade; if absent, any destination is allowed. (The check necessarily happens after the upgrade, since the destination arrives in the first message — this also avoids a 403-based destination oracle.)
- Connects to the destination only **after** the WS upgrade succeeds; if dialing fails, sends a failure-reason message followed by a close frame.
- Listens on a local **TCP address** (`host:port` from `listen`). It defaults to `localhost:2345`, so only same-host processes can reach it; anything other than a loopback address exposes the endpoint beyond localhost, where the shared key remains the access control.
- No logging of key or destination hosts at info level (debug level only).

## Client behavior

**Shared:**
- Dials `wss://<server>/ws`, sets the key header, sends the destination as the first post-upgrade message and waits for the server's single ack (sent after the upstream dial; a failure reason arrives instead and ends the handshake with an error).
- Only `wss://` URLs are accepted — any other scheme is a hard startup error. No `--insecure` flag, no fallback, no warning-then-continue. Enforced in the shared dialer so both modes inherit it.

**Mode 1 — HTTP proxy (`gotunnel client --mode http --listen 127.0.0.1:3128`):**
- `CONNECT host:port` → opens a tunnel to that destination, then raw bidirectional copy. Handles the full HTTP/1.1 CONNECT flow (100 Continue response, then binary copy).
- Plain-HTTP proxying: absolute-URI requests (`GET http://example.com/ HTTP/1.1`) → opens a tunnel to `host:80`, forwards raw request bytes verbatim, copies the response back. One tunnel per request for simplicity (no cross-request framing).
- No SOCKS in v1 (CONNECT covers browsers, curl, and ssh's `nc`-style ProxyCommand).

**Mode 2 — ssh ProxyCommand (`gotunnel client --mode ssh --url ... --host myserver:22`):**
- Bridges `os.Stdin` ↔ WS and `os.Stdout` ↔ WS.
- Usage: `ssh -o ProxyCommand='gotunnel client --mode ssh --url wss://srv/ws --host 10.0.0.5:22 ...' user@myserver`
- Stderr stays free for diagnostics (ssh surfaces it as ProxyCommand output).

## Security considerations

- Key compared with `crypto/subtle.ConstantTimeCompare`.
- TLS is the reverse proxy's responsibility; the client only ever speaks `wss://` to it.
- The tunnel destination never crosses the HTTP layer: it travels as the first message on the (TLS-protected) WebSocket stream, so request-line logging, header logging or inspection at the reverse proxy cannot reveal it.
- The server listens on a local TCP address (loopback by default, `localhost:2345`); non-loopback `listen` addresses must be behind a reverse proxy, and whoever reaches the listener still needs the shared key.
- Destination allowlist prevents using the server as an open port-scanner/relay from the internet.
- Per-tunnel dial timeout to prevent slow-dial resource exhaustion.
- No logging of the key or destination hosts at info level (only at debug).

## Dependencies

- `github.com/coder/websocket` (formerly `nhooyr.io/websocket`) — lightweight, maintained, works with `net/http` upgrade.
- `gopkg.in/yaml.v3` — config parsing.
- stdlib for everything else. No gorilla, no muxer.

## Implementation order

1. `tunnel` package: bidirectional copy loop (WS ↔ `net.Conn` / `io.Reader`/`io.Writer`) with close-frame propagation.
2. `server`: config load → auth → dest validation/allowlist (fail fast) → dial → ack → pump. Integration test using `httptest` + a loopback TCP echo.
3. `client/stdio`: simplest end-to-end path; test with `nc` on both ends.
4. `client/httpproxy`: CONNECT first, then absolute-URI forwarding.
5. `main.go` subcommands + flag parsing + README with Caddy example (`reverse_proxy /ws* localhost:2345`) and ssh config example.

## Out of scope (v1)

- Stream multiplexing over a single WS (may be added later via `hashicorp/yamux` if high-latency many-tunnel workloads demand it)
- TLS on the server itself (assumes a reverse proxy is always in front)
- SOCKS5
- UDP/QUIC forwarding
- Auto-reconnect loops for long-lived tunnels (ssh/http-proxy sessions reconnect naturally per-connection)
- Windows service handling beyond basic signal handling

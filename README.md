# gotunnel

A minimal [wstunnel](https://github.com/erebe/wstunnel)-like tool in Go.
It tunnels TCP connections over WebSockets and is designed to sit behind
a reverse proxy (Caddy, Nginx, ...) that terminates TLS. The server
listens on a local TCP address (loopback by default), it never speaks
TLS itself, and the client only ever speaks `wss://`.

Design principles: one WebSocket carries one tunneled TCP connection —
no multiplexing, no re-encoding. A tunnel is a transparent byte pipe.

## Features

- **WebSocket transport** over any reverse proxy.
- **Shared security key**, sent in the `X-Gotunnel-Key` header and
  compared in constant time.
- **One YAML config per server instance**: TCP listen address, key,
  optional destination allowlist, timeouts, concurrency limit.
- **Client mode `http`**: a local HTTP proxy supporting `CONNECT` and
  plain-HTTP absolute-URI requests.
- **Client mode `ssh`**: bridges stdin/stdout for use as an ssh
  `ProxyCommand`.
- **Destinations never cross the HTTP layer**: the tunnel target is
  sent as the first message after the WebSocket upgrade, keeping it out
  of request URLs, headers and access logs.

## Build

    go build -o gotunnel ./cmd/gotunnel

## Server

`server.yaml`:

```yaml
listen: localhost:2345
key: change-me-long-random
# Optional: restrict destinations (glob patterns on host:port).
# Not set = any destination allowed. Explicit empty list = nothing allowed.
allow:
  - "*.internal.example:22"
  - "db.local:*"
dial_timeout: 10s
# idle_timeout: 5m        # close tunnels idle for this long (off by default)
# max_concurrent: 100     # limit concurrent tunnels (unlimited by default)
```

`${VAR}` references in the file are expanded from the environment, so
the key can come from a secret store instead of the file.

`listen` is the TCP `host:port` address the server listens on. It
defaults to `localhost:2345`, so only processes on the same host can
reach the server. Anything other than a loopback address in `listen`
exposes the endpoint beyond localhost — keep it behind a reverse proxy
and rely on the shared key for access control.

Run it (it must sit behind a reverse proxy, which connects over TCP):

    gotunnel server --config server.yaml

### Caddy

```
tunnel.example.com {
    reverse_proxy /ws* localhost:2345
}
```

## Client

The client accepts only `wss://` URLs. The security key can be passed
with `--key` or the `GOTUNNEL_KEY` environment variable.

### Protocol

After the upgrade, the client sends exactly one binary message holding
the tunnel destination (`host`, `host:port` or `[v6-host]:port`; the
port defaults to 80 when omitted). The server validates it against its
optional `allow` list **before** dialing: an invalid or not-allowed
destination is rejected immediately with the reason. Otherwise it dials
the target and replies with a single message only once the connection
is up: `ok` on success, or the failure reason followed by a close
frame (`destination not allowed`, `upstream dial failed: ...`). The
remaining messages are then relayed as a transparent byte pipe.

Because the client's dial waits for that message, a rejected or
undialable destination fails synchronously with a readable error (the
HTTP proxy answers `502 <reason>`; ssh ProxyCommand prints it on
stderr). The handshake therefore includes the upstream dial:
`--connect-timeout` (default 30s) must exceed the server's
`dial_timeout` (default 10s).

### HTTP proxy mode

    gotunnel client \
        --url wss://tunnel.example.com/ws \
        --key change-me-long-random \
        --mode http \
        --listen 127.0.0.1:3128

Use it like any HTTP proxy:

    curl -x http://127.0.0.1:3128 https://ifconfig.me   # via CONNECT
    curl -x http://127.0.0.1:3128 http://ifconfig.me    # via absolute-URI

### ssh ProxyCommand mode

    gotunnel client \
        --url wss://tunnel.example.com/ws \
        --key change-me-long-random \
        --mode ssh \
        --host 10.0.0.5:22

Configure ssh:

```
Host bastion
    ProxyCommand gotunnel client --url wss://tunnel.example.com/ws --mode ssh --host 10.0.0.5:22 --key %k
```

(In practice keep the key in `GOTUNNEL_KEY` rather than `%k` so it does
not appear in `ps` output.)

## Notes and limits

- Every proxied connection opens its own WebSocket; multiplexing is
  intentionally out of scope.
- Plain-HTTP (absolute-URI) requests are buffered up to 10 MiB before
  forwarding (`MaxBufferedBody`); use `CONNECT` for anything larger.
- The client participates in a 30 s ping keepalive so reverse proxies
  do not drop idle tunnels. During a tunnel handshake the server is
  busy dialing the target and nothing flows yet; keep `dial_timeout`
  modest if the reverse proxy in front has a short idle timeout.
- Tunnel destinations are sent as the first message on the WebSocket
  after the upgrade, so they never appear in the request URL, request
  headers, or reverse-proxy access logs.

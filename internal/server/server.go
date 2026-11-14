package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"

	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"gotunnel/internal/config"
	"gotunnel/internal/dest"
	"gotunnel/internal/tunnel"
)

const (
	// destWait bounds how long the server waits for each handshake
	// message (key, then destination) after the upgrade; clients send
	// them immediately.
	destWait = 5 * time.Second
	// ackWait bounds the server's own control writes (ack/rejection)
	// before the pump starts.
	ackWait = 5 * time.Second
)

// errUnauthorized is the only rejection surfaced before the client
// proves the shared key: a missing, wrong or malformed key message is
// indistinguishable from the outside.
var errUnauthorized = errors.New("unauthorized")

// Server is a gotunnel server: it authenticates WebSocket clients,
// enforces the destination allowlist and relays each tunnel (one
// WebSocket per connection) to its destination.
type Server struct {
	cfg     config.ServerConfig
	keyHash [sha256.Size]byte
	conns   atomic.Int64
}

// New creates a Server.
func New(cfg config.ServerConfig) (*Server, error) {
	if cfg.Key == "" {
		return nil, errors.New("server: key is required")
	}
	s := &Server{cfg: cfg}
	s.keyHash = sha256.Sum256([]byte(cfg.Key))
	return s, nil
}

// Handler returns the http.Handler serving the WebSocket endpoint.
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if max := s.cfg.MaxConcurrent; max > 0 && s.conns.Load() >= int64(max) {
		http.Error(w, "too many concurrent tunnels", http.StatusServiceUnavailable)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Clients are not browsers; the shared key, sent as the first
		// WebSocket message, is the authentication mechanism, so skip
		// the origin check.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	s.conns.Add(1)
	defer s.conns.Add(-1)

	if err := s.readKey(conn); err != nil {
		s.reject(conn, err)
		return
	}

	host, port, err := s.readDest(conn)
	if err == nil && !s.destAllowed(host, port) {
		err = errors.New("destination not allowed")
	}
	if err != nil {
		// Fail fast: no dial attempt for a rejected destination.
		s.reject(conn, err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialer := &net.Dialer{Timeout: time.Duration(s.cfg.DialTimeout)}
	target, err := dialer.DialContext(ctx, "tcp", dest.Join(host, port))
	if err != nil {
		s.reject(conn, fmt.Errorf("upstream dial failed: %w", err))
		return
	}
	defer target.Close()

	// The single ack goes out only once the target connection is up,
	// so client.Dial returns with a fully established tunnel.
	actx, acancel := context.WithTimeout(context.Background(), ackWait)
	defer acancel()
	if err := conn.Write(actx, websocket.MessageBinary, []byte(tunnel.AckOK)); err != nil {
		conn.Close(websocket.StatusInternalError, "ack write failed")
		return
	}

	ac := newActivityConn(target)
	if idle := time.Duration(s.cfg.IdleTimeout); idle > 0 {
		go s.watchIdle(ctx, ac, conn, idle)
	}
	tunnel.Pump(ctx, conn, ac)
}

// authOK compares the presented key against the configured one in
// constant time (both sides are hashed first so timing does not depend
// on the key length).
func (s *Server) authOK(presented string) bool {
	sum := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(sum[:], s.keyHash[:]) == 1
}

// readKey waits for the first post-upgrade message and checks it
// against the shared key. Every failure — a missing, wrong, malformed
// or non-binary message, or a client that never speaks — yields the
// same opaque errUnauthorized.
func (s *Server) readKey(conn *websocket.Conn) error {
	// A client that never sends the key gets the same opaque
	// rejection; closing from a timer (instead of canceling the read
	// context) keeps the close handshake intact.
	t := time.AfterFunc(destWait, func() { s.reject(conn, errUnauthorized) })
	defer t.Stop()

	typ, data, err := conn.Read(context.Background())
	if err != nil || typ != websocket.MessageBinary || !s.authOK(string(data)) {
		return errUnauthorized
	}
	return nil
}

// readDest reads the tunnel destination from the second post-upgrade
// message (the first carries the key), so neither ever crosses the
// HTTP layer (no query params, no headers).
func (s *Server) readDest(conn *websocket.Conn) (host string, port int, err error) {
	// An authenticated client that never sends the destination
	// message gets the same rejection treatment (reason message +
	// close frame); closing from a timer keeps the close handshake
	// intact.
	t := time.AfterFunc(destWait, func() {
		s.reject(conn, errors.New("destination message not received"))
	})
	defer t.Stop()

	typ, data, err := conn.Read(context.Background())
	if err != nil {
		return "", 0, fmt.Errorf("read destination: %w", err)
	}
	if typ != websocket.MessageBinary {
		return "", 0, errors.New("destination message is not binary")
	}
	return dest.ParseAddress(string(data), 80)
}

// reject informs the client that the tunnel was not established (a
// rejected destination or a failed upstream dial): one binary message
// carrying the reason, then a close frame with the same error.
func (s *Server) reject(conn *websocket.Conn, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), ackWait)
	defer cancel()
	_ = conn.Write(ctx, websocket.MessageBinary, []byte(err.Error()))
	_ = conn.Close(websocket.StatusPolicyViolation, closeReason(err))
}

// closeReason renders err as a WebSocket close reason (capped well
// below the 123-byte limit of the close frame).
func closeReason(err error) string {
	r := err.Error()
	if len(r) > 100 {
		r = r[:100]
	}
	return r
}

// destAllowed checks the allowlist. A nil Allow (not configured)
// permits everything; a configured empty list permits nothing.
func (s *Server) destAllowed(host string, port int) bool {
	if s.cfg.Allow == nil {
		return true
	}
	target := strings.ToLower(fmt.Sprintf("%s:%d", host, port))
	for _, pattern := range s.cfg.Allow {
		if ok, _ := path.Match(strings.ToLower(pattern), target); ok {
			return true
		}
	}
	return false
}

// watchIdle closes the tunnel when no traffic has crossed the
// destination connection for longer than idle.
func (s *Server) watchIdle(ctx context.Context, ac *activityConn, conn *websocket.Conn, idle time.Duration) {
	interval := idle / 2
	if interval <= 0 {
		interval = idle
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if time.Since(ac.lastActivity()) > idle {
				conn.Close(websocket.StatusGoingAway, "idle timeout")
				return
			}
		}
	}
}

// activityConn wraps a net.Conn, recording the time of the last byte
// transferred in either direction.
type activityConn struct {
	net.Conn
	last atomic.Int64
}

func newActivityConn(c net.Conn) *activityConn {
	ac := &activityConn{Conn: c}
	ac.touch()
	return ac
}

func (c *activityConn) touch() { c.last.Store(time.Now().UnixNano()) }

func (c *activityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.touch()
	return n, err
}

func (c *activityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.touch()
	return n, err
}

func (c *activityConn) lastActivity() time.Time { return time.Unix(0, c.last.Load()) }

package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"gotunnel/internal/config"
	"gotunnel/internal/handshake"
	"gotunnel/internal/tunnel"
)

// echoTarget starts a TCP echo server used as the tunnel destination.
func echoTarget(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

// newTestServer starts the server handler behind httptest and returns
// its ws:// URL.
func newTestServer(t *testing.T, cfg config.ServerConfig) string {
	t.Helper()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return "ws" + strings.TrimPrefix(ts.URL, "http")
}

// dialTunnel performs the WebSocket handshake and the tunnel
// handshake: the single signed message carries the destination, signed
// with the given key (an empty key and address sends nothing). It
// returns the first message the server sends — the ack on success, or
// the rejection reason.
func dialTunnel(t *testing.T, url, key, address string) (*websocket.Conn, []byte, error) {
	t.Helper()
	// Wide enough for a missing-handshake-message test, where the
	// server only gives up on the message after destWait.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return nil, nil, err
	}
	if key != "" && address != "" {
		host, portStr, _ := strings.Cut(address, ":")
		port, _ := strconv.Atoi(portStr)
		data, _ := json.Marshal(handshake.Sign(host, port, key))
		if err := conn.Write(ctx, websocket.MessageBinary, data); err != nil {
			_ = conn.CloseNow()
			return conn, nil, err
		}
	}
	_, ack, err := conn.Read(ctx)
	if err != nil {
		return conn, nil, err
	}
	return conn, ack, nil
}

// dialRaw performs the WebSocket handshake and sends payload verbatim
// as the first (and only) message. It returns the first message the
// server sends.
func dialRaw(t *testing.T, url, payload string) (*websocket.Conn, []byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		return nil, nil, err
	}
	if payload != "" {
		if err := conn.Write(ctx, websocket.MessageBinary, []byte(payload)); err != nil {
			_ = conn.CloseNow()
			return conn, nil, err
		}
	}
	_, ack, err := conn.Read(ctx)
	if err != nil {
		return conn, nil, err
	}
	return conn, ack, nil
}

// readClose reads until the server's close frame arrives and returns
// its code and reason.
func readClose(t *testing.T, conn *websocket.Conn) websocket.CloseError {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		_, _, err := conn.Read(ctx)
		if err == nil {
			continue // skip any data frames before the close
		}
		var ce websocket.CloseError
		if !errors.As(err, &ce) {
			t.Fatalf("expected a close frame, got %v", err)
		}
		return ce
	}
}

// expectClose reads from conn until the server's close frame arrives
// and returns its status and reason.
func expectClose(t *testing.T, conn *websocket.Conn) (websocket.StatusCode, string) {
	t.Helper()
	// The server may take up to destWait to give up on the
	// destination message before sending its close frame.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for {
		_, _, err := conn.Read(ctx)
		if err == nil {
			continue // skip any data frames before the close
		}
		var ce websocket.CloseError
		if !errors.As(err, &ce) {
			t.Fatalf("expected a close frame, got %v", err)
		}
		return ce.Code, ce.Reason
	}
}

func TestEndToEndEcho(t *testing.T) {
	host, port := echoTarget(t)
	url := newTestServer(t, config.ServerConfig{Key: "secret"})

	conn, ack, err := dialTunnel(t, url, "secret", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	if string(ack) != tunnel.AckOK {
		t.Fatalf("expected ack %q, got %q", tunnel.AckOK, ack)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("hello tunnel")); err != nil {
		t.Fatalf("write: %v", err)
	}
	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if typ != websocket.MessageBinary || string(data) != "hello tunnel" {
		t.Fatalf("got (%v, %q)", typ, data)
	}
}

func TestBadKeyRejected(t *testing.T) {
	url := newTestServer(t, config.ServerConfig{Key: "secret"})

	// The upgrade succeeds; a message signed with the wrong key
	// yields the same opaque rejection as a missing one, followed by
	// a close frame.
	conn, ack, err := dialTunnel(t, url, "wrong", "127.0.0.1:80")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()
	if string(ack) != "unauthorized" {
		t.Fatalf("expected %q, got %q", "unauthorized", ack)
	}
	if ce := readClose(t, conn); ce.Code != websocket.StatusPolicyViolation {
		t.Fatalf("expected close status %d, got %d", websocket.StatusPolicyViolation, ce.Code)
	}
}

func TestMissingMessageRejected(t *testing.T) {
	url := newTestServer(t, config.ServerConfig{Key: "secret"})

	// No handshake message at all: same opaque rejection as a
	// wrongly signed one.
	conn, ack, err := dialTunnel(t, url, "", "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()
	if string(ack) != "unauthorized" {
		t.Fatalf("expected %q, got %q", "unauthorized", ack)
	}
	if ce := readClose(t, conn); ce.Code != websocket.StatusPolicyViolation {
		t.Fatalf("expected close status %d, got %d", websocket.StatusPolicyViolation, ce.Code)
	}
}

func TestMalformedMessageRejected(t *testing.T) {
	for name, payload := range map[string]string{
		"garbage bytes": "\x00\x01",
		"not json":      "127.0.0.1:80",
		"bad sig":       `{"v":1,"host":"127.0.0.1","port":80,"sig":"` + strings.Repeat("0", 64) + `"}`,
		"not hex":       `{"v":1,"host":"127.0.0.1","port":80,"sig":"zz"}`,
		"wrong version": `{"v":99,"host":"127.0.0.1","port":80,"sig":"` + strings.Repeat("0", 64) + `"}`,
	} {
		url := newTestServer(t, config.ServerConfig{Key: "secret"})
		conn, ack, err := dialRaw(t, url, payload)
		if err != nil {
			t.Fatalf("%s: dial: %v", name, err)
		}
		if string(ack) != "unauthorized" {
			t.Errorf("%s: expected %q, got %q", name, "unauthorized", ack)
		}
		if ce := readClose(t, conn); ce.Code != websocket.StatusPolicyViolation {
			t.Errorf("%s: expected close status %d, got %d", name, websocket.StatusPolicyViolation, ce.Code)
		}
		conn.CloseNow()
	}
}

func TestDialFailureReported(t *testing.T) {
	// Reserve a port, then release it: dialing it is refused quickly.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	url := newTestServer(t, config.ServerConfig{Key: "secret"})
	conn, ack, err := dialTunnel(t, url, "secret", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()

	// The reason is a single message naming the dial failure,
	// followed by a close frame.
	if string(ack) == tunnel.AckOK {
		t.Fatal("expected a failure reason, got the success ack")
	}
	if !strings.HasPrefix(string(ack), "upstream dial failed: ") {
		t.Fatalf("expected dial failure reason, got %q", ack)
	}
	if ce := readClose(t, conn); ce.Code != websocket.StatusPolicyViolation {
		t.Fatalf("expected close status %d, got %d", websocket.StatusPolicyViolation, ce.Code)
	}
}

func TestAllowlist(t *testing.T) {
	host, port := echoTarget(t)
	url := newTestServer(t, config.ServerConfig{
		Key:   "secret",
		Allow: []string{"*.example.com:*"},
	})

	// Not matching the allowlist -> rejection message + close frame.
	conn, ack, err := dialTunnel(t, url, "secret", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()
	if string(ack) != "destination not allowed" {
		t.Fatalf("expected rejection message, got %q", ack)
	}
	if ce := readClose(t, conn); ce.Code != websocket.StatusPolicyViolation {
		t.Fatalf("expected close status %d, got %d", websocket.StatusPolicyViolation, ce.Code)
	}

	// Matching the allowlist -> tunnel works.
	url2 := newTestServer(t, config.ServerConfig{
		Key:   "secret",
		Allow: []string{"127.0.0.1:*"},
	})
	conn2, ack2, err := dialTunnel(t, url2, "secret", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn2.Close(websocket.StatusNormalClosure, "")
	if string(ack2) != tunnel.AckOK {
		t.Fatalf("expected ack %q, got %q", tunnel.AckOK, ack2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn2.Write(ctx, websocket.MessageBinary, []byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := conn2.Read(ctx); err != nil {
		t.Fatalf("read: %v", err)
	}
}

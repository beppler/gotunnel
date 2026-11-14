package tunnel

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// newWSServer serves f over an httptest server: each dialed connection
// is upgraded to a WebSocket and handed to f.
func newWSServer(t *testing.T, f func(ctx context.Context, conn *websocket.Conn)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		f(r.Context(), conn)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPumpEcho(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	served := make(chan error, 1)
	srv := newWSServer(t, func(ctx context.Context, conn *websocket.Conn) {
		served <- Pump(ctx, conn, serverSide)
	})
	url := "ws" + srv.URL[len("http"):]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// WS -> pipe.
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	clientSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(clientSide, buf); err != nil {
		t.Fatalf("pipe read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("pipe got %q", buf)
	}

	// pipe -> WS.
	clientSide.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientSide.Write([]byte("pong")); err != nil {
		t.Fatalf("pipe write: %v", err)
	}
	typ, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}
	if typ != websocket.MessageBinary || string(data) != "pong" {
		t.Fatalf("ws got (%v, %q)", typ, data)
	}

	// Closing the pipe ends the tunnel cleanly. The client must take
	// part in the WebSocket close handshake (its conn.Close replies to
	// the server's close frame), otherwise the server's Close waits
	// the full 5s handshake timeout.
	clientSide.Close()
	go conn.Close(websocket.StatusNormalClosure, "")
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("pump error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pump did not return after pipe close")
	}
}

func TestDrainUntilServerCloses(t *testing.T) {
	srv := newWSServer(t, func(ctx context.Context, conn *websocket.Conn) {
		_ = conn.Write(ctx, websocket.MessageBinary, []byte("chunk1"))
		_ = conn.Write(ctx, websocket.MessageBinary, []byte("chunk2"))
		conn.Close(websocket.StatusNormalClosure, "")
	})
	url := "ws" + srv.URL[len("http"):]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	var out []byte
	done := make(chan error, 1)
	go func() {
		_, err := Drain(ctx, conn, &byteWriter{&out})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("drain: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not return")
	}
	if string(out) != "chunk1chunk2" {
		t.Fatalf("drained %q", out)
	}
}

// byteWriter is a tiny append writer.
type byteWriter struct{ p *[]byte }

func (w *byteWriter) Write(p []byte) (int, error) {
	*w.p = append(*w.p, p...)
	return len(p), nil
}

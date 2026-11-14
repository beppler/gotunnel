// Package tunnel moves bytes between a WebSocket connection and a
// duplex byte stream. The WebSocket is a transparent byte pipe: binary
// messages carry raw stream bytes, one message per read chunk.
package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/coder/websocket"
)

// ChunkSize is the maximum number of stream bytes carried in a single
// WebSocket message.
const ChunkSize = 32 * 1024

// AckOK is the message the server sends on a fresh tunnel once the
// destination is accepted and the upstream target is dialed. Any other
// server message received at that point carries the reason the tunnel
// was not established, and is followed by a close frame.
const AckOK = "ok"

// drainGrace bounds how long Pump waits for the second direction to
// unwind after the first one finished. It exists so tunnels backed by
// unclosable streams (e.g. stdin) still terminate promptly.
var drainGrace = 2 * time.Second

// wsReader turns a WebSocket connection into an io.Reader spanning
// consecutive binary messages. Non-binary messages are drained and
// ignored. A closed WebSocket reads as EOF; the close frame's error is
// recorded in closeErr for callers that want the peer's close status.
type wsReader struct {
	ctx      context.Context
	conn     *websocket.Conn
	msg      io.Reader
	closeErr error
}

func (r *wsReader) Read(p []byte) (int, error) {
	for {
		if r.msg == nil {
			typ, msg, err := r.conn.Reader(r.ctx)
			if err != nil {
				if websocket.CloseStatus(err) != -1 {
					r.closeErr = err
					return 0, io.EOF
				}
				return 0, err
			}
			if typ != websocket.MessageBinary {
				_, _ = io.Copy(io.Discard, msg)
				continue
			}
			r.msg = msg
		}
		n, err := r.msg.Read(p)
		if n > 0 {
			if errors.Is(err, io.EOF) {
				r.msg = nil
				return n, nil
			}
			return n, err
		}
		if errors.Is(err, io.EOF) {
			r.msg = nil
			continue
		}
		if err != nil {
			return 0, err
		}
	}
}

// copyToWS copies a stream into the WebSocket as binary messages.
func copyToWS(ctx context.Context, conn *websocket.Conn, r io.Reader) error {
	buf := make([]byte, ChunkSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if werr := conn.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// Pump copies bidirectionally between conn and target. It returns the
// first error encountered (nil for clean termination) and always closes
// both conn and target before returning.
func Pump(ctx context.Context, conn *websocket.Conn, target io.ReadWriteCloser) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, &wsReader{ctx: ctx, conn: conn})
		errCh <- err
	}()
	go func() {
		errCh <- copyToWS(ctx, conn, target)
	}()

	first := <-errCh
	cancel()
	_ = conn.Close(websocket.StatusNormalClosure, "")
	_ = target.Close()

	var second error
	select {
	case second = <-errCh:
	case <-time.After(drainGrace):
	}

	return normalize(first, second)
}

// Drain reads binary messages from conn until the WebSocket closes,
// writing everything to w. It returns the number of bytes written and,
// when the peer closed with a status other than 1000 (normal), the
// peer's CloseError.
func Drain(ctx context.Context, conn *websocket.Conn, w io.Writer) (int64, error) {
	r := &wsReader{ctx: ctx, conn: conn}
	written, err := io.Copy(w, r)
	if err == nil {
		if r.closeErr != nil && websocket.CloseStatus(r.closeErr) != websocket.StatusNormalClosure {
			err = r.closeErr
		}
	} else if errors.Is(err, io.EOF) {
		err = nil
	}
	return written, err
}

// normalize collapses termination errors into nil; anything that is
// just the consequence of tearing a tunnel down is not a real failure.
func normalize(first, second error) error {
	err := first
	if err == nil {
		err = second
	}
	if err == nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, net.ErrClosed) ||
		websocket.CloseStatus(err) != -1 {
		return nil
	}
	return err
}

// Package handshake carries the tunnel handshake between client and
// server: a single binary WebSocket message right after the upgrade
// holding the destination and an HMAC-SHA256 signature over it, keyed
// by the shared key. The key itself never crosses the wire.
package handshake

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"go.beppler.dev.br/gotunnel/internal/dest"
)

// Version is the protocol version of the handshake message; the
// server rejects messages carrying any other value.
const Version = 1

// Message is the single post-upgrade handshake message. The signature
// covers the canonical "host:port" address; the version rides
// alongside unsigned (a future version would change the payload
// format anyway).
type Message struct {
	Version int    `json:"v"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Sig     string `json:"sig"`
}

// Sign builds the handshake message for a destination: hex
// HMAC-SHA256 of the canonical host:port address, keyed by the shared
// key.
func Sign(host string, port int, key string) Message {
	return Message{
		Version: Version,
		Host:    host,
		Port:    port,
		Sig:     hex.EncodeToString(mac(host, port, key)),
	}
}

// Verify parses and authenticates a handshake message: the JSON must
// carry the current version and a signature matching the destination
// under the shared key. It returns the authenticated destination.
func Verify(data []byte, key string) (host string, port int, err error) {
	var m Message
	if err := json.Unmarshal(data, &m); err != nil {
		return "", 0, fmt.Errorf("decode handshake message: %w", err)
	}
	if m.Version != Version {
		return "", 0, fmt.Errorf("unsupported handshake version %d", m.Version)
	}
	want, err := hex.DecodeString(m.Sig)
	if err != nil {
		return "", 0, errors.New("handshake signature is not hex")
	}
	if !hmac.Equal(want, mac(m.Host, m.Port, key)) {
		return "", 0, errors.New("handshake signature mismatch")
	}
	return m.Host, m.Port, nil
}

// mac computes the HMAC-SHA256 over the canonical host:port address.
func mac(host string, port int, key string) []byte {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(dest.Join(host, port)))
	return m.Sum(nil)
}

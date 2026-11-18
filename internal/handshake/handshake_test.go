package handshake

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const key = "secret"

func TestSignVerifyRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		host string
		port int
	}{
		{"127.0.0.1", 80},
		{"example.com", 443},
		{"::1", 22}, // bare IPv6 literal host
	} {
		data, err := json.Marshal(Sign(tc.host, tc.port, key))
		if err != nil {
			t.Fatalf("marshal %s:%d: %v", tc.host, tc.port, err)
		}
		host, port, err := Verify(data, key)
		if err != nil {
			t.Fatalf("verify %s:%d: %v", tc.host, tc.port, err)
		}
		if host != tc.host || port != tc.port {
			t.Fatalf("got %s:%d, want %s:%d", host, port, tc.host, tc.port)
		}
	}
}

func TestVerifyWrongKey(t *testing.T) {
	data, _ := json.Marshal(Sign("example.com", 80, key))
	if _, _, err := Verify(data, "wrong"); err == nil {
		t.Fatal("expected a signature mismatch with the wrong key")
	}
}

func TestVerifyTampered(t *testing.T) {
	data, _ := json.Marshal(Sign("example.com", 80, key))

	var m Message
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Message){
		"host":    func(m *Message) { m.Host = "evil.com" },
		"port":    func(m *Message) { m.Port = 8080 },
		"version": func(m *Message) { m.Version = Version + 1 },
		"ts":      func(m *Message) { m.TS++ },
		"sig":     func(m *Message) { m.Sig = strings.Repeat("0", 64) },
	} {
		tampered := m
		mutate(&tampered)
		data, _ := json.Marshal(tampered)
		if _, _, err := Verify(data, key); err == nil {
			t.Errorf("%s: expected verification to fail", name)
		}
	}
}

func TestVerifyMalformed(t *testing.T) {
	for name, data := range map[string]string{
		"not json":    "\x00\x01",
		"empty":       "",
		"not hex":     `{"v":1,"host":"h","port":80,"ts":1,"sig":"zz"}`,
		"no version":  `{"host":"h","port":80,"sig":"` + strings.Repeat("0", 64) + `"}`,
		"missing sig": `{"v":1,"host":"h","port":80}`,
	} {
		if _, _, err := Verify([]byte(data), key); err == nil {
			t.Errorf("%s: expected verification to fail", name)
		}
	}
}

func TestVerifyStaleTimestamp(t *testing.T) {
	now := time.Now().Unix()
	for name, ts := range map[string]int64{
		"too old":       now - 61,
		"too far ahead": now + 61,
	} {
		data, _ := json.Marshal(signAt("example.com", 80, key, ts))
		if _, _, err := Verify(data, key); err == nil {
			t.Errorf("%s: expected verification to fail", name)
		}
	}
	// Inside the ±maxSkew window the message verifies.
	for _, ts := range []int64{now - 59, now, now + 59} {
		data, _ := json.Marshal(signAt("example.com", 80, key, ts))
		if _, _, err := Verify(data, key); err != nil {
			t.Errorf("ts %d: expected verification to succeed: %v", ts, err)
		}
	}
}

// The signature must bind the destination it was made for: a sig over
// one canonical host:port must not verify for a different host or
// port. (Tampering a signed message is covered by TestVerifyTampered;
// malformed hosts are the server's ParseAddress concern, not Verify's.)
func TestSignBindsDestination(t *testing.T) {
	m := Sign("example.com", 80, key)
	otherHost := Sign("evil.com", 80, key)
	otherPort := Sign("example.com", 81, key)
	if m.Sig == otherHost.Sig || m.Sig == otherPort.Sig {
		t.Fatal("a signature must not verify for a different destination")
	}
}

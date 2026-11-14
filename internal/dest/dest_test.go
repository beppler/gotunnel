package dest

import "testing"

func TestParseAddress(t *testing.T) {
	tests := []struct {
		in   string
		def  int
		host string
		port int
		ok   bool
	}{
		{in: "example.com:22", def: 80, host: "example.com", port: 22, ok: true},
		{in: "example.com", def: 80, host: "example.com", port: 80, ok: true},
		{in: "example.com:", def: 80, host: "example.com", port: 80, ok: true},
		{in: "[::1]:22", def: 80, host: "::1", port: 22, ok: true},
		{in: "::1", def: 80, host: "::1", port: 80, ok: true},
		{in: "127.0.0.1:99999", def: 80, ok: false},
		{in: "a/b:22", def: 80, ok: false},
		{in: "not an host:22", def: 80, ok: false},
		{in: "[::1]", def: 80, ok: false},                   // bare bracketed form is not a valid host
		{in: "host:22:33", def: 80, ok: false},              // not host:port, not an IP literal
		{in: string(make([]byte, 300)), def: 80, ok: false}, // too long
	}
	for _, tt := range tests {
		host, port, err := ParseAddress(tt.in, tt.def)
		if tt.ok {
			if err != nil {
				t.Errorf("ParseAddress(%q): unexpected error %v", tt.in, err)
				continue
			}
			if host != tt.host || port != tt.port {
				t.Errorf("ParseAddress(%q) = (%q, %d), want (%q, %d)", tt.in, host, port, tt.host, tt.port)
			}
			continue
		}
		if err == nil {
			t.Errorf("ParseAddress(%q): expected error, got (%q, %d)", tt.in, host, port)
		}
	}
}

func TestJoinRoundTrip(t *testing.T) {
	for _, tt := range []struct {
		host string
		port int
	}{
		{"example.com", 22},
		{"::1", 80},
		{"127.0.0.1", 1},
	} {
		addr := Join(tt.host, tt.port)
		host, port, err := ParseAddress(addr, 80)
		if err != nil {
			t.Errorf("ParseAddress(%q): %v", addr, err)
			continue
		}
		if host != tt.host || port != tt.port {
			t.Errorf("ParseAddress(%q) = (%q, %d), want (%q, %d)", addr, host, port, tt.host, tt.port)
		}
	}
}

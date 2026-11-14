// Package dest holds helpers shared by client and server for
// representing tunnel destinations.
package dest

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ValidateHost checks that host is a bare hostname or IP literal
// without scheme, path, port or credentials.
func ValidateHost(host string) error {
	if host == "" {
		return errors.New("empty destination host")
	}
	if len(host) > 253 {
		return fmt.Errorf("destination host %q too long", host)
	}
	if strings.ContainsAny(host, " \t\r\n/\\?#%@[]") {
		return fmt.Errorf("invalid destination host %q", host)
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return fmt.Errorf("invalid destination host %q", host)
	}
	return nil
}

// ParsePort parses a decimal port, falling back to def when empty.
func ParsePort(s string, def int) (int, error) {
	if s == "" {
		return def, nil
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return p, nil
}

// MaxAddressLen bounds the encoded destination carried in the first
// WebSocket message: longest valid host, ":" and a port.
const MaxAddressLen = 253 + 1 + 5

// ParseAddress parses a destination address as carried in the first
// WebSocket message: "host", "host:port" or "[v6-host]:port". A
// missing port falls back to def. The host part is validated with
// ValidateHost.
func ParseAddress(s string, def int) (string, int, error) {
	if len(s) > MaxAddressLen {
		return "", 0, fmt.Errorf("destination address too long (%d bytes)", len(s))
	}
	host, portStr := s, ""
	if strings.Contains(s, ":") {
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			// A bare IPv6 literal ("::1") is a host, not host:port;
			// bracketed IPv6 must be used to carry an explicit port.
			if net.ParseIP(s) == nil {
				return "", 0, fmt.Errorf("invalid destination address %q", s)
			}
		} else {
			host, portStr = h, p
		}
	}
	if err := ValidateHost(host); err != nil {
		return "", 0, err
	}
	port, err := ParsePort(portStr, def)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// Join renders host and port as a dialable "host:port" address.
func Join(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

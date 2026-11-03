package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func reqFrom(peer string, hdr map[string][]string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/session", nil)
	r.RemoteAddr = peer
	for k, v := range hdr {
		r.Header[http.CanonicalHeaderKey(k)] = v
	}
	return r
}

// Which address a request is attributed to (DR-038 D2, finding F-03): the connection's own, unless a proxy on this host is configured, the connection is from
// loopback, and the header's rightmost entry is an address.
func TestClientAddressBehindAProxy(t *testing.T) {
	proxy := &Handler{deps: Deps{ProxyAddressHeader: "X-Forwarded-For"}}
	plain := &Handler{deps: Deps{}}
	xff := func(v ...string) map[string][]string { return map[string][]string{"X-Forwarded-For": v} }
	cases := []struct {
		name string
		h    *Handler
		r    *http.Request
		want string
	}{
		{"no proxy configured: the header is never read", plain, reqFrom("127.0.0.1:5000", xff("198.51.100.7")), "127.0.0.1"},
		{"proxy, from loopback: the header's address", proxy, reqFrom("127.0.0.1:5000", xff("198.51.100.7")), "198.51.100.7"},
		{"proxy, from IPv6 loopback", proxy, reqFrom("[::1]:5000", xff("198.51.100.7")), "198.51.100.7"},
		{"proxy, a client-supplied entry on the left is ignored: the rightmost wins", proxy, reqFrom("127.0.0.1:5000", xff("10.9.9.9, 198.51.100.7")), "198.51.100.7"},
		{"proxy, several header lines: the last entry of the last", proxy, reqFrom("127.0.0.1:5000", xff("10.9.9.9", "203.0.113.4, 198.51.100.7")), "198.51.100.7"},
		{"proxy, but the connection is not from loopback: the header is the client's own claim", proxy, reqFrom("203.0.113.9:5000", xff("198.51.100.7")), "203.0.113.9"},
		{"proxy, no header: the connection", proxy, reqFrom("127.0.0.1:5000", nil), "127.0.0.1"},
		{"proxy, rightmost entry is not an address: the connection, not a left entry", proxy, reqFrom("127.0.0.1:5000", xff("198.51.100.7, not-an-ip")), "127.0.0.1"},
		{"proxy, empty value", proxy, reqFrom("127.0.0.1:5000", xff("")), "127.0.0.1"},
		{"proxy, IPv6 client", proxy, reqFrom("127.0.0.1:5000", xff("2001:db8::7")), "2001:db8::7"},
		{"an unparsable peer address", proxy, reqFrom("garbage", xff("198.51.100.7")), ""},
	}
	for _, c := range cases {
		if got := c.h.clientHost(c.r); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// the other header name is honoured, and only that one
	other := &Handler{deps: Deps{ProxyAddressHeader: "X-Real-Client"}}
	if got := other.clientHost(reqFrom("127.0.0.1:5000", map[string][]string{"X-Real-Client": {"198.51.100.8"}, "X-Forwarded-For": {"198.51.100.7"}})); got != "198.51.100.8" {
		t.Errorf("configured header: %q", got)
	}
}

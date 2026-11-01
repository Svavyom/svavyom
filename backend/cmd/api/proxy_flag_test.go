package main

import "testing"

// --proxy-address-header names a header: letters, digits and hyphens, starting with a letter (DR-038). Anything else could smuggle a second header or a CRLF.
func TestProxyAddressHeaderGrammar(t *testing.T) {
	for _, ok := range []string{"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "Forwarded"} {
		if !headerNameRE.MatchString(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "1X", "X Forwarded", "X-Forwarded-For\r\nX-Evil: 1", "X:Y", "X_Forwarded", "x/y", "-X"} {
		if headerNameRE.MatchString(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

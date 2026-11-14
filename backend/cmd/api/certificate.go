package main

import (
	"os"
	"path/filepath"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/api"
	"example.invalid/dedicatedcloud/backend/internal/tlsacme"
)

// certificateView describes the certificate file the API serves, with what the last issuance or renewal recorded next to it (DR-034). It reads the files
// on each call: the host page is read rarely and the files are small. Nothing it returns is secret.
func certificateView(certFile string, now func() time.Time) func() *api.CertificateView {
	return func() *api.CertificateView {
		b, err := os.ReadFile(certFile)
		if err != nil {
			return nil
		}
		in, err := tlsacme.Inspect(b)
		if err != nil {
			return nil
		}
		t := now()
		v := &api.CertificateView{Names: in.Names, Issuer: in.Issuer, NotBefore: in.NotBefore.Format(time.RFC3339), NotAfter: in.NotAfter.Format(time.RFC3339),
			DaysLeft: in.DaysLeft(t), Source: in.Source, RenewsFrom: tlsacme.RenewAt(in.NotBefore, in.NotAfter).UTC().Format(time.RFC3339)}
		if v.Names == nil {
			v.Names = []string{}
		}
		if st, ok := (tlsacme.Store{Dir: filepath.Dir(certFile)}).ReadState(); ok {
			at := st.LastAttempt.UTC().Format(time.RFC3339)
			v.LastAttempt, v.LastResult = &at, &st.LastResult
			if st.LastDetail != "" {
				v.LastDetail = &st.LastDetail
			}
			// The renewal settings are root-only, so the API cannot read them: a Let's Encrypt certificate that the tool has recorded is the one it renews.
			v.Managed = in.Source == "lets_encrypt" && len(in.Names) > 0 && in.Names[0] == st.Name
		}
		return v
	}
}

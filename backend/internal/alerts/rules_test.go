package alerts

import (
	"testing"
	"time"
)

func TestCertificateExpiryIsWarnedFrom14DaysAndCriticalFrom3AndScaledForShortCertificates(t *testing.T) {
	day := 24 * time.Hour
	for _, c := range []struct {
		lifetime, left time.Duration
		active         bool
		sev            string
	}{
		{90 * day, 20 * day, false, ""},
		{90 * day, 14 * day, true, Warning},
		{90 * day, 4 * day, true, Warning},
		{90 * day, 3 * day, true, Critical},
		{6 * day, 5 * day, false, ""},
		{6 * day, 20 * time.Hour, true, Warning},
		{6 * day, 6 * time.Hour, true, Critical},
	} {
		obs, covered := (&Evaluator{}).Evaluate(Inputs{HostID: "local", CertKnown: true, CertLeft: c.left, CertLifetime: c.lifetime})
		var got *Obs
		for i := range obs {
			if obs[i].Type == CertExpiring {
				got = &obs[i]
			}
		}
		if got == nil || got.Active != c.active || (c.active && got.Severity != c.sev) || got.Clear == c.active {
			t.Fatalf("lifetime %v left %v: %+v", c.lifetime, c.left, got)
		}
		_ = covered
	}
	obs, covered := (&Evaluator{}).Evaluate(Inputs{HostID: "local"})
	for _, o := range obs {
		if o.Type == CertExpiring {
			t.Fatal("no certificate (a proxy ends TLS): no alert, and the rule is not covered so nothing resolves")
		}
	}
	for _, c := range covered {
		if c == CertExpiring {
			t.Fatal("not covered")
		}
	}
}

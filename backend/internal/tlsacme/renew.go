package tlsacme

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Config is what renewal needs and the console must not show: it lives under acme/ (0600, root only) next to the account key.
type Config struct {
	Name         string `json:"name"`
	Email        string `json:"email"`
	Challenge    string `json:"challenge"`
	SkipDNSCheck bool   `json:"skip_dns_check,omitempty"`
}

func (s Store) configPath() string { return filepath.Join(s.Dir, "acme", "config.json") }

// AccountKeyFile is where the ACME account key is kept.
func (s Store) AccountKeyFile() string { return filepath.Join(s.Dir, "acme", "account.key") }

// WriteConfig saves the settings of the certificate in use, for the renewal timer.
func (s Store) WriteConfig(c Config) error {
	if err := os.MkdirAll(filepath.Dir(s.configPath()), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return writeAtomic(s.configPath(), append(b, '\n'), 0o600)
}

// ReadConfig returns the saved settings; ok is false when there are none (the certificate was not issued by this tool).
func (s Store) ReadConfig() (c Config, ok bool) {
	b, err := os.ReadFile(s.configPath())
	if err != nil || json.Unmarshal(b, &c) != nil || c.Name == "" {
		return Config{}, false
	}
	return c, true
}

// RemoveConfig forgets the settings (the switch back to a self-signed certificate). The account key stays: it is not a secret about the console, and the
// certificate authority keeps the registration.
func (s Store) RemoveConfig() error {
	if err := os.Remove(s.configPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// rateBackoff is how long a rate-limited renewal is not tried again.
const rateBackoff = 12 * time.Hour

// Renew renews the certificate in use when it is due (a third of its lifetime left). It returns renewed=false with a nil error when it is not due, and
// does not ask the authority again within twelve hours of a rate-limit answer. The outcome is recorded for the console either way.
func Renew(ctx context.Context, o Options) (renewed bool, in Info, err error) {
	defaults(&o)
	cb, rerr := os.ReadFile(o.Store.CertFile())
	if rerr != nil {
		return false, Info{}, fail(CodeIssue, "there is no certificate to renew")
	}
	in, rerr = Inspect(cb)
	if rerr != nil {
		return false, Info{}, fail(CodeIssue, "the certificate in use cannot be read")
	}
	if !in.Due(o.Now()) {
		return false, in, nil
	}
	if st, ok := o.Store.ReadState(); ok && st.LastResult == CodeRateLimited && o.Now().Sub(st.LastAttempt) < rateBackoff {
		return false, in, fail(CodeRateLimited, "rate limited at %s; not asking again for %s", st.LastAttempt.Format(time.RFC3339), rateBackoff)
	}
	ni, ierr := Issue(ctx, o)
	if ierr != nil {
		return false, in, ierr
	}
	return true, ni, nil
}

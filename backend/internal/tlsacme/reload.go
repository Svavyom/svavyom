package tlsacme

import (
	"crypto/tls"
	"errors"
	"os"
	"sync"
	"time"
)

// Reloader serves the certificate files and picks up a new pair when their modification times change, checked at most once a minute (DR-034 D3). A new
// pair that does not parse or does not match is ignored: the old certificate stays in use and Log gets a typed finding (once per change).
type Reloader struct {
	CertFile, KeyFile string
	Now               func() time.Time
	// Log receives a closed code and a short detail; it may be nil.
	Log func(code, detail string)

	mu      sync.Mutex
	cur     *tls.Certificate
	loaded  stamp
	tried   stamp
	checked time.Time
}

type stamp struct{ cert, key time.Time }

const recheck = time.Minute

func (r *Reloader) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reloader) stat() (stamp, error) {
	c, err := os.Stat(r.CertFile)
	if err != nil {
		return stamp{}, err
	}
	k, err := os.Stat(r.KeyFile)
	if err != nil {
		return stamp{}, err
	}
	return stamp{c.ModTime(), k.ModTime()}, nil
}

func (r *Reloader) load(s stamp) error {
	cb, err := os.ReadFile(r.CertFile)
	if err != nil {
		return err
	}
	kb, err := os.ReadFile(r.KeyFile)
	if err != nil {
		return err
	}
	c, err := Pair(cb, kb, "")
	if err != nil {
		return err
	}
	r.cur, r.loaded = c, s
	return nil
}

// Load reads the pair once; the API calls it at start so that a bad pair is an error then, not at the first handshake.
func (r *Reloader) Load() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, err := r.stat()
	if err != nil {
		return err
	}
	r.checked = r.now()
	return r.load(s)
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur == nil {
		return nil, errors.New("no certificate loaded")
	}
	if now := r.now(); now.Sub(r.checked) >= recheck {
		r.checked = now
		s, err := r.stat()
		if err == nil && s != r.loaded && s != r.tried {
			if err := r.load(s); err != nil {
				r.tried = s
				if r.Log != nil {
					r.Log("certificate_reload_failed", err.Error()+"; the previous certificate stays in use")
				}
			} else if r.Log != nil {
				r.Log("certificate_reloaded", "a new certificate is in use")
			}
		}
	}
	return r.cur, nil
}

package tlsacme

import (
	"os"
	"path/filepath"
)

// Store is the directory of the web console's certificate: cert.pem (0644), key.pem (0640 root:svavyom-api) and previous/ (the pair that was replaced,
// kept for one renewal). The ACME account key lives in acme/ (0600, root only) and State in state.json.
type Store struct {
	Dir string
	// Chown gives the key to the API's group; nil leaves ownership alone (tests).
	Chown func(path string) error
}

func (s Store) cert() string { return filepath.Join(s.Dir, "cert.pem") }
func (s Store) key() string  { return filepath.Join(s.Dir, "key.pem") }

// CertFile and KeyFile are the paths the API serves.
func (s Store) CertFile() string { return s.cert() }
func (s Store) KeyFile() string  { return s.key() }

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Install replaces the pair. The pair is checked first (it must parse, match and name `name`); the old pair is copied to previous/; the key is written
// before the certificate so that a reader never sees a new certificate with an old key for longer than the moment between the two renames (the API's
// reload rejects a mismatch and tries again at the next change).
func (s Store) Install(certPEM, keyPEM []byte, name string) error {
	if _, err := Pair(certPEM, keyPEM, name); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	if oc, err := os.ReadFile(s.cert()); err == nil {
		if ok, err := os.ReadFile(s.key()); err == nil {
			prev := filepath.Join(s.Dir, "previous")
			if err := os.MkdirAll(prev, 0o700); err != nil {
				return err
			}
			if err := writeAtomic(filepath.Join(prev, "cert.pem"), oc, 0o644); err != nil {
				return err
			}
			if err := writeAtomic(filepath.Join(prev, "key.pem"), ok, 0o600); err != nil {
				return err
			}
		}
	}
	if err := writeAtomic(s.key(), keyPEM, 0o640); err != nil {
		return err
	}
	if s.Chown != nil {
		if err := s.Chown(s.key()); err != nil {
			return err
		}
	}
	return writeAtomic(s.cert(), certPEM, 0o644)
}

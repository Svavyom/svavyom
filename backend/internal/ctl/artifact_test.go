package ctl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyArtifactAcceptsAnExactArtifact(t *testing.T) {
	dir := makeArtifact(t, "0.1.0", map[string]int{"operation": 8, "auth": 3}, nil)
	m, err := VerifyArtifact(dir)
	if err != nil || m.Version != "0.1.0" || m.SchemaVersions["operation"] != 8 {
		t.Fatalf("%+v %v", m, err)
	}
	if f, ok := m.File("bin/api"); !ok || f.Size == 0 {
		t.Fatal("File lookup")
	}
}

func TestVerifyArtifactRefusesEverythingThatIsNotWhatTheManifestSays(t *testing.T) {
	base := func() string { return makeArtifact(t, "0.1.0", map[string]int{"operation": 8}, nil) }
	cases := map[string]func(dir string){
		"a changed file": func(d string) { _ = os.WriteFile(filepath.Join(d, "bin/api"), []byte("evil"), 0o644) },
		"a same-size changed file": func(d string) {
			b, _ := os.ReadFile(filepath.Join(d, "bin/api"))
			b[len(b)-2] ^= 1
			_ = os.WriteFile(filepath.Join(d, "bin/api"), b, 0o644)
		},
		"a removed file":   func(d string) { _ = os.Remove(filepath.Join(d, "bin/agent")) },
		"an unlisted file": func(d string) { _ = os.WriteFile(filepath.Join(d, "bin/backdoor"), []byte("x"), 0o755) },
		"a symlink in place": func(d string) {
			_ = os.Remove(filepath.Join(d, "docs/INSTALL.md"))
			_ = os.Symlink("/etc/passwd", filepath.Join(d, "docs/INSTALL.md"))
		},
		"no manifest":          func(d string) { _ = os.Remove(filepath.Join(d, ManifestName)) },
		"a malformed manifest": func(d string) { _ = os.WriteFile(filepath.Join(d, ManifestName), []byte("{"), 0o644) },
		"an unknown key": func(d string) {
			rewrite(d, func(s string) string { return strings.Replace(s, `"schema": 1`, `"schema": 1, "extra": true`, 1) })
		},
		"a bad version": func(d string) {
			rewrite(d, func(s string) string { return strings.Replace(s, `"version": "0.1.0"`, `"version": "latest"`, 1) })
		},
		"a traversal path": func(d string) {
			rewrite(d, func(s string) string { return strings.Replace(s, `"path": "bin/api"`, `"path": "../etc/passwd"`, 1) })
		},
		"a bad audience": func(d string) {
			rewrite(d, func(s string) string { return strings.Replace(s, `"audience": "public"`, `"audience": "maybe"`, 1) })
		},
	}
	for name, mut := range cases {
		d := base()
		mut(d)
		if _, err := VerifyArtifact(d); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	d := makeArtifact(t, "0.1.0", nil, func(f map[string][]byte) { delete(f, "bin/mutation-helper") })
	if _, err := VerifyArtifact(d); err == nil || !strings.Contains(err.Error(), "bin/mutation-helper") {
		t.Fatalf("an artifact without a required binary: %v", err)
	}
}

func rewrite(dir string, f func(string) string) {
	p := filepath.Join(dir, ManifestName)
	b, _ := os.ReadFile(p)
	_ = os.WriteFile(p, []byte(f(string(b))), 0o644)
}

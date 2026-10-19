package ctl

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// A Plan is the ordered list of changes a command intends to make. Printing it before anything happens is part of the contract: dry-run (the default of every
// privileged subcommand) prints the plan and exits; --apply prints each step as it runs, and the first failure stops the run.
type step struct {
	desc string
	do   func() error
}

// Plan collects steps.
type Plan struct{ steps []step }

func (p *Plan) add(desc string, do func() error) { p.steps = append(p.steps, step{desc, do}) }

// Run prints the plan; with apply it also executes it.
func (p *Plan) Run(w io.Writer, apply bool) error {
	if !apply {
		_, _ = fmt.Fprintln(w, "PLAN (nothing is changed without --apply):")
		for i, s := range p.steps {
			_, _ = fmt.Fprintf(w, "  %2d. %s\n", i+1, s.desc)
		}
		return nil
	}
	_, _ = fmt.Fprintln(w, "APPLYING:")
	for i, s := range p.steps {
		_, _ = fmt.Fprintf(w, "  %2d. %s\n", i+1, s.desc)
		if err := s.do(); err != nil {
			_, _ = fmt.Fprintf(w, "      FAILED: %s\n", clean(err.Error()))
			return fmt.Errorf("step %d (%s): %w", i+1, s.desc, err)
		}
	}
	return nil
}

// writeAtomic writes data to path through a temporary file in the same directory and a rename, with the given mode and owner. It reports whether the file
// changed (the same content, mode and owner is left alone, so a re-run changes nothing). The directory must exist; a symlink at the destination is replaced,
// never followed.
func (e *Env) writeAtomic(path string, data []byte, mode os.FileMode, uid, gid int) (bool, error) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() {
		if old, rerr := os.ReadFile(path); rerr == nil && bytes.Equal(old, data) && fi.Mode().Perm() == mode { // #nosec G304 -- a fixed Svavyom destination chosen by the caller, never user input
			if u, ok := ownerOf(fi); ok {
				if g, _ := gidOf(fi); u == uid && g == gid {
					return false, nil
				}
			}
			return true, e.Chown(path, uid, gid)
		}
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".svavyom-new-*")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := e.Chown(tmp.Name(), uid, gid); err != nil {
		return false, err
	}
	return true, os.Rename(tmp.Name(), path)
}

// ensureDir creates a directory (and parents) with the mode and owner; an existing directory keeps its content and gets the mode and owner.
func (e *Env) ensureDir(path string, mode os.FileMode, uid, gid int) error {
	if fi, err := os.Lstat(path); err == nil && !fi.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", path)
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return e.Chown(path, uid, gid)
}

func sub(s string, kv map[string]string) string {
	for k, v := range kv {
		s = strings.ReplaceAll(s, k, v)
	}
	return s
}

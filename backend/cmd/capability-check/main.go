// Command capability-check reports whether a filesystem root conforms to the
// M0 support matrix (story M0-E02-S05; DR-007 D1/D2/D3 = A). Read-only,
// unprivileged, process-free and network-free. The verdict is matrix
// conformance only, never host qualification.
//
//	capability-check --root DIR --matrix FILE [--out FILE]
//
// Exit codes: 0 supported, 10 unsupported, 11 unknown, 2 usage/contract/environment error.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"example.invalid/dedicatedcloud/backend/internal/capability"
)

const maxMatrixBytes = 1 << 20

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("capability-check", flag.ContinueOnError)
	fl.SetOutput(stderr)
	root := fl.String("root", "", "filesystem root to assess (read-only)")
	matrixPath := fl.String("matrix", "", "support matrix JSON (docs repo, pinned commit)")
	outPath := fl.String("out", "", "write the report to a new file (never overwrites)")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || *root == "" || *matrixPath == "" {
		_, _ = fmt.Fprintln(stderr, "usage: capability-check --root DIR --matrix FILE [--out FILE]")
		return 2
	}
	if os.Geteuid() == 0 {
		_, _ = fmt.Fprintln(stderr, "ERROR refusing to run as root: the checker needs no privilege")
		return 2
	}
	data, err := readMatrix(*matrixPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ERROR matrix: %v\n", err)
		return 2
	}
	m, err := capability.LoadMatrix(data)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ERROR %v\n", err)
		return 2
	}
	fsys, closeFS, err := capability.OpenRoot(filepath.Clean(*root))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ERROR root: %v\n", err)
		return 2
	}
	defer func() { _ = closeFS() }()
	rep := capability.CheckWith(wrapFS(fsys), m, options())
	out := rep.JSON()
	if *outPath != "" {
		if err := writeNew(*outPath, out); err != nil {
			_, _ = fmt.Fprintf(stderr, "ERROR out: %v\n", err)
			return 2
		}
	} else if _, err := stdout.Write(out); err != nil {
		return 2
	}
	switch rep.Verdict {
	case capability.Supported:
		return 0
	case capability.Unsupported:
		return 10
	default:
		return 11
	}
}

// readMatrix reads a regular, bounded matrix file without following a final symlink.
func readMatrix(path string) ([]byte, error) {
	f, err := os.OpenFile(filepath.Clean(path), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxMatrixBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxMatrixBytes {
		return nil, errors.New("matrix too large")
	}
	return data, nil
}

// writeNew creates path exclusively (never overwrites, never follows a symlink).
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

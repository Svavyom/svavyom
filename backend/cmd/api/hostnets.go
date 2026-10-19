package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// hostPrefixes returns the IPv4 prefixes the host itself uses: every non-default kernel route (which includes the connected subnet of every addressed interface). The API
// process shares the host's network namespace; the confined mutation helper does not, so this is read here and passed to the helper as extra reasons to
// refuse a new managed network. Anything unreadable is an error: the caller then refuses the create (fail closed).
func hostPrefixes() ([]netip.Prefix, error) {
	// /proc/self/net/route is the kernel's table for this process's network namespace (the API's is the host's). Connected subnets of every interface that has an
	// address are in it, up or down, so it is enough; interface addresses are not read separately (that would need netlink, which the API's unit does not allow).
	f, err := os.Open("/proc/self/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseProcRoutes(f)
}

// parseProcRoutes reads the Linux /proc/net/route table (little-endian hexadecimal destination and mask) and returns its non-default prefixes.
func parseProcRoutes(r io.Reader) ([]netip.Prefix, error) {
	sc := bufio.NewScanner(io.LimitReader(r, 1<<20))
	var out []netip.Prefix
	first := true
	for sc.Scan() {
		if first {
			first = false
			if !strings.HasPrefix(sc.Text(), "Iface") {
				return nil, errors.New("unexpected route table header")
			}
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 8 {
			return nil, errors.New("short route line")
		}
		dest, err1 := strconv.ParseUint(f[1], 16, 32)
		mask, err2 := strconv.ParseUint(f[7], 16, 32)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad route line")
		}
		if mask == 0 {
			continue // the default route says nothing about a subnet
		}
		var d, m [4]byte
		binary.LittleEndian.PutUint32(d[:], uint32(dest)) // #nosec G115 -- ParseUint bitSize 32
		binary.LittleEndian.PutUint32(m[:], uint32(mask)) // #nosec G115 -- ParseUint bitSize 32
		ones, bits := net.IPMask(m[:]).Size()
		if bits != 32 {
			return nil, errors.New("non-contiguous route mask")
		}
		p, err := netip.AddrFrom4(d).Prefix(ones)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if first {
		return nil, errors.New("empty route table")
	}
	return out, nil
}

func prefixStrings(p []netip.Prefix) []string {
	out := make([]string, 0, len(p))
	seen := map[string]bool{}
	for _, x := range p {
		s := x.Masked().String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

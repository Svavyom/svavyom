//go:build libvirt && libvirt_test

package libvirtmut

// REAL-HOST network qualification (docs/QUALIFICATION-NETWORKS.md): a uniquely named Svavyom-managed NAT network in a private subnet that conflicts with
// nothing, a VM attached to it, DHCP, a compute change, a static DHCP reservation, and an ownership-proving teardown, one STEP per invocation
// (SVAVYOM_QUALIFY_STEP), driven by tools/qualify_network.py, which also performs the guest-side checks over SSH and compares the host's own network
// state before and after. It does nothing unless SVAVYOM_QUALIFY_CREATE=1. The network and the VM have identities DERIVED from the run id, proven before
// each step; nothing else on the host is created, changed or deleted. Evidence lines start with "QUALIFY ".

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor/libvirtro"
	"example.invalid/dedicatedcloud/backend/internal/provision"
)

const netBeforeFile = "networks-before.json"

// netIdentity derives the qualification network's name and UUID from the run id, the same way qualIdentity derives the VM's.
func netIdentity(runID string) (name, uuid string) {
	s := sha256.Sum256([]byte("svavyom-qualify-net-v1:" + runID))
	b := s[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return "svqn-" + strings.TrimPrefix(runID, "qr-"), h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func TestQualificationNetworkIdentityIsDerivedFromTheRunID(t *testing.T) {
	n1, u1 := netIdentity("qr-20261012-a1b2c3")
	n2, u2 := netIdentity("qr-20261012-a1b2c3")
	n3, u3 := netIdentity("qr-20261012-a1b2c4")
	if n1 != n2 || u1 != u2 || n1 == n3 || u1 == u3 {
		t.Fatal("not deterministic or not unique")
	}
	spec := provision.NetworkSpec{Name: n1, UUID: u1, Subnet: "10.201.7.0/24", DHCPStart: "10.201.7.10", DHCPEnd: "10.201.7.200"}
	if err := spec.Validate(); err != nil {
		t.Fatalf("a derived network identity must be a valid network specification: %v", err)
	}
}

type netSnap struct {
	Name      string `json:"name"`
	UUID      string `json:"uuid"`
	Managed   bool   `json:"managed"`
	Active    bool   `json:"active"`
	Autostart bool   `json:"autostart"`
	Subnet    string `json:"subnet"`
	Bridge    string `json:"bridge"`
	Hosts     int    `json:"reservations"`
}

func snapNets(all []provision.NetworkInfo) []netSnap {
	var out []netSnap
	for _, n := range all {
		out = append(out, netSnap{n.Name, n.UUID, n.Managed, n.Active, n.Autostart, n.Subnet.String(), n.Bridge, len(n.Hosts)})
	}
	return out
}

func TestSystemNetworkQualification(t *testing.T) {
	cfg, pol, rec, vmName, vmUUID, vmFP := qualEnv(t)
	step := os.Getenv("SVAVYOM_QUALIFY_STEP")
	rec.res.Stage = "network-" + step
	defer rec.flush()
	netName, netUUID := netIdentity(rec.res.RunID)
	subnet := os.Getenv("SVAVYOM_QUALIFY_NET_SUBNET")
	pfx, perr := provision.ParseManagedSubnet(subnet)
	if perr != nil || pfx.Bits() != 24 {
		t.Fatalf("SVAVYOM_QUALIFY_NET_SUBNET must be a private /24: %v", perr)
	}
	base := pfx.Masked().Addr().As4()
	at := func(last byte) string { return netip.AddrFrom4([4]byte{base[0], base[1], base[2], last}).String() }
	nspec := provision.NetworkSpec{Name: netName, UUID: netUUID, Subnet: subnet, DHCPStart: at(10), DHCPEnd: at(200)}
	reservedIP := at(50)

	ops, err := Open(SystemURI)
	if err != nil {
		rec.fail("real-libvirt", "cannot open qemu:///system read-write")
		t.Fatal(err)
	}
	defer ops.Close()
	ops.Diag = func(op, detail string) { t.Logf("raw libvirt %s: %s", op, detail) } // harness only; never reaches a product surface
	if typ, terr := ops.conn.GetType(); terr != nil || typ != "QEMU" {
		rec.fail("real-libvirt", "not a real QEMU system connection")
		t.Fatal("not QEMU")
	}
	ro, err := libvirtro.Open(libvirtro.SystemURI)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	ctx := context.Background()
	cat, err := provision.LoadTrustedCatalog(pol, cfg.CatalogDir)
	if err != nil {
		rec.fail("managed-image", fmt.Sprint(err))
		t.Fatal(err)
	}
	img, err := cat.Usable(os.Getenv("SVAVYOM_QUALIFY_IMAGE_ID"))
	if err != nil {
		rec.fail("managed-image", fmt.Sprint(err))
		t.Fatal(err)
	}
	hostPrefixes := func() []netip.Prefix {
		raw, rerr := os.ReadFile(os.Getenv("SVAVYOM_QUALIFY_HOST_ROUTES")) // #nosec G304 -- operator-supplied record of the host's own prefixes
		if rerr != nil {
			rec.fail("host-prefixes", "the host's own subnets were not supplied")
			t.Fatal(rerr)
		}
		var out []netip.Prefix
		for _, l := range strings.Fields(string(raw)) {
			p, perr := provision.ParsePrefixStrict(l)
			if perr != nil {
				rec.fail("host-prefixes", "unparsable host prefix")
				t.Fatal(perr)
			}
			out = append(out, p)
		}
		return out
	}
	var want provision.AnchorWant
	var baseAnchor provision.Anchor
	haveAnchor := false
	if raw, rerr := os.ReadFile(filepath.Join(rec.out, anchorFile)); rerr == nil && json.Unmarshal(raw, &baseAnchor) == nil { // #nosec G304 -- fixed name in the run output dir
		for _, im := range cat.Images {
			if p, perr := cat.Path(im); perr == nil && p == baseAnchor.Path && im.SHA256 == baseAnchor.SHA256 {
				want, haveAnchor = provision.AnchorWant{Path: p, UID: pol.Owner, GID: 0, SHA256: im.SHA256, Size: im.SizeBytes}, true
			}
		}
	}
	anchor := func(id string) {
		t.Helper()
		if !haveAnchor {
			rec.add(id, "NOT_RUN", "no "+anchorFile+" from the baseline step")
			return
		}
		if _, line, err := checkAnchor(want, &baseAnchor); err != nil {
			rec.fail(id, fmt.Sprintf("the base image changed: %v; %s", err, line))
			t.Fatal(id)
		} else {
			rec.pass(id, "root:root 0444 regular file, identical to the baseline; "+line)
		}
	}
	ownedVM := func() provision.DomainInfo {
		t.Helper()
		di, err := ops.LookupDomain(ctx, vmName)
		if err != nil || !di.Managed || di.UUID != vmUUID || di.Fingerprint != vmFP {
			rec.fail("svavyom-owned", fmt.Sprintf("%s is not provably this run's Svavyom VM (%v)", vmName, err))
			t.Fatal("ownership not proven")
		}
		return di
	}
	ownedNet := func() provision.NetworkInfo {
		t.Helper()
		n, err := ops.LookupNetwork(ctx, netName)
		if err != nil || !n.Managed || n.UUID != netUUID || n.Bridge != provision.BridgeName(netUUID) {
			rec.fail("network-owned", fmt.Sprintf("%s is not provably this run's Svavyom network (%v)", netName, err))
			t.Fatal("network ownership not proven")
		}
		return n
	}
	startAndWait := func() string {
		t.Helper()
		if err := provision.Start(ctx, ops, vmName, nil); err != nil {
			rec.fail("vm-start", fmt.Sprint(err))
			t.Fatal(err)
		}
		deadline := time.Now().Add(4 * time.Minute)
		var d hypervisor.Domain
		for time.Now().Before(deadline) {
			if d, err = ro.Lookup(ctx, vmName); err == nil && d.State == hypervisor.StateRunning && provision.IsIPv4(d.IPv4) {
				if a, perr := netip.ParseAddr(d.IPv4); perr == nil && pfx.Contains(a) {
					return d.IPv4
				}
			}
			time.Sleep(3 * time.Second)
		}
		rec.fail("vm-start", fmt.Sprintf("%s did not get an address of %s: %+v %v", vmName, subnet, d, err))
		t.Fatal("no address")
		return ""
	}
	cat0 := func(err error) hypervisor.Category { return hypervisor.CategoryOf(err) }

	switch step {
	case "baseline":
		all, err := ops.ListNetworks(ctx)
		if err != nil {
			rec.fail("networks-recorded", fmt.Sprint(err))
			t.Fatal(err)
		}
		snap := snapNets(all)
		b, _ := json.MarshalIndent(snap, "", "  ")
		if rec.out != "" {
			_ = os.WriteFile(filepath.Join(rec.out, netBeforeFile), append(b, '\n'), 0o644) // #nosec G306 -- non-secret record: names, flags, subnets
		}
		rec.pass("networks-recorded", fmt.Sprintf("%d existing libvirt networks recorded", len(all)))
		for _, n := range all {
			if n.Name == netName || n.UUID == netUUID || n.Bridge == provision.BridgeName(netUUID) {
				rec.fail("name-free", "a network of this run's identity already exists")
				t.Fatal("not clean")
			}
			if n.Subnet.IsValid() && provision.Overlaps(n.Subnet, pfx) {
				rec.fail("subnet-free", fmt.Sprintf("%s overlaps the existing libvirt network %s", subnet, n.Name))
				t.Fatal("subnet in use")
			}
		}
		for _, h := range hostPrefixes() {
			if provision.Overlaps(h, pfx) {
				rec.fail("subnet-free", fmt.Sprintf("%s overlaps a host subnet or route %s", subnet, h))
				t.Fatal("subnet in use")
			}
		}
		rec.pass("subnet-free", subnet+" overlaps no libvirt network and no subnet or route of the host")
		if _, err := cat.Verify(img); err != nil {
			rec.fail("managed-image", "digest verification failed")
			t.Fatal(err)
		}
		a, line, err := checkAnchor(func() provision.AnchorWant {
			w, werr := anchorWantFor(pol, cat, img)
			if werr != nil {
				rec.fail("image-immutable-before", "managed image path not resolvable")
				t.Fatal(werr)
			}
			return w
		}(), nil)
		if err != nil {
			rec.fail("image-immutable-before", fmt.Sprintf("%v; %s", err, line))
			t.Fatal(err)
		}
		if ab, merr := json.MarshalIndent(a, "", "  "); merr == nil && rec.out != "" {
			_ = os.WriteFile(filepath.Join(rec.out, anchorFile), append(ab, '\n'), 0o644) // #nosec G306 -- non-secret record
		}
		rec.res.ImageID, rec.res.LoginUser = img.ID, img.LoginUser
		rec.pass("image-immutable-before", "root:root 0444 regular file; "+line)

	case "net-create":
		if err := provision.NetworkCreate(ctx, ops, cfg, nspec, hostPrefixes(), nil); err != nil {
			rec.fail("network-created", fmt.Sprint(err))
			t.Fatal(err)
		}
		n := ownedNet()
		if !n.Active || !n.Autostart || n.Mode != "nat" || n.Subnet != pfx || n.Gateway != at(1) || n.DHCPStart != at(10) || n.DHCPEnd != at(200) {
			rec.fail("network-created", fmt.Sprintf("unexpected network %+v", n))
			t.Fatal("network shape")
		}
		rec.pass("network-created", fmt.Sprintf("%s: NAT %s, gateway %s, DHCP %s-%s, bridge %s, active, autostart, Svavyom ownership marker", netName, subnet, n.Gateway, n.DHCPStart, n.DHCPEnd, n.Bridge))
		if err := provision.NetworkCreate(ctx, ops, cfg, nspec, hostPrefixes(), nil); err != nil {
			rec.fail("network-create-idempotent", fmt.Sprint(err))
			t.Fatal(err)
		}
		all, _ := ops.ListNetworks(ctx)
		count := 0
		for _, x := range all {
			if x.Name == netName || x.UUID == netUUID {
				count++
			}
		}
		if count != 1 {
			rec.fail("network-create-idempotent", fmt.Sprintf("%d networks carry this identity", count))
			t.Fatal("duplicate")
		}
		rec.pass("network-create-idempotent", "creating the same network again changed nothing and made no duplicate")
		// refusals, each proven to change nothing
		before, _ := ops.ListNetworks(ctx)
		other := provision.NetworkSpec{Name: netName + "-x", UUID: "9a9a9a9a-2222-4333-8444-5555555555ab", Subnet: pfx.String(), DHCPStart: at(10), DHCPEnd: at(20)}
		if err := provision.NetworkCreate(ctx, ops, cfg, other, nil, nil); cat0(err) != hypervisor.Conflict {
			rec.fail("overlap-refused", fmt.Sprintf("a second network on the same subnet must be refused: %v", err))
			t.Fatal("overlap")
		}
		rec.pass("overlap-refused", "a second network on the same subnet was refused")
		var foreign provision.NetworkInfo
		for _, x := range before {
			if !x.Managed && x.Subnet.IsValid() {
				foreign = x
				break
			}
		}
		if foreign.Name != "" {
			f := other
			f.Subnet = foreign.Subnet.String()
			if foreign.Subnet.Bits() < provision.MinNetPrefix || foreign.Subnet.Bits() > provision.MaxNetPrefix || provision.ParseManagedSubnetOK(foreign.Subnet) != nil {
				rec.add("overlap-refused-foreign", "NOT_RUN", "the existing network is not in the managed range grammar")
			} else {
				a := foreign.Subnet.Addr().Next().Next().Next()
				f.DHCPStart, f.DHCPEnd = a.String(), a.Next().String()
				if err := provision.NetworkCreate(ctx, ops, cfg, f, nil, nil); cat0(err) != hypervisor.Conflict {
					rec.fail("overlap-refused-foreign", fmt.Sprintf("a network overlapping %s must be refused: %v", foreign.Name, err))
					t.Fatal("overlap foreign")
				}
				rec.pass("overlap-refused-foreign", "a network overlapping the existing network "+foreign.Name+" was refused")
			}
		}
		hp := hostPrefixes()
		if len(hp) > 0 {
			h := hp[0]
			f := other
			f.Name, f.UUID = netName+"-y", "9b9b9b9b-2222-4333-8444-5555555555ab"
			if h.Bits() <= provision.MaxNetPrefix && provision.ParseManagedSubnetOK(h) == nil {
				a := h.Addr().Next().Next().Next()
				f.Subnet, f.DHCPStart, f.DHCPEnd = h.String(), a.String(), a.Next().String()
				if err := provision.NetworkCreate(ctx, ops, cfg, f, hp, nil); cat0(err) != hypervisor.Conflict {
					rec.fail("overlap-refused-host", fmt.Sprintf("a network overlapping the host prefix %s must be refused: %v", h, err))
					t.Fatal("overlap host")
				}
				rec.pass("overlap-refused-host", "a network overlapping a host subnet or route was refused")
			}
		}
		for _, bad := range []string{cfg.Network} {
			if err := provision.NetworkDelete(ctx, ops, bad, nil); cat0(err) != hypervisor.Prohibited {
				rec.fail("foreign-network-untouched", fmt.Sprintf("deleting %s must be prohibited: %v", bad, err))
				t.Fatal("foreign delete")
			}
			if err := provision.NetworkStop(ctx, ops, bad, nil); cat0(err) != hypervisor.Prohibited {
				rec.fail("foreign-network-untouched", fmt.Sprintf("stopping %s must be prohibited: %v", bad, err))
				t.Fatal("foreign stop")
			}
		}
		after, _ := ops.ListNetworks(ctx)
		if len(after) != len(before) {
			rec.fail("refusals-change-nothing", fmt.Sprintf("%d networks before the refusals, %d after", len(before), len(after)))
			t.Fatal("refusals changed the host")
		}
		rec.pass("foreign-network-untouched", "deleting or stopping the pre-existing network "+cfg.Network+" was prohibited")
		rec.pass("refusals-change-nothing", "no refusal created, changed or removed a libvirt network")

	case "vm-create":
		ownedNet()
		key, kerr := os.ReadFile(os.Getenv("SVAVYOM_QUALIFY_SSH_PUBKEY_FILE")) // #nosec G304 -- operator-supplied PUBLIC key
		if kerr != nil {
			t.Fatal(kerr)
		}
		k, kerr := provision.NormalizeSSHKey(string(key))
		if kerr != nil {
			t.Fatal(kerr)
		}
		spec := provision.Spec{Name: vmName, UUID: vmUUID, Fingerprint: vmFP, VCPUs: 1, MemoryMiB: 1024, ImageID: img.ID, ImageSHA256: img.SHA256, DiskGiB: 10, SSHPublicKey: k.Authorized, Network: netName}
		if err := provision.Provision(ctx, ops, cfg, cat, spec, t.TempDir(), nil); err != nil {
			rec.fail("vm-created", fmt.Sprint(err))
			t.Fatal(err)
		}
		d := ownedVM()
		pd, _ := provision.ParseDomain(d.XML)
		if pd.Network != netName || pd.MAC != provision.MAC(vmUUID) {
			rec.fail("vm-attached", fmt.Sprintf("network=%q mac=%q", pd.Network, pd.MAC))
			t.Fatal("not attached")
		}
		rec.pass("vm-created", "the VM was defined with its two volumes")
		rec.pass("vm-attached", "the VM's interface is on "+netName+" with its derived MAC")
		if err := provision.NetworkDelete(ctx, ops, netName, nil); cat0(err) != hypervisor.Conflict {
			rec.fail("delete-with-vm-refused", fmt.Sprintf("deleting a network with an attached VM must be refused: %v", err))
			t.Fatal("delete with VM")
		}
		ownedNet()
		rec.pass("delete-with-vm-refused", "deleting the network while the VM is attached was refused; the network is intact")
		if err := provision.NetworkCreate(ctx, ops, cfg, provision.NetworkSpec{Name: cfg.Network, UUID: "9c9c9c9c-2222-4333-8444-5555555555ab", Subnet: "10.202.0.0/24", DHCPStart: "10.202.0.10", DHCPEnd: "10.202.0.20"}, nil, nil); cat0(err) != hypervisor.Validation {
			rec.fail("default-name-refused", fmt.Sprintf("a managed network may not take the configured network's name: %v", err))
			t.Fatal("name")
		}
		rec.pass("default-name-refused", "a managed network may not take the name of the configured network")
		anchor("image-immutable-after-create")

	case "vm-start":
		ownedVM()
		ownedNet()
		rec.res.IPv4 = startAndWait()
		if ip := rec.res.IPv4; strings.TrimSpace(os.Getenv("SVAVYOM_QUALIFY_EXPECT_IP")) != "" && ip != os.Getenv("SVAVYOM_QUALIFY_EXPECT_IP") {
			rec.fail("vm-address", fmt.Sprintf("expected %s, got %s", os.Getenv("SVAVYOM_QUALIFY_EXPECT_IP"), ip))
			t.Fatal("wrong address")
		}
		leases, _ := ops.NetworkLeases(ctx, netName)
		found := false
		for _, l := range leases {
			found = found || (l.MAC == provision.MAC(vmUUID) && l.IP == rec.res.IPv4)
		}
		if !found {
			rec.fail("dhcp-lease", fmt.Sprintf("no lease for %s at %s in %+v", provision.MAC(vmUUID), rec.res.IPv4, leases))
			t.Fatal("no lease")
		}
		rec.pass("vm-start", "Running with an address of "+subnet)
		rec.pass("dhcp-lease", fmt.Sprintf("the network's DHCP table holds a lease %s for the VM's MAC", rec.res.IPv4))
		if err := provision.NetworkStop(ctx, ops, netName, nil); cat0(err) != hypervisor.Conflict {
			rec.fail("stop-with-running-vm-refused", fmt.Sprintf("stopping a network with a running VM must be refused: %v", err))
			t.Fatal("stop with running VM")
		}
		rec.pass("stop-with-running-vm-refused", "stopping the network while the VM runs was refused")
		if err := provision.Compute(ctx, ops, vmName, 3, 3072, nil); cat0(err) != hypervisor.Conflict {
			rec.fail("compute-running-refused", fmt.Sprintf("a compute change of a running VM must be refused: %v", err))
			t.Fatal("compute while running")
		}
		rec.pass("compute-running-refused", "changing the size of a running VM was refused")

	case "vm-stop":
		ownedVM()
		if err := provision.Stop(ctx, ops, vmName, nil); err != nil {
			rec.fail("vm-stop", fmt.Sprint(err))
			t.Fatal(err)
		}
		rec.pass("vm-stop", "graceful stop observed")

	case "compute":
		ownedVM()
		for name, c := range map[string][2]int{"zero cpus": {0, 1024}, "too many": {provision.MaxVCPUs + 1, 1024}, "odd memory": {2, 1000}} {
			if err := provision.Compute(ctx, ops, vmName, c[0], c[1], nil); cat0(err) != hypervisor.Validation {
				rec.fail("compute-bounds", fmt.Sprintf("%s must be refused: %v", name, err))
				t.Fatal("bounds")
			}
		}
		rec.pass("compute-bounds", "out-of-range vCPU and memory values were refused")
		if err := provision.Compute(ctx, ops, vmName, 2, 2048, nil); err != nil {
			rec.fail("compute-set", fmt.Sprint(err))
			t.Fatal(err)
		}
		d := ownedVM()
		pd, _ := provision.ParseDomain(d.XML)
		if d.VCPUs != 2 || d.MemoryMiB != 2048 || pd.VCPUs != 2 || pd.MemoryMiB != 2048 {
			rec.fail("compute-set", fmt.Sprintf("definition says %d vCPU / %d MiB (parsed %d / %d)", d.VCPUs, d.MemoryMiB, pd.VCPUs, pd.MemoryMiB))
			t.Fatal("definition")
		}
		rec.pass("compute-set", "the stopped VM's persistent definition now says 2 vCPU and 2048 MiB")

	case "reserve":
		ownedVM()
		ownedNet()
		for name, ip := range map[string]string{"gateway": at(1), "network address": at(0), "broadcast": at(255), "outside the subnet": "10.99.99.99"} {
			if err := provision.ReserveIP(ctx, ops, vmName, ip, nil); cat0(err) != hypervisor.Validation {
				rec.fail("reserve-refusals", fmt.Sprintf("%s (%s) must be refused: %v", name, ip, err))
				t.Fatal("reserve refusal")
			}
		}
		if err := provision.ReserveIP(ctx, ops, vmName, reservedIP, nil); err != nil {
			rec.fail("ip-reserved", fmt.Sprint(err))
			t.Fatal(err)
		}
		if err := provision.ReserveIP(ctx, ops, vmName, reservedIP, nil); err != nil {
			rec.fail("ip-reserved", "repeating the same reservation must be a no-op: "+err.Error())
			t.Fatal(err)
		}
		if err := provision.ReserveIP(ctx, ops, vmName, at(51), nil); cat0(err) != hypervisor.Conflict {
			rec.fail("reserve-refusals", fmt.Sprintf("a second reservation for the same VM must be refused: %v", err))
			t.Fatal("second reservation")
		}
		n := ownedNet()
		if len(n.Hosts) != 1 || n.Hosts[0].MAC != provision.MAC(vmUUID) || n.Hosts[0].IP != reservedIP {
			rec.fail("ip-reserved", fmt.Sprintf("network hosts %+v", n.Hosts))
			t.Fatal("hosts")
		}
		rec.pass("reserve-refusals", "gateway, network, broadcast and outside addresses, and a second reservation for the VM, were refused")
		rec.pass("ip-reserved", fmt.Sprintf("a static DHCP reservation binds %s to the VM's MAC %s (persistent and live)", reservedIP, provision.MAC(vmUUID)))

	case "release":
		ownedVM()
		if err := provision.ReleaseIP(ctx, ops, vmName, nil); err != nil {
			rec.fail("ip-released", fmt.Sprint(err))
			t.Fatal(err)
		}
		if err := provision.ReleaseIP(ctx, ops, vmName, nil); err != nil {
			rec.fail("ip-released", "releasing twice must be a no-op: "+err.Error())
			t.Fatal(err)
		}
		if n := ownedNet(); len(n.Hosts) != 0 {
			rec.fail("ip-released", fmt.Sprintf("%d reservations remain", len(n.Hosts)))
			t.Fatal("remains")
		}
		rec.pass("ip-released", "the reservation was removed")

	case "vm-delete":
		ownedVM()
		if err := provision.Delete(ctx, ops, cfg, vmName, nil); err != nil {
			rec.fail("vm-deleted", fmt.Sprint(err))
			t.Fatal(err)
		}
		d, v, _ := resourcesOf(ops, cfg.Pool, vmName, vmUUID)
		if d != 0 || v != 0 {
			rec.fail("vm-deleted", fmt.Sprintf("%d domains and %d volumes remain", d, v))
			t.Fatal("remains")
		}
		rec.pass("vm-deleted", "the VM and its two volumes are gone")
		anchor("image-immutable-after-delete")

	case "net-delete":
		ownedNet()
		if err := provision.NetworkStop(ctx, ops, netName, nil); err != nil {
			rec.fail("network-stopped", fmt.Sprint(err))
			t.Fatal(err)
		}
		if err := provision.NetworkStart(ctx, ops, netName, nil); err != nil {
			rec.fail("network-started", fmt.Sprint(err))
			t.Fatal(err)
		}
		if err := provision.NetworkAutostart(ctx, ops, netName, false); err != nil {
			rec.fail("network-autostart", fmt.Sprint(err))
			t.Fatal(err)
		}
		if n := ownedNet(); !n.Active || n.Autostart {
			rec.fail("network-autostart", fmt.Sprintf("%+v", n))
			t.Fatal("state")
		}
		rec.pass("network-lifecycle", "stop, start and autostart off worked on the managed network")
		if err := provision.NetworkDelete(ctx, ops, netName, nil); err != nil {
			rec.fail("network-deleted", fmt.Sprint(err))
			t.Fatal(err)
		}
		if err := provision.NetworkDelete(ctx, ops, netName, nil); err != nil {
			rec.fail("network-deleted", "a repeat must be success: "+err.Error())
			t.Fatal(err)
		}
		if _, err := ops.LookupNetwork(ctx, netName); cat0(err) != hypervisor.NotFound {
			rec.fail("network-deleted", fmt.Sprintf("the network is still there: %v", err))
			t.Fatal("remains")
		}
		rec.pass("network-deleted", "the network was stopped and removed; a repeat is a no-op")

	case "final":
		raw, rerr := os.ReadFile(filepath.Join(rec.out, netBeforeFile)) // #nosec G304 -- fixed name in the run's output directory
		var before []netSnap
		if rerr != nil || json.Unmarshal(raw, &before) != nil {
			rec.add("networks-unchanged", "NOT_RUN", "no "+netBeforeFile)
			break
		}
		all, _ := ops.ListNetworks(ctx)
		after := snapNets(all)
		if fmt.Sprint(before) != fmt.Sprint(after) {
			rec.fail("networks-unchanged", fmt.Sprintf("before %+v, after %+v", before, after))
			t.Fatal("networks changed")
		}
		rec.pass("networks-unchanged", fmt.Sprintf("every one of the %d pre-existing libvirt networks (including %s) has the same flags, subnet, bridge and reservations as before", len(before), cfg.Network))
		anchor("image-immutable-after")

	default:
		t.Fatalf("unknown step %q", step)
	}
}

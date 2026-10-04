//go:build linux && privileged

// These tests create real kernel WireGuard interfaces, assign real
// addresses, and install real routes. They require:
//   - Linux with WireGuard kernel support (in-tree since 5.6, or the
//     out-of-tree module loaded),
//   - CAP_NET_ADMIN (in practice: running as root, or the test binary
//     given that capability),
//   - the "privileged" build tag: go test -tags=privileged ./...
//
// The "privileged" tag does not imply root, and root does not imply the
// tag: they are independent gates checked at different times (compile time
// for the tag, syscall time for the capability). Both are required.
//
// A note on what this file does NOT attempt: a same-machine,
// same-network-namespace test where two Manager-created interfaces talk to
// each other cannot prove that IP traffic actually traverses the tunnel.
// Every address assigned with AddrAdd is automatically added to the
// kernel's implicit "local" routing table (visible via `ip route show
// table local`), which is consulted before the "main" table where
// Manager's own on-link routes live. A userspace socket sending to a
// peer's GhostwireIP that happens to be assigned to another interface *on
// this same host* will be delivered by the local-table shortcut, never
// touching wg0's crypto/transmit path at all -- so a naive send-and-receive
// test across two local Managers would pass even if Manager.addRoutes
// were completely broken. TestManagerPeerHandshake stays within what a
// single namespace can reliably prove (a real WireGuard handshake between
// two independent kernel interfaces). TestManagerRoutesPacketsOntoInterface
// proves the routing decision itself by targeting a virtual IP that is not
// locally assigned anywhere, so there is no local-table shortcut to
// confuse the result. What remains genuinely unverified on one machine is
// full end-to-end *decrypted payload delivery* between two Managers; that
// requires either two hosts (as main.go's manual test used) or per-node
// network-namespace isolation with a veth pair, which is out of scope
// here -- see the coverage notes in the accompanying review.
package wireguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestManagerUpConfiguresInterfaceAndPeer(t *testing.T) {
	localIP := mustCIDR(t, "198.51.100.1/32")
	peerIP := mustCIDR(t, "198.51.100.2/32")

	ensureTestAddressFree(t, localIP.IP)
	ensureTestAddressFree(t, peerIP.IP)

	privateKey := testPrivateKey(t)
	peerKey := testPrivateKey(t)
	peerPort := freeUDPPort(t)
	listenPort := freeUDPPort(t)
	keepalive := 2 * time.Second
	iface := uniqueInterfaceName("gwat")

	cfg := Config{
		InterfaceName: iface,
		PrivateKey:    privateKey,
		ListenPort:    listenPort,
		GhostwireIP:   localIP,
		Peers: []PeerConfig{
			{
				PublicKey:                   peerKey.PublicKey(),
				Endpoint:                    &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: peerPort},
				AllowedIPs:                  []net.IPNet{peerIP},
				PersistentKeepaliveInterval: &keepalive,
			},
		},
	}

	mgr, closeManager := newManagedTestManager(t, cfg)
	upManager(t, mgr)

	link := requireLink(t, iface)

	if _, ok := link.(*netlink.Wireguard); !ok {
		t.Fatalf(
			"interface %q has type %T, want *netlink.Wireguard",
			iface,
			link,
		)
	}

	if link.Attrs().Flags&net.FlagUp == 0 {
		t.Fatalf("interface %q is not up", iface)
	}

	assertAddressOnInterface(t, link, localIP)

	device := requireWGDevice(t, iface)

	if device.PrivateKey != privateKey {
		t.Fatal("configured private key does not match")
	}

	if device.ListenPort != listenPort {
		t.Fatalf(
			"ListenPort = %d, want %d",
			device.ListenPort,
			listenPort,
		)
	}

	if len(device.Peers) != 1 {
		t.Fatalf("peer count = %d, want 1", len(device.Peers))
	}

	peer := device.Peers[0]

	if peer.PublicKey != peerKey.PublicKey() {
		t.Fatal("peer public key does not match")
	}

	if peer.Endpoint == nil {
		t.Fatal("peer endpoint is nil")
	}

	wantEndpoint := (&net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: peerPort,
	}).String()

	if peer.Endpoint.String() != wantEndpoint {
		t.Fatalf(
			"peer endpoint = %s, want %s",
			peer.Endpoint,
			wantEndpoint,
		)
	}

	if peer.PersistentKeepaliveInterval != keepalive {
		t.Fatalf(
			"PersistentKeepaliveInterval = %s, want %s",
			peer.PersistentKeepaliveInterval,
			keepalive,
		)
	}

	assertAllowedIPs(t, peer, []net.IPNet{peerIP})
	assertRouteOnInterface(t, link, peerIP)

	closeManager()

	assertInterfaceAbsent(t, iface)
	assertExactRouteAbsent(t, peerIP)
}

func TestManagerAddPeerAndRemovePeer(t *testing.T) {
	localIP := mustCIDR(t, "198.51.100.3/32")
	peerIP := mustCIDR(t, "198.51.100.4/32")

	ensureTestAddressFree(t, localIP.IP)
	ensureTestAddressFree(t, peerIP.IP)

	cfg := Config{
		InterfaceName: uniqueInterfaceName("gwap"),
		PrivateKey:    testPrivateKey(t),
		ListenPort:    freeUDPPort(t),
		GhostwireIP:   localIP,
	}

	mgr, closeManager := newManagedTestManager(t, cfg)
	upManager(t, mgr)

	link := requireLink(t, cfg.InterfaceName)

	peerKey := testPrivateKey(t)
	keepalive := 3 * time.Second

	peer := PeerConfig{
		PublicKey:                   peerKey.PublicKey(),
		Endpoint:                    &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: freeUDPPort(t)},
		AllowedIPs:                  []net.IPNet{peerIP},
		PersistentKeepaliveInterval: &keepalive,
	}

	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer() failed: %v", err)
	}

	device := requireWGDevice(t, cfg.InterfaceName)

	if len(device.Peers) != 1 {
		t.Fatalf(
			"peer count after AddPeer() = %d, want 1",
			len(device.Peers),
		)
	}

	addedPeer := device.Peers[0]

	if addedPeer.PublicKey != peerKey.PublicKey() {
		t.Fatal("AddPeer() configured the wrong public key")
	}

	assertAllowedIPs(t, addedPeer, peer.AllowedIPs)
	assertRouteOnInterface(t, link, peerIP)

	if err := mgr.RemovePeer(peer); err != nil {
		t.Fatalf("RemovePeer() failed: %v", err)
	}

	device = requireWGDevice(t, cfg.InterfaceName)

	if len(device.Peers) != 0 {
		t.Fatalf(
			"peer count after RemovePeer() = %d, want 0",
			len(device.Peers),
		)
	}

	assertExactRouteAbsent(t, peerIP)

	closeManager()
	assertInterfaceAbsent(t, cfg.InterfaceName)
}

// TestManagerAddPeerUpdatesAllowedIPsAndRoutes is the regression test for
// the bug AddPeer's kernel-read-then-diff logic exists to fix: updating an
// existing peer's AllowedIPs (which ReplaceAllowedIPs makes a full
// replacement at the WireGuard layer, not a merge) must make the OS
// routing table match exactly -- dropping routes for AllowedIPs that are
// no longer present, adding routes for ones that are newly present, and
// leaving routes for ones that are unchanged alone, without touching any
// other peer's routes.
//
// No other test in this file updates an already-configured peer's
// AllowedIPs a second time, so none of them would notice a regression back
// to "add the new routes and never remove the old ones" (the original
// bug), or any other broken variant of the diff.
func TestManagerAddPeerUpdatesAllowedIPsAndRoutes(t *testing.T) {
	localIP := mustCIDR(t, "198.51.100.60/32")
	unrelatedIP := mustCIDR(t, "198.51.100.61/32")
	keptIP := mustCIDR(t, "198.51.100.62/32")
	droppedIP := mustCIDR(t, "198.51.100.63/32")
	addedIP := mustCIDR(t, "198.51.100.64/32")

	for _, ip := range []net.IP{localIP.IP, unrelatedIP.IP, keptIP.IP, droppedIP.IP, addedIP.IP} {
		ensureTestAddressFree(t, ip)
	}

	cfg := Config{
		InterfaceName: uniqueInterfaceName("gwup"),
		PrivateKey:    testPrivateKey(t),
		ListenPort:    freeUDPPort(t),
		GhostwireIP:   localIP,
	}

	mgr, closeManager := newManagedTestManager(t, cfg)
	upManager(t, mgr)
	link := requireLink(t, cfg.InterfaceName)

	// An unrelated peer, added first and never touched again, so its
	// state can be checked at the end to prove the target peer's update
	// didn't disturb it (point 8).
	unrelatedKey := testPrivateKey(t)
	unrelatedPeer := PeerConfig{
		PublicKey:  unrelatedKey.PublicKey(),
		Endpoint:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: freeUDPPort(t)},
		AllowedIPs: []net.IPNet{unrelatedIP},
	}

	if err := mgr.AddPeer(unrelatedPeer); err != nil {
		t.Fatalf("adding unrelated peer failed: %v", err)
	}

	targetKey := testPrivateKey(t)
	initial := PeerConfig{
		PublicKey:  targetKey.PublicKey(),
		Endpoint:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: freeUDPPort(t)},
		AllowedIPs: []net.IPNet{keptIP, droppedIP}, // point 11: multiple AllowedIPs
	}

	// 1: add a new peer with initial AllowedIPs.
	if err := mgr.AddPeer(initial); err != nil {
		t.Fatalf("initial AddPeer() failed: %v", err)
	}

	// 2: the routes for its initial AllowedIPs exist.
	assertRouteOnInterface(t, link, keptIP)
	assertRouteOnInterface(t, link, droppedIP)

	// 3: update the same peer (same PublicKey) with a different
	// AllowedIPs set: keptIP stays, droppedIP goes away, addedIP is new.
	updated := PeerConfig{
		PublicKey:  targetKey.PublicKey(),
		Endpoint:   initial.Endpoint,
		AllowedIPs: []net.IPNet{keptIP, addedIP},
	}

	if err := mgr.AddPeer(updated); err != nil {
		t.Fatalf("update AddPeer() failed: %v", err)
	}

	// 4: the route for the dropped AllowedIP is gone. This is the literal
	// stale-route bug: without the fix, this route is what gets left
	// behind forever.
	assertExactRouteAbsent(t, droppedIP)

	// 5: the route for the newly added AllowedIP exists.
	assertRouteOnInterface(t, link, addedIP)

	// 6: the route for the AllowedIP present in both the old and new sets
	// was never removed and recreated -- it's just still there.
	assertRouteOnInterface(t, link, keptIP)

	// 7: the WireGuard peer itself has exactly the updated AllowedIPs --
	// ReplaceAllowedIPs means droppedIP must be gone at the WireGuard
	// layer too, not just at the routing layer.
	device := requireWGDevice(t, cfg.InterfaceName)
	assertAllowedIPs(
		t,
		requirePeerByKey(t, device, targetKey.PublicKey()),
		[]net.IPNet{keptIP, addedIP},
	)

	// 8: the unrelated peer's route and AllowedIPs were never touched.
	assertRouteOnInterface(t, link, unrelatedIP)
	assertAllowedIPs(
		t,
		requirePeerByKey(t, device, unrelatedKey.PublicKey()),
		[]net.IPNet{unrelatedIP},
	)

	// 9: updating a peer without changing its AllowedIPs must be a true
	// no-op at the routing layer -- in particular it must not error out
	// trying to add a route that's already there.
	if err := mgr.AddPeer(updated); err != nil {
		t.Fatalf("no-op update AddPeer() failed: %v", err)
	}

	assertRouteOnInterface(t, link, keptIP)
	assertRouteOnInterface(t, link, addedIP)

	// 10: removing a peer after it's been updated must clean up the
	// routes for what is actually configured now (keptIP, addedIP), not
	// what was configured originally. The PeerConfig passed to
	// RemovePeer deliberately carries no AllowedIPs at all, to prove
	// RemovePeer reads the peer's real state from the kernel rather than
	// trusting a (possibly stale, possibly empty) caller-supplied
	// AllowedIPs -- the same class of bug AddPeer was fixed for.
	if err := mgr.RemovePeer(PeerConfig{PublicKey: targetKey.PublicKey()}); err != nil {
		t.Fatalf("RemovePeer() after update failed: %v", err)
	}

	assertExactRouteAbsent(t, keptIP)
	assertExactRouteAbsent(t, addedIP)
	assertRouteOnInterface(t, link, unrelatedIP)

	closeManager()

	assertInterfaceAbsent(t, cfg.InterfaceName)
	assertExactRouteAbsent(t, unrelatedIP)
}

// TestManagerAddPeerWithoutEndpoint covers a case none of the original
// drafts exercised: PeerConfig.Endpoint's doc comment in manager.go
// explicitly says Endpoint may be nil "if the endpoint is not yet known
// (e.g. pending NAT traversal)". A device agent that has learned a peer's
// public key and AllowedIPs from the coordination server, but not yet its
// address, needs AddPeer to work with Endpoint left nil -- kernel
// WireGuard allows a peer with no endpoint (it will accept an incoming
// handshake and learn the endpoint from it, or wait for the endpoint to be
// filled in by a later AddPeer/ConfigureDevice call). This test only
// checks that Manager accepts and correctly stores that state; it does not
// attempt a handshake, since there is deliberately no reachable peer.
func TestManagerAddPeerWithoutEndpoint(t *testing.T) {
	localIP := mustCIDR(t, "198.51.100.20/32")
	peerIP := mustCIDR(t, "198.51.100.21/32")

	ensureTestAddressFree(t, localIP.IP)
	ensureTestAddressFree(t, peerIP.IP)

	cfg := Config{
		InterfaceName: uniqueInterfaceName("gwnoep"),
		PrivateKey:    testPrivateKey(t),
		ListenPort:    freeUDPPort(t),
		GhostwireIP:   localIP,
	}

	mgr, closeManager := newManagedTestManager(t, cfg)
	upManager(t, mgr)

	link := requireLink(t, cfg.InterfaceName)

	peer := PeerConfig{
		PublicKey:  testPrivateKey(t).PublicKey(),
		Endpoint:   nil,
		AllowedIPs: []net.IPNet{peerIP},
	}

	if err := mgr.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer() with nil Endpoint failed: %v", err)
	}

	device := requireWGDevice(t, cfg.InterfaceName)

	if len(device.Peers) != 1 {
		t.Fatalf("peer count = %d, want 1", len(device.Peers))
	}

	if device.Peers[0].Endpoint != nil {
		t.Fatalf(
			"Endpoint = %v, want nil for a peer with no known address yet",
			device.Peers[0].Endpoint,
		)
	}

	assertAllowedIPs(t, device.Peers[0], peer.AllowedIPs)
	assertRouteOnInterface(t, link, peerIP)

	closeManager()
	assertInterfaceAbsent(t, cfg.InterfaceName)
}

func TestManagerUpIsRepeatable(t *testing.T) {
	localIP := mustCIDR(t, "198.51.100.5/32")
	peerIP := mustCIDR(t, "198.51.100.6/32")

	ensureTestAddressFree(t, localIP.IP)
	ensureTestAddressFree(t, peerIP.IP)

	peerKey := testPrivateKey(t)

	cfg := Config{
		InterfaceName: uniqueInterfaceName("gwre"),
		PrivateKey:    testPrivateKey(t),
		ListenPort:    freeUDPPort(t),
		GhostwireIP:   localIP,
		Peers: []PeerConfig{
			{
				PublicKey:  peerKey.PublicKey(),
				Endpoint:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: freeUDPPort(t)},
				AllowedIPs: []net.IPNet{peerIP},
			},
		},
	}

	mgr, closeManager := newManagedTestManager(t, cfg)

	upManager(t, mgr)
	assertInterfaceState(t, cfg.InterfaceName, localIP)

	if err := mgr.Up(); err != nil {
		t.Fatalf("second Up() failed: %v", err)
	}

	assertInterfaceState(t, cfg.InterfaceName, localIP)

	device := requireWGDevice(t, cfg.InterfaceName)

	if len(device.Peers) != 1 {
		t.Fatalf(
			"peer count after second Up() = %d, want 1",
			len(device.Peers),
		)
	}

	assertAllowedIPs(t, device.Peers[0], []net.IPNet{peerIP})
	assertExactRouteOnInterfaceName(t, cfg.InterfaceName, peerIP)

	closeManager()

	assertInterfaceAbsent(t, cfg.InterfaceName)
	assertExactRouteAbsent(t, peerIP)
}

func TestManagerPeerHandshake(t *testing.T) {
	localA := mustCIDR(t, "198.51.100.7/32")
	localB := mustCIDR(t, "198.51.100.8/32")

	ensureTestAddressFree(t, localA.IP)
	ensureTestAddressFree(t, localB.IP)

	keyA := testPrivateKey(t)
	keyB := testPrivateKey(t)

	portA := freeUDPPort(t)
	portB := freeUDPPort(t)
	keepalive := 1 * time.Second

	cfgA := Config{
		InterfaceName: uniqueInterfaceName("gwaa"),
		PrivateKey:    keyA,
		ListenPort:    portA,
		GhostwireIP:   localA,
		Peers: []PeerConfig{
			{
				PublicKey:                   keyB.PublicKey(),
				Endpoint:                    &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: portB},
				AllowedIPs:                  []net.IPNet{localB},
				PersistentKeepaliveInterval: &keepalive,
			},
		},
	}

	cfgB := Config{
		InterfaceName: uniqueInterfaceName("gwbb"),
		PrivateKey:    keyB,
		ListenPort:    portB,
		GhostwireIP:   localB,
		Peers: []PeerConfig{
			{
				PublicKey:                   keyA.PublicKey(),
				Endpoint:                    &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: portA},
				AllowedIPs:                  []net.IPNet{localA},
				PersistentKeepaliveInterval: &keepalive,
			},
		},
	}

	mgrA, closeA := newManagedTestManager(t, cfgA)
	mgrB, closeB := newManagedTestManager(t, cfgB)

	upManager(t, mgrA)
	upManager(t, mgrB)

	wgClient := requireWGClient(t)

	waitForHandshake(
		t,
		wgClient,
		cfgA.InterfaceName,
		keyB.PublicKey(),
		6*time.Second,
	)

	waitForHandshake(
		t,
		wgClient,
		cfgB.InterfaceName,
		keyA.PublicKey(),
		6*time.Second,
	)

	deviceA := requireWGDeviceWithClient(
		t,
		wgClient,
		cfgA.InterfaceName,
	)

	deviceB := requireWGDeviceWithClient(
		t,
		wgClient,
		cfgB.InterfaceName,
	)

	assertAllowedIPs(
		t,
		requirePeerByKey(t, deviceA, keyB.PublicKey()),
		[]net.IPNet{localB},
	)

	assertAllowedIPs(
		t,
		requirePeerByKey(t, deviceB, keyA.PublicKey()),
		[]net.IPNet{localA},
	)

	closeB()
	closeA()

	assertInterfaceAbsent(t, cfgB.InterfaceName)
	assertInterfaceAbsent(t, cfgA.InterfaceName)
}

// TestManagerRoutesPacketsOntoInterface targets the property main.go's
// manual test called "route traffic through the peer" -- but, as explained
// in the file-level comment above, it does so without a second local
// Manager, because a same-namespace two-Manager traffic test would be
// invalidated by Linux's local-table shortcut for any address assigned to
// an interface on this host.
//
// Instead, peerVirtualIP is deliberately never assigned to anything. The
// only way the kernel can have a route to it at all is the on-link route
// Manager.addRoutes installs for the peer's AllowedIPs. Sending a UDP
// datagram to that address and observing wg0's own tx_packets counter
// increase (via the stable /sys/class/net/<iface>/statistics ABI) proves
// the OS routing decision -- the thing unique to Manager, as opposed to
// wgctrl/kernel WireGuard behavior -- actually works, independent of
// whether a real peer exists on the other end to decrypt anything.
func TestManagerRoutesPacketsOntoInterface(t *testing.T) {
	localIP := mustCIDR(t, "198.51.100.40/32")
	peerVirtualIP := mustCIDR(t, "198.51.100.41/32")

	ensureTestAddressFree(t, localIP.IP)
	ensureTestAddressFree(t, peerVirtualIP.IP)

	cfg := Config{
		InterfaceName: uniqueInterfaceName("gwrt"),
		PrivateKey:    testPrivateKey(t),
		ListenPort:    freeUDPPort(t),
		GhostwireIP:   localIP,
		Peers: []PeerConfig{
			{
				PublicKey:  testPrivateKey(t).PublicKey(),
				Endpoint:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: freeUDPPort(t)},
				AllowedIPs: []net.IPNet{peerVirtualIP},
			},
		},
	}

	mgr, closeManager := newManagedTestManager(t, cfg)
	upManager(t, mgr)
	defer closeManager()

	before, err := ifaceTxPackets(cfg.InterfaceName)
	if err != nil {
		t.Fatalf("reading tx_packets before send: %v", err)
	}

	// Port 51999 is arbitrary: nothing needs to be listening. A UDP
	// datagram is fire-and-forget, so this only fails synchronously if
	// there is genuinely no route to the destination.
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: peerVirtualIP.IP, Port: 51999})
	if err != nil {
		t.Fatalf(
			"dialing peer virtual IP %s: %v (no route to it would mean "+
				"addRoutes did not install the expected on-link route)",
			peerVirtualIP.IP,
			err,
		)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("routing-probe")); err != nil {
		t.Fatalf("writing probe packet: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		after, err := ifaceTxPackets(cfg.InterfaceName)
		if err != nil {
			t.Fatalf("reading tx_packets after send: %v", err)
		}

		if after > before {
			break
		}

		if time.Now().After(deadline) {
			t.Fatalf(
				"tx_packets on %q did not increase after sending to a "+
					"peer's AllowedIPs (before=%d, after=%d); the OS route "+
					"installed by addRoutes does not appear to be "+
					"directing traffic onto the interface",
				cfg.InterfaceName,
				before,
				after,
			)
		}

		time.Sleep(50 * time.Millisecond)
	}
}

// TestManagerUpCleansUpAfterFailure verifies that Up() tears down a
// partially-configured interface itself when a later step fails, rather
// than relying on the caller to notice and call Close().
//
// (An earlier version of this test was named TestManagerCloseAfterFailedUp
// and checked interface absence only after calling Close(). That can't
// actually distinguish Up()'s own cleanup from Close()'s, since Close() is
// called either way in that arrangement -- a regression that silently
// removed Up()'s self-cleanup would still pass, because Close() would
// still clean up the leftover interface afterward and the test never
// looked in between. Checking absence immediately after the failed Up()
// call, before Close() ever runs, is what isolates the two.)
//
// The original draft simulated failure with a malformed net.IPNet (a Mask
// of the wrong byte length) passed as GhostwireIP. That is fragile in two
// ways: (1) net.IPMask.Size() returns (0, 0) for a mask that is neither 4
// nor 16 bytes, which some netlink code paths may interpret as "/0" and
// silently *succeed* rather than fail, defeating the test's premise
// outright; and (2) even when it does fail, the failure mode depends on
// internal behavior of vishvananda/netlink and the running kernel version
// that isn't part of Manager's documented contract, so a passing or
// failing result here would not reliably say anything about manager.go.
//
// This version forces a specific, well-understood, portable failure
// instead: it holds the configured ListenPort open with a plain UDP
// socket before calling Up(), so the device-configuration step
// (ConfigureDevice, which asks the kernel to bind that port) fails with
// EADDRINUSE. That failure happens *after* LinkAdd/AddrAdd/LinkSetUp have
// already succeeded, so this also exercises a later, more realistic
// partial-failure state than the original (interface exists, is
// addressed, and is up, but has no WireGuard peers configured) -- without
// changing manager.go at all.
func TestManagerUpCleansUpAfterFailure(t *testing.T) {
	localIP := mustCIDR(t, "198.51.100.50/32")
	ensureTestAddressFree(t, localIP.IP)

	occupied, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("occupying a UDP port: %v", err)
	}
	defer occupied.Close()

	collidingPort := occupied.LocalAddr().(*net.UDPAddr).Port

	iface := uniqueInterfaceName("gwerr")
	cfg := Config{
		InterfaceName: iface,
		PrivateKey:    testPrivateKey(t),
		ListenPort:    collidingPort,
		GhostwireIP:   localIP,
	}

	mgr, closeManager := newManagedTestManager(t, cfg)

	err = mgr.Up()
	if err == nil {
		t.Fatal("Up() unexpectedly succeeded with its listen port already bound by another socket")
	}

	if skip, reason := classifyUpFailure(err); skip {
		t.Skipf("privileged networking environment unavailable: %s", reason)
	}

	if !strings.Contains(err.Error(), "configuring device") {
		t.Fatalf(
			"Up() failed at an unexpected stage: %v (want a failure while "+
				"configuring the device, i.e. binding the already-occupied "+
				"listen port)",
			err,
		)
	}

	// Isolate Up()'s own cleanup from Close()'s: check this before
	// closeManager runs at all.
	assertInterfaceAbsent(t, iface)

	closeManager()
}

// TestManagerCloseIsIdempotentAndRevokesFurtherUse covers Close()'s two
// documented lifecycle guarantees that no other test touches: calling it
// twice is a harmless no-op, and every other method returns ErrClosed
// afterward instead of operating on freed kernel state (or, before the
// closed flag existed, panicking on a nil wgctrl client).
func TestManagerCloseIsIdempotentAndRevokesFurtherUse(t *testing.T) {
	localIP := mustCIDR(t, "198.51.100.70/32")
	ensureTestAddressFree(t, localIP.IP)

	cfg := Config{
		InterfaceName: uniqueInterfaceName("gwcl"),
		PrivateKey:    testPrivateKey(t),
		ListenPort:    freeUDPPort(t),
		GhostwireIP:   localIP,
	}

	mgr, closeManager := newManagedTestManager(t, cfg)
	upManager(t, mgr)
	closeManager()

	if err := mgr.Close(); err != nil {
		t.Fatalf("second Close() call returned an error: %v, want nil", err)
	}

	if err := mgr.Up(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Up() after Close() = %v, want ErrClosed", err)
	}

	peer := PeerConfig{PublicKey: testPrivateKey(t).PublicKey()}

	if err := mgr.AddPeer(peer); !errors.Is(err, ErrClosed) {
		t.Fatalf("AddPeer() after Close() = %v, want ErrClosed", err)
	}

	if err := mgr.RemovePeer(peer); !errors.Is(err, ErrClosed) {
		t.Fatalf("RemovePeer() after Close() = %v, want ErrClosed", err)
	}
}

// TestManagerRejectsPeerOperationsBeforeUp covers the panic-turned-error
// fix in AddPeer/RemovePeer: calling either before Up() has ever
// succeeded used to dereference a nil netlink.Link inside addRoutes/
// delRoutes. It should now fail cleanly with ErrNotUp instead.
func TestManagerRejectsPeerOperationsBeforeUp(t *testing.T) {
	localIP := mustCIDR(t, "198.51.100.71/32")
	ensureTestAddressFree(t, localIP.IP)

	cfg := Config{
		InterfaceName: uniqueInterfaceName("gwnu"),
		PrivateKey:    testPrivateKey(t),
		ListenPort:    freeUDPPort(t),
		GhostwireIP:   localIP,
	}

	mgr, err := New(cfg)
	if err != nil {
		if isMissingWireGuardKernelSupport(err) {
			t.Skipf("WireGuard control interface unavailable: %v", err)
		}
		t.Fatalf("New() failed: %v", err)
	}
	t.Cleanup(func() {
		if err := mgr.Close(); err != nil {
			t.Errorf("Close() failed: %v", err)
		}
	})

	peer := PeerConfig{PublicKey: testPrivateKey(t).PublicKey()}

	if err := mgr.AddPeer(peer); !errors.Is(err, ErrNotUp) {
		t.Fatalf("AddPeer() before Up() = %v, want ErrNotUp", err)
	}

	if err := mgr.RemovePeer(peer); !errors.Is(err, ErrNotUp) {
		t.Fatalf("RemovePeer() before Up() = %v, want ErrNotUp", err)
	}
}

func newManagedTestManager(t *testing.T, cfg Config) (*Manager, func()) {
	t.Helper()

	mgr, err := New(cfg)
	if err != nil {
		if isMissingWireGuardKernelSupport(err) {
			t.Skipf(
				"WireGuard control interface unavailable: %v",
				err,
			)
		}

		t.Fatalf("New() failed: %v", err)
	}

	closed := false

	closeManager := func() {
		t.Helper()

		if closed {
			return
		}

		err := mgr.Close()
		closed = true

		if err != nil {
			t.Errorf("Close() failed: %v", err)
		}
	}

	t.Cleanup(func() {
		if closed {
			return
		}

		if err := mgr.Close(); err != nil {
			t.Errorf("test cleanup: Close() failed: %v", err)
		}

		closed = true
	})

	return mgr, closeManager
}

func upManager(t *testing.T, mgr *Manager) {
	t.Helper()

	err := mgr.Up()
	if err == nil {
		return
	}

	if skip, reason := classifyUpFailure(err); skip {
		t.Skipf("privileged networking environment unavailable: %s", reason)
	}

	t.Fatalf("Up() failed: %v", err)
}

func requireLink(t *testing.T, ifaceName string) netlink.Link {
	t.Helper()

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		t.Fatalf(
			"looking up interface %q: %v",
			ifaceName,
			err,
		)
	}

	return link
}

func requireWGDevice(t *testing.T, ifaceName string) *wgtypes.Device {
	t.Helper()

	client := requireWGClient(t)
	return requireWGDeviceWithClient(t, client, ifaceName)
}

func requireWGDeviceWithClient(
	t *testing.T,
	client *wgctrl.Client,
	ifaceName string,
) *wgtypes.Device {
	t.Helper()

	device, err := client.Device(ifaceName)
	if err != nil {
		t.Fatalf(
			"reading WireGuard device %q: %v",
			ifaceName,
			err,
		)
	}

	return device
}

func requireWGClient(t *testing.T) *wgctrl.Client {
	t.Helper()

	client, err := wgctrl.New()
	if err != nil {
		if isMissingWireGuardKernelSupport(err) {
			t.Skipf(
				"WireGuard control interface unavailable: %v",
				err,
			)
		}

		t.Fatalf("opening wgctrl client: %v", err)
	}

	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing wgctrl client: %v", err)
		}
	})

	return client
}

func assertAddressOnInterface(
	t *testing.T,
	link netlink.Link,
	want net.IPNet,
) {
	t.Helper()

	addrs, err := netlink.AddrList(
		link,
		netlink.FAMILY_V4,
	)
	if err != nil {
		t.Fatalf(
			"listing addresses on %q: %v",
			link.Attrs().Name,
			err,
		)
	}

	for _, addr := range addrs {
		if addr.IPNet != nil &&
			addr.IPNet.String() == want.String() {
			return
		}
	}

	t.Fatalf(
		"interface %q does not have address %s",
		link.Attrs().Name,
		want.String(),
	)
}

func assertInterfaceState(
	t *testing.T,
	ifaceName string,
	wantIP net.IPNet,
) {
	t.Helper()

	link := requireLink(t, ifaceName)

	if link.Attrs().Flags&net.FlagUp == 0 {
		t.Fatalf(
			"interface %q is not up",
			ifaceName,
		)
	}

	assertAddressOnInterface(t, link, wantIP)
}

// assertAllowedIPs checks that peer.AllowedIPs contains exactly the
// entries in want, ignoring order.
//
// Order-independence matters here: the kernel's AllowedIPs trie is under
// no obligation to report entries back in the order they were configured
// in, and wgctrl.Device() just returns whatever order the kernel dumps
// them in. A positional comparison (as an earlier version of this helper
// did) would flake on any peer with more than one AllowedIP purely from
// kernel-side reordering, with no actual bug involved -- exactly the
// scenario TestManagerAddPeerUpdatesAllowedIPsAndRoutes needs to exercise
// reliably.
func assertAllowedIPs(
	t *testing.T,
	peer wgtypes.Peer,
	want []net.IPNet,
) {
	t.Helper()

	got := ipNetStrings(peer.AllowedIPs)
	wantStrings := ipNetStrings(want)

	sort.Strings(got)
	sort.Strings(wantStrings)

	if len(got) != len(wantStrings) {
		t.Fatalf("AllowedIPs = %v, want %v", got, wantStrings)
		return
	}

	for i := range got {
		if got[i] != wantStrings[i] {
			t.Fatalf("AllowedIPs = %v, want %v", got, wantStrings)
			return
		}
	}
}

func ipNetStrings(ipNets []net.IPNet) []string {
	out := make([]string, len(ipNets))
	for i, ipNet := range ipNets {
		out[i] = ipNet.String()
	}
	return out
}

func requirePeerByKey(
	t *testing.T,
	device *wgtypes.Device,
	key wgtypes.Key,
) wgtypes.Peer {
	t.Helper()

	for _, peer := range device.Peers {
		if peer.PublicKey == key {
			return peer
		}
	}

	t.Fatalf(
		"peer %s not found on device %q",
		key.String(),
		device.Name,
	)

	return wgtypes.Peer{}
}

func assertRouteOnInterface(
	t *testing.T,
	link netlink.Link,
	want net.IPNet,
) {
	t.Helper()

	routes, err := netlink.RouteList(
		link,
		netlink.FAMILY_V4,
	)
	if err != nil {
		t.Fatalf(
			"listing IPv4 routes on %q: %v",
			link.Attrs().Name,
			err,
		)
	}

	for _, route := range routes {
		if route.Dst != nil &&
			route.Dst.String() == want.String() &&
			route.Scope == netlink.SCOPE_LINK {
			return
		}
	}

	t.Fatalf(
		"route %s not found on interface %q",
		want,
		link.Attrs().Name,
	)
}

func assertExactRouteOnInterfaceName(
	t *testing.T,
	ifaceName string,
	want net.IPNet,
) {
	t.Helper()

	assertRouteOnInterface(
		t,
		requireLink(t, ifaceName),
		want,
	)
}

func exactRouteExists(
	want net.IPNet,
) (bool, error) {
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{Dst: &want},
		netlink.RT_FILTER_DST,
	)
	if err != nil {
		return false, err
	}

	for _, route := range routes {
		if route.Dst != nil &&
			route.Dst.String() == want.String() {
			return true, nil
		}
	}

	return false, nil
}

func assertExactRouteAbsent(
	t *testing.T,
	want net.IPNet,
) {
	t.Helper()

	exists, err := exactRouteExists(want)
	if err != nil {
		t.Fatalf(
			"checking route %s: %v",
			want,
			err,
		)
	}

	if exists {
		t.Fatalf(
			"route %s still exists",
			want,
		)
	}
}

// ensureTestAddressFree skips the test if ip is already assigned to any
// interface on the host, or if a route to it already exists.
//
// The route check matters alongside the address check, not instead of it:
// these tests reuse the same small set of hardcoded TEST-NET-2 addresses
// every run, and Manager.Up/AddPeer install routes independently of
// address assignment. If a previous run of this suite was killed non-
// gracefully (test timeout, OOM, a forcibly torn-down CI container) rather
// than completing its own Close()-triggered cleanup, it could leave a
// route behind for one of these addresses without that address ever being
// assigned to an interface -- which the address check alone would not
// catch. A subsequent run's RouteAdd for the same destination would then
// fail with a "file exists" error that looks like a manager.go bug but is
// actually stale residue from an earlier run.
func ensureTestAddressFree(
	t *testing.T,
	ip net.IP,
) {
	t.Helper()

	links, err := netlink.LinkList()
	if err != nil {
		t.Fatalf("listing interfaces: %v", err)
	}

	for _, link := range links {
		addrs, err := netlink.AddrList(
			link,
			netlink.FAMILY_V4,
		)
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if addr.IPNet != nil &&
				addr.IPNet.IP.Equal(ip) {
				t.Skipf(
					"test address %s is already assigned to %q",
					ip,
					link.Attrs().Name,
				)
			}
		}
	}

	hostRoute := net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}

	exists, err := exactRouteExists(hostRoute)
	if err != nil {
		t.Fatalf("checking for a pre-existing route to %s: %v", ip, err)
	}

	if exists {
		t.Skipf(
			"a route to %s already exists (likely left over from a "+
				"previous, non-gracefully-terminated test run); remove "+
				"it before re-running the suite",
			ip,
		)
	}
}

func assertInterfaceAbsent(
	t *testing.T,
	ifaceName string,
) {
	t.Helper()

	link, err := netlink.LinkByName(ifaceName)
	if err == nil {
		t.Fatalf(
			"interface %q still exists (type %T, index %d)",
			ifaceName,
			link,
			link.Attrs().Index,
		)
	}

	message := strings.ToLower(err.Error())

	if !strings.Contains(message, "not found") &&
		!strings.Contains(message, "no such device") {
		t.Fatalf(
			"checking removal of interface %q: %v",
			ifaceName,
			err,
		)
	}
}

// freeUDPPort returns a port that was free at the moment it was checked.
// There is an inherent, unavoidable TOCTOU gap between this call returning
// and the port actually being (re)used by Manager: something else on the
// machine could bind it in between, causing a rare, environment-dependent
// flake. This is accepted as a known limitation rather than "fixed",
// because the only way to fully close the gap -- holding the socket open
// across the Up() call -- is incompatible with handing the same port
// number to the kernel WireGuard device, which needs to bind it itself.
// (TestManagerUpCleansUpAfterFailure uses the hold-it-open version
// deliberately, specifically because it *wants* the collision.)
func freeUDPPort(t *testing.T) int {
	t.Helper()

	conn, err := net.ListenUDP(
		"udp4",
		&net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 0,
		},
	)
	if err != nil {
		t.Fatalf("allocating UDP port: %v", err)
	}
	defer conn.Close()

	return conn.LocalAddr().(*net.UDPAddr).Port
}

func uniqueInterfaceName(prefix string) string {
	suffix := fmt.Sprintf(
		"%x",
		time.Now().UnixNano()&0xffffff,
	)

	name := prefix + suffix

	if len(name) > 15 {
		name = name[:15]
	}

	return name
}

func waitForHandshake(
	t *testing.T,
	client *wgctrl.Client,
	ifaceName string,
	peerKey wgtypes.Key,
	timeout time.Duration,
) {
	t.Helper()

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		device, err := client.Device(ifaceName)
		if err != nil {
			t.Fatalf(
				"reading device %q while waiting for handshake: %v",
				ifaceName,
				err,
			)
		}

		for _, peer := range device.Peers {
			if peer.PublicKey == peerKey &&
				!peer.LastHandshakeTime.IsZero() {
				return
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	device, err := client.Device(ifaceName)
	if err != nil {
		t.Fatalf(
			"reading device %q after handshake timeout: %v",
			ifaceName,
			err,
		)
	}

	for _, peer := range device.Peers {
		if peer.PublicKey == peerKey {
			t.Fatalf(
				"peer %s on %q did not complete a WireGuard handshake within %s; last handshake: %v",
				peerKey,
				ifaceName,
				timeout,
				peer.LastHandshakeTime,
			)
		}
	}

	t.Fatalf(
		"peer %s not present on device %q after handshake timeout",
		peerKey,
		ifaceName,
	)
}

// ifaceTxPackets reads a network interface's transmit-packet counter via
// the stable /sys/class/net/<iface>/statistics ABI. Used by
// TestManagerRoutesPacketsOntoInterface to observe, without needing a
// second machine or a network namespace, that a packet was actually handed
// to the interface for transmission.
func ifaceTxPackets(ifaceName string) (uint64, error) {
	path := filepath.Join("/sys/class/net", ifaceName, "statistics", "tx_packets")

	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", path, err)
	}

	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", path, err)
	}

	return value, nil
}

// isPrivilegeError reports whether err indicates the calling process lacks
// the capability (in practice: CAP_NET_ADMIN, usually via root) required
// for the network operation that was attempted.
//
// This check is intentionally narrow: it does NOT treat "no such device",
// "not supported", or similar as privilege errors. Once an operation has
// gotten far enough to be a *capability* question rather than a *does
// WireGuard exist at all* question, those errors are far more likely to
// indicate a genuine bug in manager.go (for example, a route or peer
// operation racing against an interface that unexpectedly no longer
// exists) than an environment limitation, and should fail the test loudly
// instead of being silently skipped.
func isPrivilegeError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return true
	}

	message := strings.ToLower(err.Error())

	return strings.Contains(message, "operation not permitted") ||
		strings.Contains(message, "permission denied")
}

// isMissingWireGuardKernelSupport reports whether err indicates this
// machine cannot create/use a WireGuard interface at all: no kernel
// module, no "wireguard" generic-netlink family, or no permission to even
// ask. This is deliberately broader than isPrivilegeError, and that breadth
// is only safe to apply to the specific operations that establish WHETHER
// WireGuard is usable in the first place: opening the wgctrl client
// (New()), and the initial interface-creation step of Up(). See
// classifyUpFailure, which is what enforces that scoping for Up().
func isMissingWireGuardKernelSupport(err error) bool {
	if err == nil {
		return false
	}

	for _, target := range []error{
		syscall.ENODEV,
		syscall.EOPNOTSUPP,
		syscall.EPROTONOSUPPORT,
	} {
		if errors.Is(err, target) {
			return true
		}
	}

	message := strings.ToLower(err.Error())

	for _, fragment := range []string{
		"no such device",
		"operation not supported",
		"protocol not supported",
	} {
		if strings.Contains(message, fragment) {
			return true
		}
	}

	return isPrivilegeError(err)
}

// classifyUpFailure decides how a test should react to an error returned
// by Manager.Up.
//
// manager.go wraps each stage of Up with a distinct prefix ("creating
// interface", "assigning ... to", "bringing up", "configuring device"), so
// the wrapped error text tells us which stage failed. Only a failure at
// the "creating interface" stage -- the one place where "this environment
// has no usable WireGuard support" would first show up -- is judged
// against the broad isMissingWireGuardKernelSupport check. Every later
// stage is judged only against the narrow isPrivilegeError check, so an
// ENODEV or EOPNOTSUPP surfacing from address assignment, bringing the
// link up, or device configuration is treated as a real failure, not
// quietly skipped.
//
// This couples the check to manager.go's current error-wrapping text; if
// that wrapper text changes, update the "creating interface" substring
// here to match.
func classifyUpFailure(err error) (skip bool, reason string) {
	if err == nil {
		return false, ""
	}

	if strings.Contains(err.Error(), "creating interface") &&
		isMissingWireGuardKernelSupport(err) {
		return true, err.Error()
	}

	if isPrivilegeError(err) {
		return true, err.Error()
	}

	return false, ""
}

//go:build linux

// Package wireguard configures a native Linux kernel WireGuard interface.
// It has no knowledge of CLI flags, hardcoded keys, or a coordination
// server. Callers supply fully-resolved Config values.
package wireguard

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ErrClosed is returned by Up, AddPeer, and RemovePeer once Close has been
// called on the Manager. A closed Manager holds no kernel resources and
// cannot be reused.
var ErrClosed = errors.New("wireguard: manager is closed")

// ErrNotUp is returned by AddPeer and RemovePeer when called before Up has
// ever completed successfully on this Manager. There is no interface yet
// for a route change to attach to.
var ErrNotUp = errors.New("wireguard: interface is not up")

// PeerConfig describes one WireGuard peer.
type PeerConfig struct {
	PublicKey wgtypes.Key

	// Endpoint is the peer's physical/LAN address, e.g. 192.168.1.20:51820.
	// Nil if the endpoint is not yet known (e.g. pending NAT traversal).
	Endpoint *net.UDPAddr

	// AllowedIPs are Ghostwire virtual IPs/CIDRs this peer is permitted for,
	// e.g. 10.0.0.2/32. Never physical/LAN addresses.
	AllowedIPs []net.IPNet

	PersistentKeepaliveInterval *time.Duration
}

func (p PeerConfig) toWG() wgtypes.PeerConfig {
	return wgtypes.PeerConfig{
		PublicKey:                   p.PublicKey,
		Endpoint:                    p.Endpoint,
		AllowedIPs:                  p.AllowedIPs,
		PersistentKeepaliveInterval: p.PersistentKeepaliveInterval,
		ReplaceAllowedIPs:           true,
	}
}

// Config fully specifies one node's WireGuard setup.
// It carries no defaults and reads nothing from the environment.
type Config struct {
	InterfaceName string
	PrivateKey    wgtypes.Key
	ListenPort    int

	// GhostwireIP is this node's own virtual address assigned to the
	// interface itself, e.g. 10.0.0.1/32. Never the physical/LAN address.
	GhostwireIP net.IPNet

	Peers []PeerConfig
}

func (c Config) validate() error {
	if c.InterfaceName == "" {
		return errors.New("wireguard: InterfaceName is required")
	}
	if c.PrivateKey == (wgtypes.Key{}) {
		return errors.New("wireguard: PrivateKey is required")
	}
	if c.GhostwireIP.IP == nil {
		return errors.New("wireguard: GhostwireIP is required")
	}
	return nil
}

// Manager owns one WireGuard interface's lifecycle:
// creation, peer configuration, routing, and teardown.
//
// A Manager is not safe for concurrent use from multiple goroutines; the
// caller is responsible for serializing calls to Up, AddPeer, RemovePeer,
// and Close.
type Manager struct {
	cfg    Config
	client *wgctrl.Client
	link   netlink.Link
	closed bool
}

// New validates cfg and opens a handle to the kernel WireGuard control
// interface. It does not touch network interfaces yet. Call Up for that.
func New(cfg Config) (*Manager, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf(
			"wireguard: opening wgctrl client: %w",
			err,
		)
	}

	return &Manager{
		cfg:    cfg,
		client: client,
	}, nil
}

// Up creates (idempotently) the interface, assigns the Ghostwire IP,
// brings the link up, applies the private key/listen port/initial peers,
// and installs an OS route for every peer's AllowedIPs pointing at this
// interface. If an interface with the same name already exists it is
// deleted first, so this is safe to call after an unclean shutdown.
//
// If any step fails after the interface has been created, Up removes that
// interface itself before returning, so a failed Up never leaves a
// partially-configured interface behind; the caller does not have to
// notice a failure and separately call Close just to release it. Close is
// still required afterward to release the wgctrl handle.
//
// Up returns ErrClosed if Close has already been called on this Manager.
func (m *Manager) Up() error {
	if m.closed {
		return ErrClosed
	}

	if existing, err := netlink.LinkByName(m.cfg.InterfaceName); err == nil {
		if err := netlink.LinkDel(existing); err != nil {
			return fmt.Errorf(
				"wireguard: removing existing interface %s: %w",
				m.cfg.InterfaceName,
				err,
			)
		}
	}

	link := &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name: m.cfg.InterfaceName,
		},
	}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf(
			"wireguard: creating interface %s: %w",
			m.cfg.InterfaceName,
			err,
		)
	}

	m.link = link

	// If any step below fails, remove the interface we just created so
	// Up never leaves a partially-configured interface (addressed and/or
	// up, but with no WireGuard peers/routes applied) behind.
	configured := false
	defer func() {
		if !configured {
			_ = netlink.LinkDel(link)
			m.link = nil
		}
	}()

	ghostIP := m.cfg.GhostwireIP
	if err := netlink.AddrAdd(
		link,
		&netlink.Addr{IPNet: &ghostIP},
	); err != nil {
		return fmt.Errorf(
			"wireguard: assigning %s to %s: %w",
			ghostIP.String(),
			m.cfg.InterfaceName,
			err,
		)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf(
			"wireguard: bringing up %s: %w",
			m.cfg.InterfaceName,
			err,
		)
	}

	peers := make([]wgtypes.PeerConfig, 0, len(m.cfg.Peers))
	for _, p := range m.cfg.Peers {
		peers = append(peers, p.toWG())
	}

	privKey := m.cfg.PrivateKey
	listenPort := m.cfg.ListenPort

	devCfg := wgtypes.Config{
		PrivateKey:   &privKey,
		ListenPort:   &listenPort,
		ReplacePeers: true,
		Peers:        peers,
	}

	if err := m.client.ConfigureDevice(
		m.cfg.InterfaceName,
		devCfg,
	); err != nil {
		return fmt.Errorf(
			"wireguard: configuring device %s: %w",
			m.cfg.InterfaceName,
			err,
		)
	}

	// The kernel WireGuard module only maintains its own internal
	// cryptokey routing (which peer to encrypt a packet for).
	// It does NOT touch the OS routing table. Since wg-quick is bypassed,
	// the OS routes are installed explicitly here.
	for _, p := range m.cfg.Peers {
		if err := m.addRoutes(p.AllowedIPs); err != nil {
			return err
		}
	}

	configured = true
	return nil
}

// AddPeer adds or updates a single peer, without touching the rest of the
// device's peer set, and reconciles the OS routes for that peer's
// AllowedIPs so that Linux routing state stays consistent with what
// WireGuard was just told.
//
// PeerConfig.toWG sets ReplaceAllowedIPs, so configuring a peer that
// already exists replaces its AllowedIPs at the WireGuard layer rather
// than merging with them. To match that at the routing layer, AddPeer
// reads the peer's current AllowedIPs directly from the kernel before
// applying the update (the kernel is treated as the source of truth here,
// rather than Manager keeping separate bookkeeping that could drift out
// of sync with it), diffs that previous set against the AllowedIPs being
// requested, then installs routes only for entries that are newly present
// and removes routes only for entries that are no longer present.
// AllowedIPs unchanged between the two calls are left untouched, and only
// this peer's own previous/next AllowedIPs are ever consulted, so other
// peers' routes cannot be affected. For a peer that does not exist yet,
// the "previous" set is simply empty, so every requested AllowedIP is
// added and nothing is removed.
//
// AddPeer returns ErrClosed if Close has been called, or ErrNotUp if Up
// has never completed successfully on this Manager.
func (m *Manager) AddPeer(p PeerConfig) error {
	if m.closed {
		return ErrClosed
	}
	if m.link == nil {
		return ErrNotUp
	}

	previous, err := m.peerAllowedIPs(p.PublicKey)
	if err != nil {
		return fmt.Errorf(
			"wireguard: reading current state of peer %s: %w",
			p.PublicKey.String(),
			err,
		)
	}

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{p.toWG()},
	}

	if err := m.client.ConfigureDevice(
		m.cfg.InterfaceName,
		cfg,
	); err != nil {
		return fmt.Errorf(
			"wireguard: adding peer %s: %w",
			p.PublicKey.String(),
			err,
		)
	}

	added, removed := diffAllowedIPs(previous, p.AllowedIPs)

	var errs []error

	if err := m.addRoutes(added); err != nil {
		errs = append(errs, err)
	}

	if err := m.delRoutes(removed); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// RemovePeer removes a peer from the device and deletes the OS routes
// that were installed for its AllowedIPs.
//
// The peer's current AllowedIPs are read from the kernel device before it
// is removed, rather than trusting p.AllowedIPs: once a peer has been
// updated via AddPeer, a caller's own record of that peer's AllowedIPs
// may be stale, or (for a caller that only tracks public keys) simply
// absent, and the kernel is the only thing that reliably knows what
// routes were actually installed for it.
//
// RemovePeer returns ErrClosed if Close has been called, or ErrNotUp if
// Up has never completed successfully on this Manager.
func (m *Manager) RemovePeer(p PeerConfig) error {
	if m.closed {
		return ErrClosed
	}
	if m.link == nil {
		return ErrNotUp
	}

	allowedIPs, err := m.peerAllowedIPs(p.PublicKey)
	if err != nil {
		return fmt.Errorf(
			"wireguard: reading current state of peer %s: %w",
			p.PublicKey.String(),
			err,
		)
	}

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: p.PublicKey,
				Remove:    true,
			},
		},
	}

	if err := m.client.ConfigureDevice(
		m.cfg.InterfaceName,
		cfg,
	); err != nil {
		return fmt.Errorf(
			"wireguard: removing peer %s: %w",
			p.PublicKey.String(),
			err,
		)
	}

	return m.delRoutes(allowedIPs)
}

// peerAllowedIPs returns the AllowedIPs currently configured on the kernel
// device for the peer identified by key, or nil if that peer is not
// present on the device at all (which is the correct "previous state" for
// a peer being added for the first time, and the correct "nothing to
// clean up" state for RemovePeer on a peer that was never added).
func (m *Manager) peerAllowedIPs(key wgtypes.Key) ([]net.IPNet, error) {
	device, err := m.client.Device(m.cfg.InterfaceName)
	if err != nil {
		return nil, err
	}

	for _, peer := range device.Peers {
		if peer.PublicKey == key {
			return peer.AllowedIPs, nil
		}
	}

	return nil, nil
}

// canonicalCIDR returns the CIDR string for n's network address: n.IP
// with any bits outside n.Mask zeroed out, then formatted. This exists
// because net.IPNet.String() does not perform this masking itself -- an
// IPNet built from an IP with nonzero host bits under its own mask (for
// example IP=10.0.0.5, Mask=/24) prints as "10.0.0.5/24", not the
// "10.0.0.0/24" that both describe on the wire. diffAllowedIPs uses this
// as its map key so that two net.IPNet values naming the same network
// compare equal regardless of which of them happens to carry unmasked
// host bits (in practice: the kernel-reported "previous" side is usually
// already canonical, but a caller-supplied "next" side is not guaranteed
// to be).
func canonicalCIDR(n net.IPNet) string {
	return (&net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}).String()
}

// diffAllowedIPs compares a peer's previous and next AllowedIPs sets and
// reports which entries need a route added (present in next but not
// previous) and which need a route removed (present in previous but not
// next). Entries present in both sets are returned in neither slice.
// Comparison is by canonical CIDR string (see canonicalCIDR), which is an
// exact, unambiguous key regardless of how two equal net.IPNet values
// happen to be represented internally.
func diffAllowedIPs(previous, next []net.IPNet) (added, removed []net.IPNet) {
	previousSet := make(map[string]net.IPNet, len(previous))
	for _, ipNet := range previous {
		previousSet[canonicalCIDR(ipNet)] = ipNet
	}

	nextSet := make(map[string]struct{}, len(next))
	for _, ipNet := range next {
		nextSet[canonicalCIDR(ipNet)] = struct{}{}
	}

	for _, ipNet := range next {
		if _, ok := previousSet[canonicalCIDR(ipNet)]; !ok {
			added = append(added, ipNet)
		}
	}

	for key, ipNet := range previousSet {
		if _, ok := nextSet[key]; !ok {
			removed = append(removed, ipNet)
		}
	}

	return added, removed
}

// addRoutes installs an on-link route for each of the given
// GhostWire IPs/CIDRs, pointing at this interface.
func (m *Manager) addRoutes(allowedIPs []net.IPNet) error {
	for _, allowedIP := range allowedIPs {
		dst := allowedIP

		route := &netlink.Route{
			LinkIndex: m.link.Attrs().Index,
			Dst:       &dst,
			Scope:     netlink.SCOPE_LINK,
		}

		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf(
				"wireguard: adding route %s via %s: %w",
				dst.String(),
				m.cfg.InterfaceName,
				err,
			)
		}
	}

	return nil
}

// delRoutes removes the routes previously installed by addRoutes for the
// given GhostWire IPs/CIDRs.
func (m *Manager) delRoutes(allowedIPs []net.IPNet) error {
	var errs []error

	for _, allowedIP := range allowedIPs {
		dst := allowedIP

		route := &netlink.Route{
			LinkIndex: m.link.Attrs().Index,
			Dst:       &dst,
			Scope:     netlink.SCOPE_LINK,
		}

		if err := netlink.RouteDel(route); err != nil {
			errs = append(
				errs,
				fmt.Errorf(
					"wireguard: removing route %s: %w",
					dst.String(),
					err,
				),
			)
		}
	}

	return errors.Join(errs...)
}

// Close tears down the interface and releases the wgctrl handle.
// Safe to call even if Up failed partway through, and safe to call more
// than once: the second and subsequent calls are no-ops that return nil.
// After Close, Up, AddPeer, and RemovePeer all return ErrClosed.
func (m *Manager) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true

	var errs []error

	if m.link != nil {
		if err := netlink.LinkDel(m.link); err != nil {
			errs = append(
				errs,
				fmt.Errorf(
					"wireguard: deleting interface: %w",
					err,
				),
			)
		}
		m.link = nil
	}

	if m.client != nil {
		if err := m.client.Close(); err != nil {
			errs = append(
				errs,
				fmt.Errorf(
					"wireguard: closing wgctrl client: %w",
					err,
				),
			)
		}
	}

	return errors.Join(errs...)
}

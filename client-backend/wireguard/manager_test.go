//go:build linux

package wireguard

import (
	"net"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestConfigValidate(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generating private key: %v", err)
	}

	valid := Config{
		InterfaceName: "gwt-unit",
		PrivateKey:    key,
		ListenPort:    51820,
		GhostwireIP:   mustCIDR(t, "198.51.100.1/32"),
	}

	tests := []struct {
		name      string
		cfg       Config
		wantError string
	}{
		{
			name: "valid configuration",
			cfg:  valid,
		},
		{
			name: "missing interface name",
			cfg: func() Config {
				cfg := valid
				cfg.InterfaceName = ""
				return cfg
			}(),
			wantError: "InterfaceName",
		},
		{
			name: "missing private key",
			cfg: func() Config {
				cfg := valid
				cfg.PrivateKey = wgtypes.Key{}
				return cfg
			}(),
			wantError: "PrivateKey",
		},
		{
			name: "missing GhostWire IP",
			cfg: func() Config {
				cfg := valid
				cfg.GhostwireIP = net.IPNet{}
				return cfg
			}(),
			wantError: "GhostwireIP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate()

			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("validate() returned unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf(
					"validate() returned nil, want error containing %q",
					tt.wantError,
				)
			}

			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf(
					"validate() error = %q, want substring %q",
					err,
					tt.wantError,
				)
			}
		})
	}
}

// TestNewRejectsInvalidConfig only exercises configurations that fail
// cfg.validate(). validate() runs before New() ever calls wgctrl.New(), so
// none of these cases touch the kernel WireGuard control socket -- that is
// what keeps this test safe to run without root/CAP_NET_ADMIN and without a
// WireGuard-capable kernel. Do not add a "valid config succeeds" case here:
// that requires opening the real wgctrl client and belongs in the
// privileged suite (see manager_privileged_test.go).
func TestNewRejectsInvalidConfig(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generating private key: %v", err)
	}

	valid := Config{
		InterfaceName: "gwt-unit",
		PrivateKey:    key,
		ListenPort:    51820,
		GhostwireIP:   mustCIDR(t, "198.51.100.1/32"),
	}

	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "missing interface name",
			cfg: func() Config {
				cfg := valid
				cfg.InterfaceName = ""
				return cfg
			}(),
		},
		{
			name: "missing private key",
			cfg: func() Config {
				cfg := valid
				cfg.PrivateKey = wgtypes.Key{}
				return cfg
			}(),
		},
		{
			name: "missing GhostWire IP",
			cfg: func() Config {
				cfg := valid
				cfg.GhostwireIP = net.IPNet{}
				return cfg
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, err := New(tt.cfg)

			if mgr != nil {
				t.Fatal("New() returned a manager for invalid configuration")
			}

			if err == nil {
				t.Fatal("New() returned nil error for invalid configuration")
			}
		})
	}
}

// TestPeerConfigToWG exercises PeerConfig.toWG() directly. It is pure data
// transformation with no kernel or privilege dependency at all, so it has
// no business living only in the privileged suite -- the original drafts
// did not test this mapping anywhere, despite it being exactly the kind of
// small, easy-to-get-subtly-wrong logic (a dropped field, a forgotten
// ReplaceAllowedIPs) that unit tests exist for.
func TestPeerConfigToWG(t *testing.T) {
	key := testPrivateKey(t).PublicKey()
	keepalive := 17 * time.Second
	allowed := []net.IPNet{mustCIDR(t, "10.0.0.5/32")}

	t.Run("fully specified peer", func(t *testing.T) {
		endpoint := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 51820}

		p := PeerConfig{
			PublicKey:                   key,
			Endpoint:                    endpoint,
			AllowedIPs:                  allowed,
			PersistentKeepaliveInterval: &keepalive,
		}

		got := p.toWG()

		if got.PublicKey != key {
			t.Fatalf("PublicKey = %v, want %v", got.PublicKey, key)
		}

		if got.Endpoint != endpoint {
			t.Fatalf(
				"Endpoint = %v, want the exact *net.UDPAddr passed in (%v)",
				got.Endpoint,
				endpoint,
			)
		}

		if len(got.AllowedIPs) != 1 || got.AllowedIPs[0].String() != allowed[0].String() {
			t.Fatalf("AllowedIPs = %v, want %v", got.AllowedIPs, allowed)
		}

		if got.PersistentKeepaliveInterval == nil || *got.PersistentKeepaliveInterval != keepalive {
			t.Fatalf(
				"PersistentKeepaliveInterval = %v, want %v",
				got.PersistentKeepaliveInterval,
				keepalive,
			)
		}

		if !got.ReplaceAllowedIPs {
			t.Fatal(
				"ReplaceAllowedIPs = false, want true: without this, a " +
					"peer update via AddPeer would merge with rather than " +
					"replace the previous AllowedIPs set, leaving stale " +
					"routes/permissions configured on the kernel peer",
			)
		}

		if got.Remove {
			t.Fatal("Remove = true for a peer being added/updated, not removed")
		}
	})

	t.Run("peer with no endpoint yet (pending NAT traversal)", func(t *testing.T) {
		p := PeerConfig{
			PublicKey:  key,
			Endpoint:   nil,
			AllowedIPs: allowed,
		}

		got := p.toWG()

		if got.Endpoint != nil {
			t.Fatalf(
				"Endpoint = %v, want nil: manager.go's PeerConfig.Endpoint "+
					"doc comment explicitly allows nil for a peer whose "+
					"address is not yet known",
				got.Endpoint,
			)
		}

		if got.PersistentKeepaliveInterval != nil {
			t.Fatalf(
				"PersistentKeepaliveInterval = %v, want nil when not configured",
				got.PersistentKeepaliveInterval,
			)
		}

		if !got.ReplaceAllowedIPs {
			t.Fatal("ReplaceAllowedIPs = false, want true")
		}
	})
}

// TestDiffAllowedIPs is a direct, privilege-free unit test of
// diffAllowedIPs -- the function that decides which routes AddPeer adds
// and removes when a peer's AllowedIPs change. It is the single piece of
// logic most directly responsible for the stale-route bug this package
// was fixed for, and before this test it had no dedicated coverage at
// all: the only place it was exercised was indirectly, through the
// privileged integration tests, which require root and a WireGuard-
// capable kernel to even run. A CI runner without those can now still
// catch a regression here in milliseconds.
func TestDiffAllowedIPs(t *testing.T) {
	tests := []struct {
		name        string
		previous    []net.IPNet
		next        []net.IPNet
		wantAdded   []net.IPNet
		wantRemoved []net.IPNet
	}{
		{
			name:      "new peer: everything is added, nothing removed",
			previous:  nil,
			next:      []net.IPNet{mustCIDR(t, "10.0.0.1/32"), mustCIDR(t, "10.0.0.2/32")},
			wantAdded: []net.IPNet{mustCIDR(t, "10.0.0.1/32"), mustCIDR(t, "10.0.0.2/32")},
		},
		{
			name:        "peer removed: everything is removed, nothing added",
			previous:    []net.IPNet{mustCIDR(t, "10.0.0.1/32"), mustCIDR(t, "10.0.0.2/32")},
			next:        nil,
			wantRemoved: []net.IPNet{mustCIDR(t, "10.0.0.1/32"), mustCIDR(t, "10.0.0.2/32")},
		},
		{
			name:     "no-op update: identical sets touch nothing",
			previous: []net.IPNet{mustCIDR(t, "10.0.0.1/32")},
			next:     []net.IPNet{mustCIDR(t, "10.0.0.1/32")},
		},
		{
			name:        "update: one kept, one dropped, one added",
			previous:    []net.IPNet{mustCIDR(t, "10.0.0.1/32"), mustCIDR(t, "10.0.0.2/32")},
			next:        []net.IPNet{mustCIDR(t, "10.0.0.1/32"), mustCIDR(t, "10.0.0.3/32")},
			wantAdded:   []net.IPNet{mustCIDR(t, "10.0.0.3/32")},
			wantRemoved: []net.IPNet{mustCIDR(t, "10.0.0.2/32")},
		},
		{
			// net.IPNet.String() does NOT mask off host bits (verified
			// against the net package's networkNumberAndMask/String
			// implementation, not assumed): an IPNet built with
			// IP=10.0.0.5 and a /24 mask prints "10.0.0.5/24", not
			// "10.0.0.0/24". Without canonicalCIDR's explicit
			// IP.Mask(Mask) step, this case and its "next" counterpart
			// would diff as two different, string-unequal networks and
			// wrongly produce both an add and a remove for what is, on
			// the wire, the exact same route.
			name: "same network in unmasked vs. canonical form is not a change",
			previous: []net.IPNet{
				{IP: net.IPv4(10, 0, 0, 5), Mask: net.CIDRMask(24, 32)},
			},
			next: []net.IPNet{
				mustCIDR(t, "10.0.0.0/24"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			added, removed := diffAllowedIPs(tt.previous, tt.next)

			if !sameIPNetSet(added, tt.wantAdded) {
				t.Fatalf("added = %v, want %v", added, tt.wantAdded)
			}

			if !sameIPNetSet(removed, tt.wantRemoved) {
				t.Fatalf("removed = %v, want %v", removed, tt.wantRemoved)
			}
		})
	}
}

// sameIPNetSet reports whether got and want contain the same CIDRs,
// ignoring order (diffAllowedIPs makes no ordering guarantee, since it
// builds its added/removed slices from map iteration).
func sameIPNetSet(got, want []net.IPNet) bool {
	if len(got) != len(want) {
		return false
	}

	gotSet := make(map[string]bool, len(got))
	for _, ipNet := range got {
		gotSet[ipNet.String()] = true
	}

	for _, ipNet := range want {
		if !gotSet[ipNet.String()] {
			return false
		}
	}

	return true
}

func mustCIDR(t *testing.T, value string) net.IPNet {
	t.Helper()

	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatalf("parsing CIDR %q: %v", value, err)
	}

	network.IP = ip
	return *network
}

func testPrivateKey(t *testing.T) wgtypes.Key {
	t.Helper()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generating private key: %v", err)
	}

	return key
}

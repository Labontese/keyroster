package cert

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

// hostPrev is a previous host certificate issued at issued (ValidAfter +
// 300) for life seconds, for principals.
func hostPrev(issued, life, capSeconds, dir uint64, principals ...string) HostPrev {
	return HostPrev{
		Cert:           &ssh.Certificate{ValidAfter: issued - 300, ValidBefore: issued + life, ValidPrincipals: principals},
		CapSeconds:     capSeconds,
		IssuedUnderDir: dir,
	}
}

// TestHostCertRecent is the one host_cert_recent rule (03-09, Q-09-2,
// Q-09-5, Q-09-6).
func TestHostCertRecent(t *testing.T) {
	const t0 = 1_800_000_000
	web := []string{"web1"}
	t.Run("boundary", func(t *testing.T) {
		for _, c := range []uint64{90, 2592000} {
			p := hostPrev(t0, c, c, 1, web...)
			if got := HostCertRecent(p, t0+c/3-1, c, 1, web); got != "host_cert_recent" {
				t.Errorf("cap %d at -1: %q, want host_cert_recent", c, got)
			}
			if got := HostCertRecent(p, t0+c/3, c, 1, web); got != "" {
				t.Errorf("cap %d at 0: %q, want not recent", c, got)
			}
		}
	})
	t.Run("prev_lifetime_does_not_shorten", func(t *testing.T) {
		for _, life := range []uint64{1, 2, 3} {
			p := hostPrev(t0, life, 2592000, 1, web...)
			if got := HostCertRecent(p, t0+29, 90, 1, web); got != "host_cert_recent" {
				t.Errorf("a %d s previous lifetime at +29 s: %q, want the 30 s window of the 90 s cap", life, got)
			}
			if got := HostCertRecent(p, t0+30, 90, 1, web); got != "" {
				t.Errorf("a %d s previous lifetime at +30 s: %q, want not recent", life, got)
			}
		}
	})
	t.Run("lowered_cap_shortens_window", func(t *testing.T) {
		p := hostPrev(t0, 2592000, 2592000, 1, web...)
		if got := HostCertRecent(p, t0+30, 90, 1, web); got != "" {
			t.Fatalf("a cap lowered to 90 s at +30 s: %q, want not recent", got)
		}
	})
	t.Run("raised_cap_does_not_extend_window", func(t *testing.T) {
		p := hostPrev(t0, 86400, 86400, 1, web...)
		if got := HostCertRecent(p, t0+8*3600-1, 2592000, 1, web); got != "host_cert_recent" {
			t.Fatalf("at 8 h - 1 s: %q, want recent", got)
		}
		if got := HostCertRecent(p, t0+8*3600, 2592000, 1, web); got != "" {
			t.Fatalf("a cap raised from 1 day to 30 days at 8 h: %q, want the 8-hour window kept", got)
		}
	})
	t.Run("stale_agent_cap_not_stranded", func(t *testing.T) {
		p := hostPrev(t0, 2592000, 2592000, 1, web...)
		if got := HostCertRecent(p, t0+20*86400, 86400, 1, web); got != "" {
			t.Fatalf("a 30-day certificate at 20 days under a 1-day cap: %q, want not recent", got)
		}
	})
	t.Run("principals_order_is_no_change", func(t *testing.T) {
		p := hostPrev(t0, 90, 90, 1, "web1", "web1.lab")
		if got := HostCertRecent(p, t0+1, 90, 2, []string{"web1.lab", "web1"}); got != "host_cert_recent" {
			t.Fatalf("principals in another order: %q, want recent", got)
		}
	})
	t.Run("principals_change_bypasses_once_per_version", func(t *testing.T) {
		p := hostPrev(t0, 90, 90, 1, web...)
		if got := HostCertRecent(p, t0+1, 90, 2, []string{"web1", "www"}); got != "" {
			t.Fatalf("a principal change under a newer version: %q, want not recent", got)
		}
		p.IssuedUnderDir = 2
		if got := HostCertRecent(p, t0+1, 90, 2, []string{"web1", "www"}); got != "host_cert_recent" {
			t.Fatalf("the exception within the same directory version: %q, want recent", got)
		}
	})
	t.Run("cert_revoked_until_new_directory", func(t *testing.T) {
		p := hostPrev(t0, 90, 90, 1, web...)
		p.Revoked, p.RevokedAtDir = true, 3
		if got := HostCertRecent(p, t0+1000, 90, 3, web); got != "cert_revoked" {
			t.Fatalf("revoked at v3, v3 in force: %q, want cert_revoked", got)
		}
		if got := HostCertRecent(p, t0+1, 90, 4, web); got != "" {
			t.Fatalf("revoked at v3, v4 in force: %q, want released", got)
		}
	})
	t.Run("no_prev", func(t *testing.T) {
		if got := HostCertRecent(HostPrev{}, t0, 90, 1, web); got != "" {
			t.Fatalf("no previous certificate: %q", got)
		}
	})
}

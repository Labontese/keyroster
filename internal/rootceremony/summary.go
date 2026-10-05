package rootceremony

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// Summary renders what a root signature over b and p would vouch for, for
// the operator to read before confirming: every root, CA, ops and log key
// with fingerprint, role, algorithm and custody, the root threshold, the
// admins and quorum, the CA profiles and the bundle hash. Software-held
// roots are flagged loudly (D-10, D-11).
func Summary(b *trust.Bundle, p *trust.Policy) string {
	var w strings.Builder
	fmt.Fprintf(&w, "Trust bundle version %d, issued %s\n", b.Version, b.IssuedAt)
	fmt.Fprintf(&w, "  prev:          %s\n", b.Prev)
	fmt.Fprintf(&w, "  policy sha256: %s\n", b.PolicySHA256)
	fmt.Fprintf(&w, "Root keys (threshold %d of %d):\n", b.Root.Threshold, len(b.Root.Keys))
	for _, r := range b.Root.Keys {
		fp, typ := describe(r.Key)
		fmt.Fprintf(&w, "  %s  %-34s custody=%s\n", fp, typ, r.Custody)
		if r.Custody == "software" {
			w.WriteString("    WARNING: SOFTWARE ROOT - this key is not hardware-protected; keep it on offline media\n")
		}
	}
	w.WriteString("CA keys:\n")
	for _, ca := range b.CAs {
		fp, _ := describe(ca.Key)
		fmt.Fprintf(&w, "  %-8s gen %-3d %-8s %s  %s  custody=%s\n", ca.Role, ca.Generation, ca.State, fp, ca.Alg, ca.Custody)
	}
	fp, _ := describe(b.OpsKey.Key)
	fmt.Fprintf(&w, "Ops key (KRL authority): %s  %s  custody=%s\n", fp, b.OpsKey.Alg, b.OpsKey.Custody)
	fp, _ = describe(b.Log.Key)
	fmt.Fprintf(&w, "Log key: %s  %s  custody=%s  origin=%s\n", fp, b.Log.Alg, b.Log.Custody, b.Log.Origin)
	if p != nil {
		fmt.Fprintf(&w, "Policy version %d:\n", p.Version)
		fmt.Fprintf(&w, "  admin quorum %d of %d\n", p.AdminQuorum, len(p.Admins))
		for _, a := range p.Admins {
			fp, typ := describe(a.Key)
			fmt.Fprintf(&w, "  admin %-16s %s  %s\n", a.Name, fp, typ)
		}
		for _, c := range p.CAProfiles {
			fmt.Fprintf(&w, "  profile %-8s max ttl %s  default extensions [%s]  allowed extensions [%s]  allowed critical options [%s]\n",
				c.Role, seconds(c.MaxTTLSeconds), strings.Join(c.DefaultExtensions, " "),
				strings.Join(c.AllowedExtensions, " "), strings.Join(c.AllowedCriticalOptions, " "))
		}
		fmt.Fprintf(&w, "  timelock %s\n", seconds(p.TimelockSeconds))
	}
	if data, err := b.Canonical(); err == nil {
		fmt.Fprintf(&w, "Bundle SHA-256: %s\n", BundleHash(data))
	}
	return w.String()
}

// describe returns a key's SHA256 fingerprint and type.
func describe(key string) (fingerprint, keyType string) {
	pub, err := trust.ParseKey(key)
	if err != nil {
		return "<invalid key>", "?"
	}
	return ssh.FingerprintSHA256(pub), pub.Type()
}

func seconds(s uint64) string {
	if s > uint64(1<<62)/uint64(time.Second) {
		return fmt.Sprintf("%ds", s)
	}
	return (time.Duration(s) * time.Second).String() //nolint:gosec // G115: bounded above
}

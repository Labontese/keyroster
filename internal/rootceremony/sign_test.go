package rootceremony

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

func readVector(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "test", "vectors", name)) //nolint:gosec // G304: fixed test vector path
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func rootSigner(t *testing.T) ssh.Signer {
	t.Helper()
	// The golden vectors' root A (seed byte 1).
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignBundleAndPolicy(t *testing.T) {
	bundle, policy := readVector(t, "bundle_genesis_v1.json"), readVector(t, "policy_genesis_v1.json")
	s := rootSigner(t)

	bsig, err := SignBundle(rand.Reader, s, bundle)
	if err != nil {
		t.Fatal(err)
	}
	psig, err := SignPolicy(rand.Reader, s, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		armored   []byte
		doc       []byte
		ns, other string
	}{{bsig, bundle, trust.NamespaceBundle, trust.NamespacePolicy}, {psig, policy, trust.NamespacePolicy, trust.NamespaceBundle}} {
		sig, err := sshsig.Parse(c.armored)
		if err != nil {
			t.Fatal(err)
		}
		if err := sig.Verify(c.ns, c.doc); err != nil {
			t.Fatalf("signature does not verify under %s: %v", c.ns, err)
		}
		if err := sig.Verify(c.other, c.doc); err == nil {
			t.Fatalf("signature also verifies under %s", c.other)
		}
	}
	// The golden root A signature makes the golden vectors verify (1 of 2).
	pins := []string{ssh.FingerprintSHA256(s.PublicKey())}
	b, err := trust.ParseBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range b.Root.Keys[1:] {
		pub, err := trust.ParseKey(r.Key)
		if err != nil {
			t.Fatal(err)
		}
		pins = append(pins, ssh.FingerprintSHA256(pub))
	}
	if _, _, err := trust.VerifyGenesisBundle(bundle, bsig, policy, psig, pins, 1); err != nil {
		t.Fatalf("golden vectors signed by root A do not verify: %v", err)
	}
	if h := BundleHash(bundle); len(h) != 64 || h != trust.SHA256Hex(bundle) {
		t.Fatalf("BundleHash = %q", h)
	}
	sum := Summary(b, nil)
	for _, want := range []string{"threshold 1 of 2", "custody=piv", "SOFTWARE ROOT", "Bundle SHA-256: " + BundleHash(bundle), b.Log.Origin} {
		if !strings.Contains(sum, want) {
			t.Fatalf("Summary lacks %q:\n%s", want, sum)
		}
	}
}

// TestSignRefusesOtherDocuments checks that the root signs nothing but a
// canonical, valid document of the requested type.
func TestSignRefusesOtherDocuments(t *testing.T) {
	bundle, policy := readVector(t, "bundle_genesis_v1.json"), readVector(t, "policy_genesis_v1.json")
	s := rootSigner(t)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, bundle, "", "  "); err != nil {
		t.Fatal(err)
	}
	invalid := bytes.Replace(bundle, []byte(`"threshold":1`), []byte(`"threshold":0`), 1)
	if bytes.Equal(invalid, bundle) {
		t.Fatal("fixture lacks threshold 1")
	}
	certLike := []byte("\x00\x00\x00\x1cssh-ed25519-cert-v01@openssh.com")

	for name, doc := range map[string][]byte{
		"non_canonical_bundle": pretty.Bytes(),
		"invalid_bundle":       invalid,
		"policy_as_bundle":     policy,
		"certificate_bytes":    certLike,
		"empty":                nil,
	} {
		t.Run("SignBundle_"+name, func(t *testing.T) {
			if out, err := SignBundle(rand.Reader, s, doc); err == nil || out != nil {
				t.Fatalf("SignBundle signed %s", name)
			}
		})
	}
	for name, doc := range map[string][]byte{
		"bundle_as_policy":  bundle,
		"certificate_bytes": certLike,
		"non_canonical":     append(bytes.Clone(policy), '\n'),
	} {
		t.Run("SignPolicy_"+name, func(t *testing.T) {
			if out, err := SignPolicy(rand.Reader, s, doc); err == nil || out != nil {
				t.Fatalf("SignPolicy signed %s", name)
			}
		})
	}
	if _, err := SignBundle(rand.Reader, s, pretty.Bytes()); !errors.Is(err, trust.ErrNotCanonical) {
		t.Fatalf("non-canonical bundle: err = %v, want ErrNotCanonical", err)
	}
}

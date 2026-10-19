//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/serverclient"
)

// testCA is a private TLS CA for one test: a P-256 root and leaves issued
// directly under it, written as PEM files.
type testCA struct {
	dir      string
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	RootPEM  string // root certificate file
	RootPin  string // serverclient.PinOf(root)
	CertPath string // leaf for the dnsName given to newTestCA, valid 1 h
	KeyPath  string
}

// newTestCA creates a root and a leaf with SAN DNS=dnsName valid for one
// hour from now.
func newTestCA(t *testing.T, dnsName string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "keyroster e2e test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := &testCA{dir: t.TempDir(), root: root, rootKey: key, RootPin: serverclient.PinOf(root)}
	ca.RootPEM = filepath.Join(ca.dir, "root.pem")
	writePEM(t, ca.RootPEM, "CERTIFICATE", der)
	ca.CertPath, ca.KeyPath = ca.leaf(t, "leaf", dnsName, now.Add(-time.Minute), now.Add(time.Hour))
	return ca
}

// leaf issues a leaf for dnsName valid from notBefore to notAfter and
// writes it (leaf only; the root is never sent) and its key as name.pem
// and name.key.
func (ca *testCA) leaf(t *testing.T, name, dnsName string, notBefore, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.root, &key.PublicKey, ca.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(ca.dir, name+".pem"), filepath.Join(ca.dir, name+".key")
	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)
	return certPath, keyPath
}

// expiredLeaf issues a leaf for dnsName that expired an hour ago.
func (ca *testCA) expiredLeaf(t *testing.T, dnsName string) (certPath, keyPath string) {
	t.Helper()
	now := time.Now()
	return ca.leaf(t, "expired", dnsName, now.Add(-2*time.Hour), now.Add(-time.Hour))
}

// otherNameLeaf issues a valid leaf for a name other than the RP ID.
func (ca *testCA) otherNameLeaf(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	now := time.Now()
	return ca.leaf(t, "other", "other.localhost", now.Add(-time.Minute), now.Add(time.Hour))
}

// pool returns a pool holding only the root.
func (ca *testCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.root)
	return p
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

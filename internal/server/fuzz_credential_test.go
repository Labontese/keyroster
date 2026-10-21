package server

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/Labontese/keyroster/internal/server/servertest"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
)

// FuzzSPKIFromCOSE: the COSE key comes from the authenticator through the
// browser. Whatever spkiFromCOSE accepts must be one of the three
// algorithms, an SPKI that webauthn.ParsePublicKey accepts for it (so the
// signer accepts it too), and stable: converting the same input twice
// gives the same bytes.
func FuzzSPKIFromCOSE(f *testing.F) {
	for _, alg := range []int64{webauthn.AlgEdDSA, webauthn.AlgES256, webauthn.AlgRS256} {
		a, err := webauthntest.New(alg)
		if err != nil {
			f.Fatal(err)
		}
		pub, err := x509.ParsePKIXPublicKey(a.Credential().SPKI)
		if err != nil {
			f.Fatal(err)
		}
		cose, err := servertest.COSEKey(alg, pub)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(cose)
		// The same key under another algorithm label.
		if wrong, err := servertest.COSEKey(-35, pub); err == nil {
			f.Add(wrong)
		}
	}
	f.Add([]byte{0xa0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, cose []byte) {
		alg, spki, err := spkiFromCOSE(cose)
		if err != nil {
			return
		}
		switch alg {
		case webauthn.AlgEdDSA, webauthn.AlgES256, webauthn.AlgRS256:
		default:
			t.Fatalf("spkiFromCOSE accepted algorithm %d", alg)
		}
		if _, err := webauthn.ParsePublicKey(alg, spki); err != nil {
			t.Fatalf("spkiFromCOSE returned an SPKI ParsePublicKey refuses: %v", err)
		}
		alg2, spki2, err := spkiFromCOSE(cose)
		if err != nil || alg2 != alg || !bytes.Equal(spki2, spki) {
			t.Fatalf("spkiFromCOSE is not stable: %d %x %v", alg2, spki2, err)
		}
	})
}

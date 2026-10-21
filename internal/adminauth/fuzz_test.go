package adminauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// FuzzVerify: the admin headers come from any client, so Verify must never
// panic, and it must accept only a request that the policy's admin signed
// for exactly this origin, method, path and body digest, and CheckBody
// only the body with that digest: a fuzzed request passes both only when
// every field equals the signed one.
func FuzzVerify(f *testing.F) {
	seed := make([]byte, ed25519.SeedSize)
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		f.Fatal(err)
	}
	admins := []trust.AdminKey{{Name: "alice", Key: trust.FormatKey(signer.PublicKey())}}
	// Fixed headers: the fuzz workers rerun this setup, so nothing here
	// may be random (Ed25519 signing is deterministic).
	sum := sha256.Sum256([]byte(testBody))
	ts, nonce, digest := strconv.FormatInt(tNow.Unix(), 10), "0123456789abcdef0123456789abcdef", hex.EncodeToString(sum[:])
	armored, err := sshsig.Sign(rand.Reader, signer, Namespace, Message(testOrigin, "POST", testPath, sum, tNow.Unix(), nonce))
	if err != nil {
		f.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(armored)
	f.Add(ts, nonce, digest, sig, testOrigin, "POST", testPath, []byte(testBody))
	f.Add(ts, nonce, digest, sig, "https://staging.example", "POST", testPath, []byte(testBody))
	f.Add(ts, nonce, digest, sig, testOrigin, "POST", "/api/v1/admin/users?x=2", []byte(testBody))
	f.Add(ts, nonce, digest, sig, testOrigin, "POST", testPath, []byte(`{}`))
	f.Add("", "", "", "", "", "GET", "/", []byte{})
	f.Add(ts, "00000000000000000000000000000000", "00", "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0K", testOrigin, "POST", "/", []byte("{}"))
	f.Fuzz(func(t *testing.T, fts, fnonce, fdigest, fsig, origin, method, path string, body []byte) {
		hh := http.Header{}
		hh.Set(HeaderTime, fts)
		hh.Set(HeaderNonce, fnonce)
		hh.Set(HeaderBodySHA256, fdigest)
		hh.Set(HeaderSignature, fsig)
		name, _, d, err := Verify(hh, origin, method, path, tNow, admins)
		if err != nil {
			return
		}
		if name != "alice" || fts != ts || fnonce != nonce || fdigest != digest || origin != testOrigin || method != "POST" || path != testPath {
			t.Fatalf("Verify accepted a request that differs from the signed one: %q %q %q %q %q %q", fts, fnonce, fdigest, origin, method, path)
		}
		if CheckBody(d, body) == nil && !bytes.Equal(body, []byte(testBody)) {
			t.Fatalf("CheckBody accepted the body %q for the digest of %q", body, testBody)
		}
	})
}

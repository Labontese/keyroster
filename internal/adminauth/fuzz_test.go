package adminauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// FuzzVerify: the admin headers come from any client, so Verify must never
// panic, and it must accept only a request that the policy's admin signed
// for exactly this method, path and body: a fuzzed request is accepted
// only when every field equals the signed one.
func FuzzVerify(f *testing.F) {
	seed := make([]byte, ed25519.SeedSize)
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		f.Fatal(err)
	}
	admins := []trust.AdminKey{{Name: "alice", Key: trust.FormatKey(signer.PublicKey())}}
	// Fixed headers: the fuzz workers rerun this setup, so nothing here
	// may be random (Ed25519 signing is deterministic).
	ts, nonce := strconv.FormatInt(tNow.Unix(), 10), "0123456789abcdef0123456789abcdef"
	armored, err := sshsig.Sign(rand.Reader, signer, Namespace, Message("POST", testPath, sha256.Sum256([]byte(testBody)), tNow.Unix(), nonce))
	if err != nil {
		f.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(armored)
	f.Add(ts, nonce, sig, "POST", testPath, []byte(testBody))
	f.Add(ts, nonce, sig, "POST", "/api/v1/admin/users?x=2", []byte(testBody))
	f.Add("", "", "", "GET", "/", []byte{})
	f.Add(ts, "00000000000000000000000000000000", "LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0K", "POST", "/", []byte("{}"))
	f.Fuzz(func(t *testing.T, fts, fnonce, fsig, method, path string, body []byte) {
		hh := http.Header{}
		hh.Set(HeaderTime, fts)
		hh.Set(HeaderNonce, fnonce)
		hh.Set(HeaderSignature, fsig)
		name, _, err := Verify(hh, method, path, body, tNow, admins)
		if err != nil {
			return
		}
		if name != "alice" || fts != ts || fnonce != nonce || method != "POST" || path != testPath || !bytes.Equal(body, []byte(testBody)) {
			t.Fatalf("accepted a request that differs from the signed one: %q %q %q %q", fts, fnonce, method, path)
		}
	})
}

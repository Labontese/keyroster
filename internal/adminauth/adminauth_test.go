package adminauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// skEd25519Signer is the software stand-in for a FIDO security key
// holding an sk-ssh-ed25519@openssh.com key, copied from the SSHSIG
// fixture in internal/sshsig's tests (helpers_test.go): Ed25519 over
// SHA-256(application) || flags || counter || SHA-256(data), with the
// user-presence flag set.
type skEd25519Signer struct {
	priv ed25519.PrivateKey
	pub  ssh.PublicKey
}

func newSKEd25519Signer(t *testing.T) *skEd25519Signer {
	t.Helper()
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire := ssh.Marshal(struct {
		Name string
		Key  []byte
		App  string
	}{ssh.KeyAlgoSKED25519, pubKey, "ssh:"})
	pub, err := ssh.ParsePublicKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	return &skEd25519Signer{priv: priv, pub: pub}
}

func (s *skEd25519Signer) PublicKey() ssh.PublicKey { return s.pub }

func (s *skEd25519Signer) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	app := sha256.Sum256([]byte("ssh:"))
	msg := sha256.Sum256(data)
	var rest [5]byte
	rest[0] = 0x01 // user present
	binary.BigEndian.PutUint32(rest[1:], 7)
	signed := append(append(append([]byte{}, app[:]...), rest[:]...), msg[:]...)
	return &ssh.Signature{Format: ssh.KeyAlgoSKED25519, Blob: ed25519.Sign(s.priv, signed), Rest: rest[:]}, nil
}

func newEd25519Signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func adminOf(name string, s ssh.Signer) trust.AdminKey {
	return trust.AdminKey{Name: name, Key: trust.FormatKey(s.PublicKey())}
}

var tNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

const (
	testPath = "/api/v1/admin/users?x=1"
	testBody = `{"name":"alice","reinvite":false}`
)

func TestMessage(t *testing.T) {
	sum := sha256.Sum256([]byte("b"))
	got := string(Message("POST", "/p?q=1", sum, 1760961600, "0123456789abcdef0123456789abcdef"))
	want := "keyroster/admin-api/v1\nPOST\n/p?q=1\n" +
		"3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d\n" +
		"1760961600\n0123456789abcdef0123456789abcdef\n"
	if got != want {
		t.Fatalf("Message =\n%q\nwant\n%q", got, want)
	}
}

func TestVerify(t *testing.T) {
	adminKey := newEd25519Signer(t)
	skKey := newSKEd25519Signer(t)
	other := newEd25519Signer(t)
	admins := []trust.AdminKey{adminOf("alice", adminKey), adminOf("bob", skKey)}

	sign := func(t *testing.T, s ssh.Signer, method, path, body string, at time.Time) http.Header {
		t.Helper()
		h, err := Sign(s, method, path, []byte(body), at)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	verify := func(h http.Header, method, path, body string) (string, error) {
		name, _, err := Verify(h, method, path, []byte(body), tNow, admins)
		return name, err
	}

	t.Run("ed25519_admin_key_accepted", func(t *testing.T) {
		h := sign(t, adminKey, "POST", testPath, testBody, tNow)
		name, nonce, err := Verify(h, "POST", testPath, []byte(testBody), tNow, admins)
		if err != nil || name != "alice" || nonce != h.Get(HeaderNonce) || len(nonce) != 32 {
			t.Fatalf("Verify = %q, %q, %v; want alice, the request's nonce", name, nonce, err)
		}
	})
	t.Run("sk_admin_key_accepted", func(t *testing.T) {
		h := sign(t, skKey, "POST", testPath, testBody, tNow)
		if name, err := verify(h, "POST", testPath, testBody); err != nil || name != "bob" {
			t.Fatalf("Verify = %q, %v; want bob", name, err)
		}
	})
	t.Run("window_edges_accepted", func(t *testing.T) {
		for _, at := range []time.Time{tNow.Add(-MaxSkew), tNow.Add(MaxSkew)} {
			if _, err := verify(sign(t, adminKey, "POST", testPath, testBody, at), "POST", testPath, testBody); err != nil {
				t.Fatalf("stamped %v: %v", at.Sub(tNow), err)
			}
		}
	})

	cases := []struct {
		name string
		h    func(t *testing.T) http.Header
		// what Verify is called with
		method, path, body string
		want               error
	}{
		{"missing_headers", func(t *testing.T) http.Header { return http.Header{} }, "POST", testPath, testBody, ErrMissingHeaders},
		{"missing_signature", func(t *testing.T) http.Header {
			h := sign(t, adminKey, "POST", testPath, testBody, tNow)
			h.Del(HeaderSignature)
			return h
		}, "POST", testPath, testBody, ErrMissingHeaders},
		{"stale_time", func(t *testing.T) http.Header {
			return sign(t, adminKey, "POST", testPath, testBody, tNow.Add(-121*time.Second))
		}, "POST", testPath, testBody, ErrStale},
		{"future_time", func(t *testing.T) http.Header {
			return sign(t, adminKey, "POST", testPath, testBody, tNow.Add(121*time.Second))
		}, "POST", testPath, testBody, ErrFuture},
		{"malformed_time", func(t *testing.T) http.Header {
			h := sign(t, adminKey, "POST", testPath, testBody, tNow)
			h.Set(HeaderTime, "+"+h.Get(HeaderTime))
			return h
		}, "POST", testPath, testBody, ErrBadTime},
		{"malformed_nonce", func(t *testing.T) http.Header {
			h := sign(t, adminKey, "POST", testPath, testBody, tNow)
			h.Set(HeaderNonce, "0123456789ABCDEF0123456789ABCDEF")
			return h
		}, "POST", testPath, testBody, ErrBadNonce},
		{"malformed_signature", func(t *testing.T) http.Header {
			h := sign(t, adminKey, "POST", testPath, testBody, tNow)
			h.Set(HeaderSignature, base64.StdEncoding.EncodeToString([]byte("not a signature")))
			return h
		}, "POST", testPath, testBody, ErrBadSignature},
		{"non_admin_key", func(t *testing.T) http.Header {
			return sign(t, other, "POST", testPath, testBody, tNow)
		}, "POST", testPath, testBody, ErrNotAdmin},
		{"wrong_namespace", func(t *testing.T) http.Header {
			h := sign(t, adminKey, "POST", testPath, testBody, tNow)
			msg := Message("POST", testPath, sha256.Sum256([]byte(testBody)), tNow.Unix(), h.Get(HeaderNonce))
			sig, err := sshsig.Sign(rand.Reader, adminKey, "keyroster/issue-request/v1", msg)
			if err != nil {
				t.Fatal(err)
			}
			h.Set(HeaderSignature, base64.StdEncoding.EncodeToString(sig))
			return h
		}, "POST", testPath, testBody, ErrNamespace},
		{"body_changed", func(t *testing.T) http.Header {
			return sign(t, adminKey, "POST", testPath, testBody, tNow)
		}, "POST", testPath, `{"name":"mallory","reinvite":false}`, ErrMismatch},
		{"path_changed", func(t *testing.T) http.Header {
			return sign(t, adminKey, "POST", testPath, testBody, tNow)
		}, "POST", "/api/v1/admin/other?x=1", testBody, ErrMismatch},
		{"query_changed", func(t *testing.T) http.Header {
			return sign(t, adminKey, "POST", testPath, testBody, tNow)
		}, "POST", "/api/v1/admin/users?x=2", testBody, ErrMismatch},
		{"method_changed", func(t *testing.T) http.Header {
			return sign(t, adminKey, "POST", testPath, testBody, tNow)
		}, "PUT", testPath, testBody, ErrMismatch},
		{"nonce_changed", func(t *testing.T) http.Header {
			h := sign(t, adminKey, "POST", testPath, testBody, tNow)
			h.Set(HeaderNonce, "00000000000000000000000000000000")
			return h
		}, "POST", testPath, testBody, ErrMismatch},
		{"time_changed", func(t *testing.T) http.Header {
			h := sign(t, adminKey, "POST", testPath, testBody, tNow)
			h.Set(HeaderTime, strconv.FormatInt(tNow.Unix()+1, 10))
			return h
		}, "POST", testPath, testBody, ErrMismatch},
	}
	all := []error{ErrMissingHeaders, ErrBadTime, ErrStale, ErrFuture, ErrBadNonce, ErrBadSignature, ErrNotAdmin, ErrNamespace, ErrMismatch, ErrBadPolicy}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, err := verify(tc.h(t), tc.method, tc.path, tc.body)
			if !errors.Is(err, tc.want) || name != "" {
				t.Fatalf("Verify = %q, %v; want %v", name, err, tc.want)
			}
			for _, other := range all {
				if other != tc.want && errors.Is(err, other) {
					t.Fatalf("Verify error %v also matches %v; each refusal must be distinct", err, other)
				}
			}
		})
	}
}

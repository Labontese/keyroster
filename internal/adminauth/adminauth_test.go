package adminauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
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
	testOrigin = "https://keyroster.example"
	testPath   = "/api/v1/admin/users?x=1"
	testBody   = `{"name":"alice","reinvite":false}`
)

func TestMessage(t *testing.T) {
	sum := sha256.Sum256([]byte("b"))
	got := string(Message("https://keyroster.example:8443", "POST", "/p?q=1", sum, 1760961600, "0123456789abcdef0123456789abcdef"))
	want := "keyroster/admin-api/v1\nhttps://keyroster.example:8443\nPOST\n/p?q=1\n" +
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
		h, err := Sign(s, testOrigin, method, path, []byte(body), at)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	// verify runs the server's two steps: Verify over the headers, then
	// CheckBody over the body that was read.
	verifyAt := func(h http.Header, origin, method, path, body string) (string, error) {
		name, _, digest, err := Verify(h, origin, method, path, tNow, admins)
		if err == nil {
			err = CheckBody(digest, []byte(body))
		}
		if err != nil {
			return "", err
		}
		return name, nil
	}
	verify := func(h http.Header, method, path, body string) (string, error) {
		return verifyAt(h, testOrigin, method, path, body)
	}

	t.Run("ed25519_admin_key_accepted", func(t *testing.T) {
		h := sign(t, adminKey, "POST", testPath, testBody, tNow)
		name, nonce, digest, err := Verify(h, testOrigin, "POST", testPath, tNow, admins)
		if err != nil || name != "alice" || nonce != h.Get(HeaderNonce) || len(nonce) != 32 || digest != sha256.Sum256([]byte(testBody)) {
			t.Fatalf("Verify = %q, %q, %x, %v; want alice, the request's nonce and the body's digest", name, nonce, digest, err)
		}
		if h.Get(HeaderBodySHA256) != hex.EncodeToString(digest[:]) {
			t.Fatalf("digest header %q, want the lowercase hex of the body's SHA-256", h.Get(HeaderBodySHA256))
		}
	})
	t.Run("empty_body_digest", func(t *testing.T) {
		h := sign(t, adminKey, "GET", testPath, "", tNow)
		if h.Get(HeaderBodySHA256) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
			t.Fatalf("digest header of an empty body %q", h.Get(HeaderBodySHA256))
		}
		if name, err := verify(h, "GET", testPath, ""); err != nil || name != "alice" {
			t.Fatalf("Verify = %q, %v; want alice", name, err)
		}
	})
	t.Run("other_deployment_origin_refused", func(t *testing.T) {
		// Signed for one deployment, presented to another that trusts the
		// same admin key.
		h := sign(t, adminKey, "POST", testPath, testBody, tNow)
		for _, origin := range []string{"https://staging.example", "https://keyroster.example:8443", "https://KEYROSTER.example"} {
			if name, err := verifyAt(h, origin, "POST", testPath, testBody); !errors.Is(err, ErrMismatch) || name != "" {
				t.Fatalf("verified for %s: %q, %v; want ErrMismatch", origin, name, err)
			}
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
		{"missing_headers", func(*testing.T) http.Header { return http.Header{} }, "POST", testPath, testBody, ErrMissingHeaders},
		{"missing_signature", func(t *testing.T) http.Header {
			h := sign(t, adminKey, "POST", testPath, testBody, tNow)
			h.Del(HeaderSignature)
			return h
		}, "POST", testPath, testBody, ErrMissingHeaders},
		{"missing_digest", func(t *testing.T) http.Header {
			h := sign(t, adminKey, "POST", testPath, testBody, tNow)
			h.Del(HeaderBodySHA256)
			return h
		}, "POST", testPath, testBody, ErrMissingHeaders},
		{"digest_upper_case", func(t *testing.T) http.Header {
			h := sign(t, adminKey, "POST", testPath, testBody, tNow)
			h.Set(HeaderBodySHA256, strings.ToUpper(h.Get(HeaderBodySHA256)))
			return h
		}, "POST", testPath, testBody, ErrBadDigest},
		{"digest_base64", func(t *testing.T) http.Header {
			h := sign(t, adminKey, "POST", testPath, testBody, tNow)
			sum := sha256.Sum256([]byte(testBody))
			h.Set(HeaderBodySHA256, base64.StdEncoding.EncodeToString(sum[:]))
			return h
		}, "POST", testPath, testBody, ErrBadDigest},
		{"digest_short", func(t *testing.T) http.Header {
			h := sign(t, adminKey, "POST", testPath, testBody, tNow)
			h.Set(HeaderBodySHA256, h.Get(HeaderBodySHA256)[:62])
			return h
		}, "POST", testPath, testBody, ErrBadDigest},
		{"digest_prefixed", func(t *testing.T) http.Header {
			h := sign(t, adminKey, "POST", testPath, testBody, tNow)
			h.Set(HeaderBodySHA256, "sha256:"+h.Get(HeaderBodySHA256))
			return h
		}, "POST", testPath, testBody, ErrBadDigest},
		{"digest_changed", func(t *testing.T) http.Header {
			// A well-formed digest of another body: the signature covers
			// the digest, so it no longer verifies.
			h := sign(t, adminKey, "POST", testPath, testBody, tNow)
			sum := sha256.Sum256([]byte(`{"name":"mallory","reinvite":false}`))
			h.Set(HeaderBodySHA256, hex.EncodeToString(sum[:]))
			return h
		}, "POST", testPath, `{"name":"mallory","reinvite":false}`, ErrMismatch},
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
			msg := Message(testOrigin, "POST", testPath, sha256.Sum256([]byte(testBody)), tNow.Unix(), h.Get(HeaderNonce))
			sig, err := sshsig.Sign(rand.Reader, adminKey, "keyroster/issue-request/v1", msg)
			if err != nil {
				t.Fatal(err)
			}
			h.Set(HeaderSignature, base64.StdEncoding.EncodeToString(sig))
			return h
		}, "POST", testPath, testBody, ErrNamespace},
		{"body_changed", func(t *testing.T) http.Header {
			// The headers verify; the body read afterwards is not the
			// signed one.
			return sign(t, adminKey, "POST", testPath, testBody, tNow)
		}, "POST", testPath, `{"name":"mallory","reinvite":false}`, ErrBodyMismatch},
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
	all := []error{ErrMissingHeaders, ErrBadTime, ErrStale, ErrFuture, ErrBadNonce, ErrBadDigest, ErrBadSignature, ErrNotAdmin, ErrNamespace, ErrMismatch, ErrBadPolicy, ErrBodyMismatch}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, err := verify(tc.h(t), tc.method, tc.path, tc.body)
			if !errors.Is(err, tc.want) || name != "" {
				t.Fatalf("Verify = %q, %v; want %v", name, err, tc.want)
			}
			for _, other := range all {
				if !errors.Is(tc.want, other) && errors.Is(err, other) {
					t.Fatalf("Verify error %v also matches %v; each refusal must be distinct", err, other)
				}
			}
		})
	}
}

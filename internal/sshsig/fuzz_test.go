package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

// FuzzSSHSIGParse checks that ParseAll never panics on arbitrary input and
// that every accepted signature re-armors stably: armoring its blob gives a
// block that Parse accepts with the identical blob, key and namespace.
func FuzzSSHSIGParse(f *testing.F) {
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)))
	if err != nil {
		f.Fatal(err)
	}
	seed, err := Sign(rand.Reader, s, "keyroster/trust-bundle/v1", []byte("{}\n"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add(append(bytes.Clone(seed), seed...))
	f.Add(bytes.TrimSuffix(seed, []byte("\n")))
	f.Add([]byte(armorBegin + "\n" + armorEnd + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		sigs, err := ParseAll(data)
		if err != nil {
			return
		}
		for _, sig := range sigs {
			again, err := Parse(armor(sig.blob))
			if err != nil {
				t.Fatalf("re-armored signature does not parse: %v", err)
			}
			if !bytes.Equal(again.blob, sig.blob) || again.namespace != sig.namespace ||
				!bytes.Equal(again.PublicKey().Marshal(), sig.PublicKey().Marshal()) {
				t.Fatal("re-armored signature differs")
			}
			if !bytes.Equal(armor(again.blob), armor(sig.blob)) {
				t.Fatal("armor is not stable")
			}
		}
	})
}

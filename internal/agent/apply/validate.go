//go:build linux

package apply

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/krl"
)

// Candidate refusals: a generation that fails one is never installed.
var (
	ErrCALineRejected   = errors.New("ca_line_rejected")
	ErrKRLInvalid       = errors.New("krl_invalid")
	ErrKRLRejected      = errors.New("krl_rejected_by_ssh_keygen")
	ErrKRLDropsKeyEntry = errors.New("krl_drops_key_entry")
)

// validate checks generation g, written at dir, with the host's own
// tools before any swap may install it: every CA-list line, written alone
// to a one-key file, passes ssh-keygen -l -f (a CA list with no line is
// valid and needs no call); a non-empty revocation list passes krl.Parse
// and ssh-keygen -Q -f <file> <fresh key> exits 0 (a zero-byte one, none
// published yet, revokes nothing). When installed is the generation
// current names, a candidate KRL must keep every explicit-key entry of
// installed's KRL (krl_drops_key_entry): explicit keys never leave a KRL
// (owner rule), and serial and key-ID entries leave only by 03-03's
// pruning, which the applier cannot check.
func (e *engine) validate(ctx context.Context, g *Generation, dir string, installed *Generation) error {
	if err := e.mkdir(e.l.State(checkDir), 0o700); err != nil {
		return err
	}
	check := e.l.State(checkDir)
	for _, name := range fileNames(g) {
		class, ok := ClassOf(name)
		if !ok {
			return fmt.Errorf("generation file %s has no file class", name)
		}
		switch class {
		case FileCAList:
			for i, l := range lines(g.Files[name]) {
				if _, ok := caKey(l); !ok {
					continue
				}
				f := "ca-" + strconv.Itoa(i) + ".pub"
				if err := e.writeFile(check, f, []byte(l+"\n"), 0o600); err != nil {
					return err
				}
				res, err := e.keygenFingerprint(ctx, filepath.Join(check, f))
				if err != nil {
					return fmt.Errorf("%w: %s line %d: ssh-keygen -l: %w", ErrCALineRejected, name, i+1, err)
				}
				if res.Code != 0 {
					return fmt.Errorf("%w: %s line %d: ssh-keygen -l refused it (exit %d): %s", ErrCALineRejected, name, i+1, res.Code, firstLine(res.Stderr))
				}
			}
		case FileKRL:
			b := g.Files[name]
			if len(b) == 0 {
				continue
			}
			cand, err := krl.Parse(b)
			if err != nil {
				return fmt.Errorf("%w: %s: %w", ErrKRLInvalid, name, err)
			}
			if err := e.writeFreshKey(check); err != nil {
				return err
			}
			res, err := e.keygenQuery(ctx, filepath.Join(dir, name), filepath.Join(check, "fresh.pub"))
			if err != nil {
				return fmt.Errorf("%w: ssh-keygen -Q -f %s: %w", ErrKRLRejected, name, err)
			}
			if res.Code != 0 {
				return fmt.Errorf("%w: ssh-keygen -Q -f %s exited %d: %s", ErrKRLRejected, name, res.Code, firstLine(res.Stderr))
			}
			if installed == nil {
				continue
			}
			old, err := krl.Parse(installed.Files[name])
			if err != nil || len(installed.Files[name]) == 0 {
				continue // nothing installed to keep, or a foreign KRL the agent cannot read
			}
			for _, k := range old.Keys {
				if !containsKey(cand.Keys, k) {
					return fmt.Errorf("%w: the candidate KRL no longer lists an explicitly revoked key that the installed KRL lists", ErrKRLDropsKeyEntry)
				}
			}
		}
	}
	return nil
}

func containsKey(keys [][]byte, k []byte) bool {
	for _, x := range keys {
		if bytes.Equal(x, k) {
			return true
		}
	}
	return false
}

// writeFreshKey writes a new Ed25519 public key to <check>/fresh.pub:
// a key no KRL can revoke, so ssh-keygen -Q exits 0 exactly when it read
// the KRL.
func (e *engine) writeFreshKey(check string) error {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	return e.writeFile(check, "fresh.pub", ssh.MarshalAuthorizedKey(sp), 0o600)
}

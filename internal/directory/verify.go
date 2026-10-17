package directory

import (
	"encoding/json"
	"fmt"
	"slices"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// VerifySignatures counts the distinct admins of pol who signed doc with a
// valid SSHSIG under Namespace (trust.CountPinnedSigners) and returns
// their sorted fingerprints. Fewer than pol.AdminQuorum is ErrQuorum; a
// signature by a key that is not a policy admin does not count, and an
// admin who signed twice counts once.
func VerifySignatures(doc, sigs []byte, pol *trust.Policy) ([]string, error) {
	if pol == nil || pol.AdminQuorum < 1 {
		return nil, fmt.Errorf("%w: no policy with an admin quorum", ErrQuorum)
	}
	pinned := map[string]ssh.PublicKey{}
	for _, a := range pol.Admins {
		pub, err := trust.ParseKey(a.Key)
		if err != nil {
			return nil, fmt.Errorf("directory: policy admin %s: %w", a.Name, err)
		}
		pinned[ssh.FingerprintSHA256(pub)] = pub
	}
	signed, err := trust.CountPinnedSigners(doc, sigs, Namespace, pinned)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrQuorum, err)
	}
	if len(signed) < int(pol.AdminQuorum) {
		return nil, fmt.Errorf("%w: %d of %d admin signatures", ErrQuorum, len(signed), pol.AdminQuorum)
	}
	return signed, nil
}

// CheckSuccessor checks that next may follow the installed directory's
// canonical bytes (nil when none is installed): version 1 with the all-zero
// prev first, then the installed version + 1 with prev = SHA-256 of the
// installed bytes. Anything else is ErrChain. Only the version is read
// from installed, which is not re-validated: a directory that fails
// today's rules must not block installing its successor.
func CheckSuccessor(installed []byte, next *Directory) error {
	if installed == nil {
		if next.Version != 1 || next.Prev != trust.GenesisPrev {
			return fmt.Errorf("%w: the first directory must be version 1 with an all-zero prev", ErrChain)
		}
		return nil
	}
	var cur struct {
		Version uint64 `json:"version"`
	}
	if err := json.Unmarshal(installed, &cur); err != nil || cur.Version < 1 {
		return fmt.Errorf("%w: the installed directory has no readable version", ErrChain)
	}
	if next.Version != cur.Version+1 {
		return fmt.Errorf("%w: version %d does not follow the installed version %d", ErrChain, next.Version, cur.Version)
	}
	if next.Prev != trust.SHA256Hex(installed) {
		return fmt.Errorf("%w: prev is not the SHA-256 of the installed version %d", ErrChain, cur.Version)
	}
	return nil
}

// CheckSuccessorBytes is CheckSuccessor on the version and prev of doc,
// read without parsing or validating the rest of it, so a document that
// cannot follow the installed version (a replayed older version, for
// example) is refused before the cost of Parse. A doc whose version and
// prev do not decode is not refused here: Parse refuses it. The caller
// still runs CheckSuccessor on the parsed document.
func CheckSuccessorBytes(installed, doc []byte) error {
	var next struct {
		Version uint64 `json:"version"`
		Prev    string `json:"prev"`
	}
	if err := json.Unmarshal(doc, &next); err != nil {
		return nil
	}
	return CheckSuccessor(installed, &Directory{Version: next.Version, Prev: next.Prev})
}

// CheckPolicy checks d against the policy in force: every role's max TTL
// is at most the user CA profile's max_ttl_seconds, and every role
// extension is one of that profile's default or allowed extensions.
func CheckPolicy(d *Directory, pol *trust.Policy) error {
	if pol == nil {
		return fmt.Errorf("%w: no policy", ErrPolicy)
	}
	idx := slices.IndexFunc(pol.CAProfiles, func(p trust.CAProfile) bool { return p.Role == trust.RoleUser })
	if idx < 0 {
		return fmt.Errorf("%w: the policy has no user CA profile", ErrPolicy)
	}
	prof := pol.CAProfiles[idx]
	for _, r := range d.Roles {
		if r.MaxTTLSeconds > prof.MaxTTLSeconds {
			return fmt.Errorf("%w: role %s: max_ttl_seconds %d is above the user CA cap %d", ErrPolicy, r.Name, r.MaxTTLSeconds, prof.MaxTTLSeconds)
		}
		for _, e := range r.Extensions {
			if !slices.Contains(prof.DefaultExtensions, e) && !slices.Contains(prof.AllowedExtensions, e) {
				return fmt.Errorf("%w: role %s: extension %q is not allowed by the user CA profile", ErrPolicy, r.Name, e)
			}
		}
	}
	return nil
}

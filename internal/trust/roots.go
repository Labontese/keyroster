package trust

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ParseRootsFile reads a roots.pub file: one root key per line in
// authorized_keys format whose comment is "custody=<value>" (software,
// fido, piv or pkcs11). Blank lines and lines starting with # are ignored.
// Options, duplicate keys and keys of a type a root may not have are
// refused.
func ParseRootsFile(data []byte) ([]RootKey, error) {
	var roots []RootKey
	seen := map[string]bool{}
	for n, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		pub, comment, options, rest, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			return nil, fmt.Errorf("roots line %d: %w", n+1, err)
		}
		if len(options) != 0 || len(rest) != 0 {
			return nil, fmt.Errorf("roots line %d: options are not allowed", n+1)
		}
		if _, ok := pub.(*ssh.Certificate); ok {
			return nil, fmt.Errorf("roots line %d: a certificate cannot be a root", n+1)
		}
		custody, ok := strings.CutPrefix(comment, "custody=")
		if !ok {
			return nil, fmt.Errorf("roots line %d: comment must be custody=<software|fido|piv|pkcs11>, got %q", n+1, comment)
		}
		if !rootKeyTypes[pub.Type()] {
			return nil, fmt.Errorf("%w: roots line %d: root key type %s", ErrAlgorithm, n+1, pub.Type())
		}
		if err := checkRootCustody(pub, custody); err != nil {
			return nil, fmt.Errorf("roots line %d: %w", n+1, err)
		}
		if seen[string(pub.Marshal())] {
			return nil, fmt.Errorf("%w: roots line %d repeats a root key", ErrDuplicateKey, n+1)
		}
		seen[string(pub.Marshal())] = true
		roots = append(roots, RootKey{Key: FormatKey(pub), Custody: custody})
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("%w: the roots file has no keys", ErrInvalid)
	}
	return roots, nil
}

package trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrNotCanonical reports a document that is not byte-identical to its
// canonical encoding. It is returned before any signature is checked.
var ErrNotCanonical = errors.New("trust: document is not canonical JSON")

// canonical is the one encoding of a signed document: encoding/json's
// Marshal of the struct (fields in declaration order, no insignificant
// whitespace, HTML-safe string escaping, integers only) plus one trailing
// newline.
func canonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// decodeStrict decodes exactly one JSON value into v, refusing unknown
// fields, and then requires data to equal canonical(v) byte for byte. The
// equality check catches everything a lenient decoder would silently
// accept: duplicate keys (last wins), case-insensitive key matching,
// reordered keys, whitespace, escapes that decode to the same string,
// trailing data, a byte-order mark and invalid UTF-8. Two parsers can
// therefore never disagree about what a signed document says (Pitfall 5).
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %w", ErrNotCanonical, err)
	}
	c, err := canonical(v)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotCanonical, err)
	}
	if !bytes.Equal(c, data) {
		return ErrNotCanonical
	}
	return nil
}

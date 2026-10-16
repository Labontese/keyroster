package webauthn

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// maxClientData is the largest clientDataJSON accepted. Browsers send a
// few hundred bytes.
const maxClientData = 2048

// clientData is the part of clientDataJSON the signer checks (W3C WebAuthn
// L3 §5.8.1). Every other member is skipped: browsers inject extra keys.
type clientData struct {
	Type         string
	Challenge    string
	Origin       string
	CrossOrigin  bool
	HasTopOrigin bool
}

// errClientDataSyntax is the cause wrapped in ErrClientData for every parse
// failure.
var errClientDataSyntax = errors.New("webauthn: clientDataJSON is not one strict JSON object")

// parseClientData walks exactly one top-level JSON object with the
// encoding/json v1 token API (json/v2, which refuses duplicate names, needs
// go 1.27; go.mod says 1.26). It refuses input over 2048 bytes, invalid
// UTF-8 (which the v1 decoder would replace silently), a duplicate member
// name, a non-string type, challenge, origin or topOrigin, a non-boolean
// crossOrigin and anything after the object. Values of unknown members
// are skipped whole.
func parseClientData(data []byte) (*clientData, error) {
	if len(data) == 0 || len(data) > maxClientData || !utf8.Valid(data) {
		return nil, errClientDataSyntax
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errClientDataSyntax
	}
	cd := &clientData{}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errClientDataSyntax
		}
		name, ok := tok.(string)
		if !ok || seen[name] {
			return nil, errClientDataSyntax
		}
		seen[name] = true
		switch name {
		case "type", "challenge", "origin", "topOrigin":
			v, err := dec.Token()
			if err != nil {
				return nil, errClientDataSyntax
			}
			s, ok := v.(string)
			if !ok {
				return nil, errClientDataSyntax
			}
			switch name {
			case "type":
				cd.Type = s
			case "challenge":
				cd.Challenge = s
			case "origin":
				cd.Origin = s
			default:
				cd.HasTopOrigin = true
			}
		case "crossOrigin":
			v, err := dec.Token()
			if err != nil {
				return nil, errClientDataSyntax
			}
			b, ok := v.(bool)
			if !ok {
				return nil, errClientDataSyntax
			}
			cd.CrossOrigin = b
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, errClientDataSyntax
			}
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errClientDataSyntax
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errClientDataSyntax
	}
	return cd, nil
}

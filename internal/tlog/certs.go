package tlog

import (
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/wire"
)

// LeafCertificates returns the certificates that leaf l records (03-12e):
// the one list of the leaf kinds that carry certificates, which the
// signer's install and keyroster audit verify both read, so the two drain
// scans cannot disagree about which kinds count. A leaf that carries none
// returns none. A certificate that does not parse, is not a certificate or
// is not canonically encoded is an error naming the leaf kind, never
// skipped.
func LeafCertificates(l Leaf) ([]*ssh.Certificate, error) {
	var (
		blob []byte
		err  error
	)
	switch l.Kind {
	case KindIssue:
		var b *IssueBody
		if b, err = DecodeIssueBody(l.Body); err == nil {
			blob = b.Cert
		}
	case KindLoginIssue:
		var b *LoginIssueBody
		if b, err = DecodeLoginIssueBody(l.Body); err == nil {
			blob = b.Cert
		}
	case KindHostIssue:
		var b *HostIssueBody
		if b, err = DecodeHostIssueBody(l.Body); err == nil {
			blob = b.Cert
		}
	case KindMachineIssue:
		var b *MachineIssueBody
		if b, err = DecodeMachineIssueBody(l.Body); err == nil {
			blob = b.Cert
		}
	case KindProbeIssue:
		// Either polarity: a negative probe's certificate is a
		// certificate of the machine CA like a positive one's.
		var b *ProbeIssueBody
		if b, err = DecodeProbeIssueBody(l.Body); err == nil {
			blob = b.Cert
		}
	case KindRevocationRecovery:
		return recoveryCertificates(l)
	default:
		// Every other kind records no certificate; the test
		// every_kind_is_classified fails for a kind this switch has not
		// classified (T-03-450).
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s body: %w", l.Kind, err)
	}
	c, err := leafCertificate(blob)
	if err != nil {
		return nil, fmt.Errorf("%s certificate: %w", l.Kind, err)
	}
	return []*ssh.Certificate{c}, nil
}

// recoveryCertificates returns every certificate the request of the
// revocation_recovery leaf l carries, kept or revoked, in the request's
// order (03-12e). Parsing the request runs its Validate, which already
// refuses a carried certificate that does not parse or is a plain key and
// names its position; a certificate whose encoding is not canonical
// passes Validate and is refused here, with its position.
func recoveryCertificates(l Leaf) ([]*ssh.Certificate, error) {
	b, err := DecodeRecoveryBody(l.Body)
	if err != nil {
		return nil, fmt.Errorf("%s body: %w", l.Kind, err)
	}
	r, err := wire.ParseRecoverySigningBytes(b.Request)
	if err != nil {
		return nil, fmt.Errorf("%s request: %w", l.Kind, err)
	}
	out := make([]*ssh.Certificate, 0, len(r.Certificates))
	for i, rc := range r.Certificates {
		c, err := leafCertificate(rc.Cert)
		if err != nil {
			return nil, fmt.Errorf("%s request: certificate %d: %w", l.Kind, i, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// leafCertificate parses blob as an SSH certificate whose encoding is the
// canonical one.
func leafCertificate(blob []byte) (*ssh.Certificate, error) {
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, err
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("a %s key, not a certificate", pub.Type())
	}
	if !bytes.Equal(c.Marshal(), blob) {
		return nil, errors.New("the encoding is not canonical")
	}
	return c, nil
}

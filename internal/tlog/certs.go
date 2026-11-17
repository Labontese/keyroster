package tlog

import (
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// LeafCertificates returns the certificates that leaf l records (03-12e):
// the one list of the leaf kinds that carry certificates, which the
// signer's install and keyroster audit verify both read, so the two drain
// scans cannot disagree about which kinds count. A leaf that carries none
// returns none. A certificate that does not parse, is not a certificate or
// is not canonically encoded is an error naming the leaf kind, never
// skipped.
func LeafCertificates(l Leaf) ([]*ssh.Certificate, error) {
	switch l.Kind {
	case KindIssue:
		b, err := DecodeIssueBody(l.Body)
		if err != nil {
			return nil, fmt.Errorf("%s body: %w", l.Kind, err)
		}
		c, err := leafCertificate(b.Cert)
		if err != nil {
			return nil, fmt.Errorf("%s certificate: %w", l.Kind, err)
		}
		return []*ssh.Certificate{c}, nil
	}
	return nil, nil
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

package tlog

import "golang.org/x/crypto/ssh"

// LeafCertificates returns the certificates that leaf l records (03-12e).
func LeafCertificates(_ Leaf) ([]*ssh.Certificate, error) { return nil, nil }

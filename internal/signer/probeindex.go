package signer

import (
	"crypto/sha256"
	"fmt"
	"maps"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// probeKeyOf names one probe slot: a host name and a polarity (03-10).
type probeKeyOf struct {
	host     string
	negative bool
}

// probeLatest is the latest probe certificate of one host name and
// polarity, as its probe_issue leaf records it.
type probeLatest struct {
	cert       *ssh.Certificate
	certBytes  []byte
	serial     uint64
	leaf       uint64
	issued     uint64 // ValidAfter + 300, the issuance second
	capSeconds uint64
	reqSHA256  [32]byte // of the request's signing bytes
	negative   bool
}

// probeIndex is the probe index (03-10): per host name and polarity the
// latest probe certificate, and the index of the latest krl_publish leaf.
// rebuildLogFrom rebuilds it from every leaf; like the host index it
// follows the committed log (pendingProbes is staged by appendLocked and
// installed by logTx only after COMMIT).
type probeIndex struct {
	byHost      map[probeKeyOf]probeLatest
	lastPublish uint64
	havePublish bool
}

// probeRelevant reports whether apply changes the index for a leaf of
// kind k.
func probeRelevant(k tlog.Kind) bool {
	return k == tlog.KindProbeIssue || k == tlog.KindKRLPublish
}

// apply applies one leaf: a probe_issue makes its certificate the latest
// of its host name and polarity (the logged request names both, and the
// leaf's Negative must be the request's), a krl_publish records its index.
// Other kinds change nothing.
func (p *probeIndex) apply(l tlog.Leaf) error {
	if p.byHost == nil {
		p.byHost = map[probeKeyOf]probeLatest{}
	}
	switch l.Kind {
	case tlog.KindKRLPublish:
		p.lastPublish, p.havePublish = l.Index, true
	case tlog.KindProbeIssue:
		b, err := tlog.DecodeProbeIssueBody(l.Body)
		if err != nil {
			return fmt.Errorf("%w: leaf %d: probe_issue body does not decode", errLogMismatch, l.Index)
		}
		req, err := wire.ParseProbeIssueSigningBytes(b.Request)
		if err != nil {
			return fmt.Errorf("%w: leaf %d: probe_issue request does not parse", errLogMismatch, l.Index)
		}
		if req.Negative != b.Negative {
			return fmt.Errorf("%w: leaf %d: probe_issue negative flag differs from its request's", errLogMismatch, l.Index)
		}
		pub, err := ssh.ParsePublicKey(b.Cert)
		if err != nil {
			return fmt.Errorf("%w: leaf %d: probe certificate does not parse", errLogMismatch, l.Index)
		}
		c, ok := pub.(*ssh.Certificate)
		if !ok {
			return fmt.Errorf("%w: leaf %d: probe certificate is not a certificate", errLogMismatch, l.Index)
		}
		p.byHost[probeKeyOf{req.HostName, b.Negative}] = probeLatest{cert: c, certBytes: b.Cert, serial: b.Serial, leaf: l.Index,
			issued: c.ValidAfter + 300, capSeconds: b.CapSeconds, reqSHA256: sha256.Sum256(b.Request), negative: b.Negative}
	}
	return nil
}

// clone is a deep copy of p (the certificates themselves are never
// modified).
func (p *probeIndex) clone() probeIndex {
	c := probeIndex{byHost: maps.Clone(p.byHost), lastPublish: p.lastPublish, havePublish: p.havePublish}
	if c.byHost == nil {
		c.byHost = map[probeKeyOf]probeLatest{}
	}
	return c
}

// latest returns the latest probe certificate of host and polarity.
func (p *probeIndex) latest(host string, negative bool) (probeLatest, bool) {
	l, ok := p.byHost[probeKeyOf{host, negative}]
	return l, ok
}

// published reports whether a krl_publish leaf with an index above leaf
// exists: only then can a published KRL list the certificate of that leaf.
func (p *probeIndex) published(leaf uint64) bool {
	return p.havePublish && p.lastPublish > leaf
}

// coversUntil reports whether the latest negative certificate of host is
// published and valid until at least until (Unix seconds).
func (p *probeIndex) coversUntil(host string, until uint64) bool {
	l, ok := p.latest(host, true)
	return ok && p.published(l.leaf) && l.cert.ValidBefore >= until
}

// hasUnpublishedNegative reports whether the latest negative certificate
// of some host is not yet published.
func (p *probeIndex) hasUnpublishedNegative() bool {
	for k, l := range p.byHost {
		if k.negative && !p.published(l.leaf) {
			return true
		}
	}
	return false
}

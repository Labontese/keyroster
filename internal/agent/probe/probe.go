// Package probe is the host agent's pure probe-certificate core (03-10b,
// D-06): the file names, the probe record and its attempts, BuildRequest,
// VerifyCert, PairUsable, Decide and the closed sticky list. It reads no
// file, runs nothing and draws no randomness of its own: the applier
// passes the random source and the key generator in, so the package stays
// pure and builds on every GOOS, like internal/agent/hostcert, the only
// agent-internal package it imports.
//
// A probe pair is one positive and one negative probe certificate for the
// host's own entry, issued by the machine CA by proof of possession (a
// fresh Ed25519 key per request, its private half cleared as soon as the
// request is signed). The negative is revoked by its own serial in the KRL
// the signer publishes; the applier keeps the pair in use until a newer
// pair's negative is listed in the KRL in force (Q1).
package probe

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/hostcert"
	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/certprofile"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// Limits and names (03-10b, 'Contracts frozen by this plan').
const (
	// MaxRecord bounds <state>/probe.json.
	MaxRecord = 16 << 10
	// RecordVersion is the record format this package writes and reads.
	RecordVersion = 1
	// RecordFile is the record's name under the state directory.
	RecordFile = "probe.json"
	// SpoolPrefix starts every probe answer's name in the spool and every
	// probe request's name in the outbox: no spool document has it.
	SpoolPrefix = "probecert-"
)

// Polarity is which probe certificate of a pair: the positive one sshd
// must accept, or the negative one only the KRL revokes.
type Polarity string

// The two polarities.
const (
	Positive Polarity = "positive"
	Negative Polarity = "negative"
)

// Polarities lists both, positive first.
var Polarities = []Polarity{Positive, Negative}

var (
	// RequestFileRE matches RequestFileName.
	RequestFileRE = regexp.MustCompile(`^probecert-(positive|negative)\.req$`)
	// AnswerFileRE matches AnswerFileName.
	AnswerFileRE = regexp.MustCompile(`^probecert-(positive|negative)\.answer$`)

	hex64RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	requestIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// RequestFileName is the outbox request of polarity pol.
func RequestFileName(pol Polarity) string { return SpoolPrefix + string(pol) + ".req" }

// AnswerFileName is the spool answer of polarity pol.
func AnswerFileName(pol Polarity) string { return SpoolPrefix + string(pol) + ".answer" }

// Cert is one kept probe certificate: its serial, issuance second
// (ValidAfter + 300), ValidBefore, the renewal time drawn once when it was
// kept, the SHA-256 of the CA key that signed it and of the probe key it
// certifies (lowercase hex over the SSH wire encoding), and the
// certificate itself in SSH wire format.
type Cert struct {
	Serial      uint64 `json:"serial"`
	IssuedAt    uint64 `json:"issued_at"`
	ValidBefore uint64 `json:"valid_before"`
	RenewAt     uint64 `json:"renew_at"`
	CASHA256    string `json:"ca_sha256"`
	KeySHA256   string `json:"key_sha256"`
	Cert        []byte `json:"cert"`
}

// NewCert is the record entry of a verified certificate c with the renewal
// time renewAt (hostcert.RenewAt, drawn by the caller).
func NewCert(c *ssh.Certificate, renewAt uint64) *Cert {
	return &Cert{
		Serial: c.Serial, IssuedAt: hostcert.IssuedAt(c), ValidBefore: c.ValidBefore, RenewAt: renewAt,
		CASHA256: hostcert.KeySHA256(c.SignatureKey), KeySHA256: hostcert.KeySHA256(c.Key), Cert: c.Marshal(),
	}
}

// Parse returns the certificate of c, or nil when c is nil or does not
// parse.
func (c *Cert) Parse() *ssh.Certificate {
	if c == nil {
		return nil
	}
	sc, err := hostcert.ParseCert(c.Cert)
	if err != nil {
		return nil
	}
	return sc
}

func (c *Cert) validate() error {
	switch {
	case !hex64RE.MatchString(c.CASHA256), !hex64RE.MatchString(c.KeySHA256):
		return errors.New("probe: certificate hex field")
	case c.Serial == 0:
		return errors.New("probe: certificate serial 0")
	case c.IssuedAt >= c.ValidBefore || c.RenewAt < c.IssuedAt || c.RenewAt >= c.ValidBefore:
		return errors.New("probe: certificate times")
	}
	sc, err := hostcert.ParseCert(c.Cert)
	if err != nil {
		return fmt.Errorf("probe: certificate: %w", err)
	}
	if sc.Serial != c.Serial || sc.ValidBefore != c.ValidBefore {
		return errors.New("probe: the certificate's serial or valid_before differs from the record's")
	}
	return nil
}

// Pair is a positive and a negative probe certificate; either may be nil.
type Pair struct {
	Positive *Cert `json:"positive"`
	Negative *Cert `json:"negative"`
}

// Get returns the member of polarity pol.
func (p *Pair) Get(pol Polarity) *Cert {
	if pol == Positive {
		return p.Positive
	}
	return p.Negative
}

// Set sets the member of polarity pol.
func (p *Pair) Set(pol Polarity, c *Cert) {
	if pol == Positive {
		p.Positive = c
	} else {
		p.Negative = c
	}
}

// Complete reports whether both members are present.
func (p Pair) Complete() bool { return p.Positive != nil && p.Negative != nil }

// Empty reports whether neither member is present.
func (p Pair) Empty() bool { return p.Positive == nil && p.Negative == nil }

// Serials returns the two serials (0 for an absent member).
func (p Pair) Serials() (uint64, uint64) {
	var a, b uint64
	if p.Positive != nil {
		a = p.Positive.Serial
	}
	if p.Negative != nil {
		b = p.Negative.Serial
	}
	return a, b
}

// Pending is one request ID the applier issued for a polarity: its 32 hex
// digits, CreatedAt, whether an answer for it was consumed, and the probe
// public key it asked to certify (SSH wire format). The private half is
// never recorded.
type Pending struct {
	ID        string `json:"id"`
	CreatedAt uint64 `json:"created_at"`
	Consumed  bool   `json:"consumed"`
	ProbeKey  []byte `json:"probe_key"`
}

// Live reports whether the request is still answerable at now.
func (p Pending) Live(now uint64) bool {
	return now < p.CreatedAt+hostcert.RequestTTL && now+hostcert.BackoffMax >= p.CreatedAt
}

// Attempt is one polarity's request state, hostcert.Attempt's shape: at
// most hostcert.MaxPending recent requests, the transient failure count,
// the time the back-off allows the next request, the last code and a
// sticky refusal.
type Attempt struct {
	Requests []Pending            `json:"requests"`
	Failures uint64               `json:"failures"`
	NextAt   uint64               `json:"next_at"`
	LastCode string               `json:"last_code"`
	Sticky   *hostcert.StickyHold `json:"sticky"`
}

// AddRequest records a new request, keeping the MaxPending newest.
func (a *Attempt) AddRequest(id string, createdAt uint64, probeKey []byte) {
	a.Requests = append(a.Requests, Pending{ID: id, CreatedAt: createdAt, ProbeKey: probeKey})
	if n := len(a.Requests); n > hostcert.MaxPending {
		a.Requests = slices.Clone(a.Requests[n-hostcert.MaxPending:])
	}
}

// Pending returns the live, unconsumed request, or nil.
func (a *Attempt) Pending(now uint64) *Pending {
	for i := len(a.Requests) - 1; i >= 0; i-- {
		if r := &a.Requests[i]; !r.Consumed && r.Live(now) {
			return r
		}
	}
	return nil
}

// Answerable returns the unconsumed live request with ID id, or nil: an
// answer is read only for one of the applier's own recent request IDs.
func (a *Attempt) Answerable(id string, now uint64) *Pending {
	for i := range a.Requests {
		if r := &a.Requests[i]; r.ID == id && !r.Consumed && r.Live(now) {
			return r
		}
	}
	return nil
}

// Abandoned marks consumed the unconsumed requests that expired by now and
// returns how many and the newest one's CreatedAt.
func (a *Attempt) Abandoned(now uint64) (int, uint64) {
	n, created := 0, uint64(0)
	for i := range a.Requests {
		if r := &a.Requests[i]; !r.Consumed && !r.Live(now) {
			r.Consumed = true
			n++
			created = max(created, r.CreatedAt)
		}
	}
	return n, created
}

// Attempts are both polarities' attempts.
type Attempts struct {
	Positive Attempt `json:"positive"`
	Negative Attempt `json:"negative"`
}

// Get returns the attempt of polarity pol.
func (a *Attempts) Get(pol Polarity) *Attempt {
	if pol == Positive {
		return &a.Positive
	}
	return &a.Negative
}

// Record is <state>/probe.json: the pair in use (Committed), the pair being
// collected (Next), both polarities' attempts and the issuance step's last
// hold or refusal code (Detail, "" for none).
type Record struct {
	Version   int      `json:"version"`
	Committed Pair     `json:"committed"`
	Next      Pair     `json:"next"`
	Attempts  Attempts `json:"attempts"`
	Detail    string   `json:"detail"`
}

// NewRecord is an empty record.
func NewRecord() *Record {
	return &Record{Version: RecordVersion, Attempts: Attempts{Positive: Attempt{Requests: []Pending{}}, Negative: Attempt{Requests: []Pending{}}}}
}

// ParseRecord decodes a record strictly (trust.DecodeStrict, at most
// MaxRecord bytes) and validates it.
func ParseRecord(data []byte) (*Record, error) {
	if len(data) > MaxRecord {
		return nil, fmt.Errorf("probe: record above %d bytes", MaxRecord)
	}
	var r Record
	if err := trust.DecodeStrict(data, &r); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Validate checks a record: version 1; each certificate's hex fields,
// serial, times and certificate bytes; each attempt's requests (at most
// hostcert.MaxPending, unique 32-hex IDs, a probe key that parses) and
// codes.
func (r *Record) Validate() error {
	if r.Version != RecordVersion {
		return fmt.Errorf("probe: record version %d", r.Version)
	}
	if r.Detail != "" && !hostcert.CodeRE.MatchString(r.Detail) {
		return errors.New("probe: record detail")
	}
	for _, p := range []Pair{r.Committed, r.Next} {
		for _, c := range []*Cert{p.Positive, p.Negative} {
			if c == nil {
				continue
			}
			if err := c.validate(); err != nil {
				return err
			}
		}
	}
	for _, a := range []Attempt{r.Attempts.Positive, r.Attempts.Negative} {
		if len(a.Requests) > hostcert.MaxPending {
			return fmt.Errorf("probe: more than %d requests for one polarity", hostcert.MaxPending)
		}
		seen := map[string]bool{}
		for _, q := range a.Requests {
			if !requestIDRE.MatchString(q.ID) || seen[q.ID] {
				return errors.New("probe: attempt request ID")
			}
			seen[q.ID] = true
			if _, err := ssh.ParsePublicKey(q.ProbeKey); err != nil {
				return errors.New("probe: attempt probe key")
			}
		}
		if a.LastCode != "" && !hostcert.CodeRE.MatchString(a.LastCode) {
			return errors.New("probe: attempt code")
		}
		if s := a.Sticky; s != nil && !hostcert.DetailRE.MatchString(s.Code) {
			return errors.New("probe: sticky code")
		}
	}
	return nil
}

// Encode is the record's canonical encoding (trust.CanonicalJSON).
func (r *Record) Encode() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return trust.CanonicalJSON(r)
}

// KeyGen generates an Ed25519 key from a random source. The applier passes
// ed25519.GenerateKey; this package never names a generator itself.
type KeyGen func(io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error)

// BuildRequest builds a ProbeIssueRequest for the host's own entry: the
// installation, the entry's name, the host key, a fresh probe key from
// keygen(rnd), the polarity, valid_for 0 (the signer chooses the lifetime),
// a fresh request ID from rnd and CreatedAt now, signed over its signing
// bytes under wire.ProbePoPNamespace by the host key (host-pop/v1) and then
// by the probe key (probe-pop/v1). The probe key's private half is cleared
// before BuildRequest returns, on every path, and never leaves it; it
// returns the request and the probe public key.
func BuildRequest(host ssh.Signer, installationID, hostName string, negative bool, now time.Time, rnd io.Reader, keygen KeyGen) (req *wire.ProbeIssueRequest, probeKey ssh.PublicKey, err error) {
	pub, priv, err := keygen(rnd)
	defer func() { clear(priv) }()
	if err != nil {
		return nil, nil, err
	}
	probeSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, err
	}
	probeKey, err = ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	req = &wire.ProbeIssueRequest{
		InstallationID: installationID,
		HostName:       hostName,
		HostKey:        host.PublicKey().Marshal(),
		ProbeKey:       probeKey.Marshal(),
		Negative:       negative,
		CreatedAt:      uint64(max(now.Unix(), 0)),
	}
	if _, err := io.ReadFull(rnd, req.RequestID[:]); err != nil {
		return nil, nil, err
	}
	signed := req.SigningBytes()
	hostSig, err := sshsig.Sign(rnd, host, wire.ProbePoPNamespace, signed)
	if err != nil {
		return nil, nil, err
	}
	probeSig, err := sshsig.Sign(rnd, probeSigner, wire.ProbePoPNamespace, signed)
	if err != nil {
		return nil, nil, err
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceHostPoP, Blob: hostSig}, {Type: wire.EvidenceProbePoP, Blob: probeSig}}
	if err := req.Validate(); err != nil {
		return nil, nil, err
	}
	return req, probeKey, nil
}

// CertError is a VerifyCert refusal: Code is its closed code.
type CertError struct {
	Code string
	Msg  string
}

func (e *CertError) Error() string {
	if e.Msg == "" {
		return "probe: " + e.Code
	}
	return "probe: " + e.Code + ": " + e.Msg
}

func refuse(code, format string, args ...any) error {
	return &CertError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// ErrCode returns the code of a VerifyCert error ("answer_malformed" for
// any other error).
func ErrCode(err error) string {
	var ce *CertError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return hostcert.ErrAnswerMalformed.Error()
}

// CertCheck is what a probe certificate is verified against: the host's
// entry name, the probe key of the request it answers, the machine CA keys
// of the verified bundle in force and the time.
type CertCheck struct {
	HostName string
	ProbeKey ssh.PublicKey
	CAKeys   []ssh.PublicKey
	Now      time.Time
}

// VerifyCert is the one check of a probe certificate before it is kept: a
// user certificate of exactly ProbeKey; the one principal
// cert.ReservedPrincipalPrefix + HostName; no extension; exactly
// certprofile.ProbeCriticalOptions; signed by a machine CA key of CAKeys
// with a signature that verifies; a kr3 key ID with ca=machine,
// sub=probe.<HostName> and ser the serial; a lifetime V in
// [1, certprofile.MaxProbeLifetimeSeconds]; and ValidAfter <= now <
// ValidBefore - min(60, V/6). Each refusal carries its own code. It does
// not look at the KRL: the pair rules are PairUsable's.
func VerifyCert(c *ssh.Certificate, in CertCheck) error {
	if c == nil || c.Key == nil || c.SignatureKey == nil || in.ProbeKey == nil {
		return refuse("answer_malformed", "no certificate")
	}
	if c.CertType != ssh.UserCert {
		return refuse("wrong_type_host_cert", "certificate type %d", c.CertType)
	}
	if !bytes.Equal(c.Key.Marshal(), in.ProbeKey.Marshal()) {
		return refuse("other_key", "")
	}
	want := cert.ReservedPrincipalPrefix + in.HostName
	switch {
	case len(c.ValidPrincipals) != 1:
		return refuse("two_principals", "%d principals", len(c.ValidPrincipals))
	case len(c.ValidPrincipals[0]) < len(cert.ReservedPrincipalPrefix) || c.ValidPrincipals[0][:len(cert.ReservedPrincipalPrefix)] != cert.ReservedPrincipalPrefix:
		return refuse("principal_without_prefix", "%q", c.ValidPrincipals[0])
	case c.ValidPrincipals[0] != want:
		return refuse("principal_other_host", "%q, want %q", c.ValidPrincipals[0], want)
	}
	if len(c.Extensions) != 0 {
		return refuse("extension_present", "%v", slices.Sorted(maps.Keys(c.Extensions)))
	}
	opts := certprofile.ProbeCriticalOptions()
	if v, ok := c.CriticalOptions["force-command"]; !ok {
		return refuse("force_command_missing", "")
	} else if v != opts["force-command"] {
		return refuse("force_command_value", "%q", v)
	}
	if v, ok := c.CriticalOptions["source-address"]; !ok {
		return refuse("source_address_missing", "")
	} else if v != opts["source-address"] {
		return refuse("source_address_value", "%q", v)
	}
	if !maps.Equal(c.CriticalOptions, opts) {
		return refuse("extra_critical_option", "%v", slices.Sorted(maps.Keys(c.CriticalOptions)))
	}
	kid, err := cert.ParseKeyID(c.KeyId)
	switch {
	case err != nil || !kid.V3:
		return refuse("key_id_not_kr3", "%q", c.KeyId)
	case kid.CA != wire.CARoleMachine.String():
		return refuse("key_id_ca_not_machine", "ca=%s", kid.CA)
	case kid.Subject != "probe."+in.HostName:
		return refuse("key_id_subject_other_host", "sub=%s", kid.Subject)
	case kid.Serial != c.Serial:
		return refuse("key_id_serial_mismatch", "ser=%d, serial %d", kid.Serial, c.Serial)
	}
	v := hostcert.Lifetime(c)
	switch {
	case v == 0:
		return refuse("lifetime_zero", "")
	case v > certprofile.MaxProbeLifetimeSeconds:
		return refuse("lifetime_over_seven_days", "%d s", v)
	}
	// Every structural rule is checked above, before any key is trusted:
	// the CA key and the signature come last but the time.
	if !slices.ContainsFunc(in.CAKeys, func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), c.SignatureKey.Marshal()) }) {
		return refuse("ca_not_trusted", "")
	}
	// The signature, checked at a time inside the certificate's window so
	// that only the signature can fail.
	checker := &ssh.CertChecker{
		Clock:                    func() time.Time { return time.Unix(int64(min(c.ValidAfter, uint64(1)<<62)), 0) }, //nolint:gosec // G115: clamped
		SupportedCriticalOptions: []string{"force-command", "source-address"},
	}
	if err := checker.CheckCert(want, c); err != nil {
		return refuse("signature_invalid", "%v", err)
	}
	now := uint64(max(in.Now.Unix(), 0))
	switch {
	case now < c.ValidAfter:
		return refuse("not_yet_valid", "")
	case now+hostcert.MissingMargin(v) >= c.ValidBefore:
		return refuse("expired_or_in_margin", "")
	}
	return nil
}

// Pair rule codes (PairUsable), also gate hold reasons.
const (
	CertMissing      = "cert_missing"
	PositiveInKRL    = "positive_in_krl"
	NegativeNotInKRL = "negative_not_in_krl"
	CAMismatch       = "ca_mismatch"
)

// validAt reports whether c is valid at at: ValidAfter <= at <
// ValidBefore - min(60, V/6).
func validAt(c *ssh.Certificate, at uint64) bool {
	v := hostcert.Lifetime(c)
	return v > 0 && at >= c.ValidAfter && at+hostcert.MissingMargin(v) < c.ValidBefore
}

// PairUsable returns "" when p can probe sshd at time at against the KRL k
// and the CA keys caKeys, else the first failing rule: cert_missing
// (either member absent, unparsable or not valid at at), positive_in_krl
// (k revokes the positive), negative_not_in_krl (k does not list the
// negative's serial under its CA key: a key ID or key entry is not
// enough), ca_mismatch (the two are not signed by one key, or that key is
// not in caKeys).
func PairUsable(p Pair, at time.Time, k *krl.Parsed, caKeys []ssh.PublicKey) string {
	pos, neg := p.Positive.Parse(), p.Negative.Parse()
	t := uint64(max(at.Unix(), 0))
	if pos == nil || neg == nil || !validAt(pos, t) || !validAt(neg, t) {
		return CertMissing
	}
	if hostcert.Revoked(k, pos) {
		return PositiveInKRL
	}
	if k == nil || !k.RevokesSerial(neg.SignatureKey.Marshal(), neg.Serial) {
		return NegativeNotInKRL
	}
	ca := pos.SignatureKey.Marshal()
	if !bytes.Equal(ca, neg.SignatureKey.Marshal()) || !slices.ContainsFunc(caKeys, func(c ssh.PublicKey) bool { return bytes.Equal(c.Marshal(), ca) }) {
		return CAMismatch
	}
	return ""
}

// memberUsable reports whether a single member of a pair being collected
// can still be part of a usable pair at t: valid, not revoked as a
// positive, and signed by a trusted CA key.
func memberUsable(pol Polarity, c *Cert, t uint64, k *krl.Parsed, caKeys []ssh.PublicKey) bool {
	sc := c.Parse()
	if sc == nil || !validAt(sc, t) {
		return false
	}
	if pol == Positive && hostcert.Revoked(k, sc) {
		return false
	}
	ca := sc.SignatureKey.Marshal()
	return slices.ContainsFunc(caKeys, func(c ssh.PublicKey) bool { return bytes.Equal(c.Marshal(), ca) })
}

// Defer codes (Decide), hostcert's.
const (
	DeferPending       = hostcert.DeferPending
	DeferBackoff       = hostcert.DeferBackoff
	DeferRefusedPrefix = hostcert.DeferRefusedPrefix
)

// Request is one request Decide asks for: the polarity and why (missing,
// renew, half).
type Request struct {
	Polarity Polarity
	Why      string
}

// Plan is Decide's answer: a host-level hold (and whether it writes
// nothing), the requests to make, whether Next replaces Committed, and the
// polarities that wait, with why.
type Plan struct {
	Hold         string
	WriteNothing bool
	Requests     []Request
	Switch       bool
	DropNext     bool
	Defers       map[Polarity]string
}

// Input is everything Decide decides from.
type Input struct {
	Now time.Time
	// Committed is the pair in use, Next the pair being collected.
	Committed, Next Pair
	Attempts        *Attempts
	// The facts of hostcert.Input that HostHold reads.
	Entry                         *directory.Host
	Authorized                    bool
	HostStatus                    string
	NoGeneration, ApplyUnfinished bool
	// The accepted bundle, policy and directory versions, which release a
	// sticky hold.
	Bundle, Policy, Directory uint64
	// CAKeys are the machine CA keys of the verified bundle in force, KRL
	// the KRL in force.
	CAKeys []ssh.PublicKey
	KRL    *krl.Parsed
}

// HostHold is hostcert.HostHold over in's host facts.
func (in Input) HostHold() (string, bool) {
	return hostcert.HostHold(hostcert.Input{
		Entry: in.Entry, Authorized: in.Authorized, HostStatus: in.HostStatus,
		NoGeneration: in.NoGeneration, ApplyUnfinished: in.ApplyUnfinished,
	})
}

// renewDue reports whether the pair is at or past its renewal time.
func renewDue(p Pair, now uint64) bool {
	return p.Complete() && now >= min(p.Positive.RenewAt, p.Negative.RenewAt)
}

// Decide is the pure decision of one issuance step. A host-level hold
// (hostcert.HostHold) yields the hold alone. Otherwise:
//   - Switch: Next is a complete pair PairUsable accepts now against the
//     KRL in force, and Committed is not usable, absent or due for renewal
//     (the pair in use is kept until a newer pair's negative is listed:
//     Q1).
//   - DropNext: a complete Next that can never become usable (missing,
//     positive revoked, CA mismatch); it is collected again.
//   - Requests: both polarities when no pair is usable or Committed is due
//     for renewal and Next is empty; the missing polarity of a half Next.
//   - Defers: a polarity with a live request (request_pending), a sticky
//     refusal not yet released (refused:<code>) or a running back-off.
func Decide(in Input) Plan {
	if code, nothing := in.HostHold(); code != "" {
		return Plan{Hold: code, WriteNothing: nothing}
	}
	pl := Plan{Defers: map[Polarity]string{}}
	now := uint64(max(in.Now.Unix(), 0))
	committed, next := in.Committed, in.Next
	committedOK := PairUsable(committed, in.Now, in.KRL, in.CAKeys) == ""
	if next.Complete() {
		switch PairUsable(next, in.Now, in.KRL, in.CAKeys) {
		case "":
			if !committedOK || renewDue(committed, now) {
				pl.Switch = true
				committed, next = next, Pair{}
				committedOK = true
			}
		case NegativeNotInKRL:
			// Kept until the signer's KRL lists its negative (Q1).
		default:
			pl.DropNext = true
			next = Pair{}
		}
	}
	// A half pair's member that can no longer be part of a usable pair is
	// collected again.
	for _, pol := range Polarities {
		if c := next.Get(pol); c != nil && !next.Complete() && !memberUsable(pol, c, now, in.KRL, in.CAKeys) {
			pl.DropNext = true
			next = Pair{}
		}
	}
	var want []Request
	switch {
	case next.Empty() && !committedOK:
		want = []Request{{Positive, "missing"}, {Negative, "missing"}}
	case next.Empty() && renewDue(committed, now):
		want = []Request{{Positive, "renew"}, {Negative, "renew"}}
	case !next.Empty() && !next.Complete():
		for _, pol := range Polarities {
			if next.Get(pol) == nil {
				want = append(want, Request{pol, "half"})
			}
		}
	}
	attempts := in.Attempts
	if attempts == nil {
		attempts = &Attempts{}
	}
	for _, r := range want {
		a := attempts.Get(r.Polarity)
		switch {
		case a.Pending(now) != nil:
			pl.Defers[r.Polarity] = DeferPending
		case a.Sticky != nil && !hostcert.StickyReleased(a.Sticky, now, in.Bundle, in.Policy, in.Directory):
			pl.Defers[r.Polarity] = DeferRefusedPrefix + a.Sticky.Code
		case hostcert.BackoffActive(a.NextAt, now):
			pl.Defers[r.Polarity] = DeferBackoff
		default:
			pl.Requests = append(pl.Requests, r)
		}
	}
	return pl
}

// LastIssued returns the issuance second of the latest certificate of
// polarity pol the record knows (0: none) and that certificate.
func LastIssued(committed, next Pair, pol Polarity) (uint64, *ssh.Certificate) {
	var at uint64
	var latest *ssh.Certificate
	for _, p := range []Pair{committed, next} {
		if c := p.Get(pol); c != nil && c.IssuedAt > at {
			if sc := c.Parse(); sc != nil {
				at, latest = c.IssuedAt, sc
			}
		}
	}
	return at, latest
}

// Fail records a failed attempt of polarity pol with code in in.Attempts:
// a sticky hold for a code on the closed list (IsSticky), else a transient
// failure with hostcert.NextBackoff, measured against the committed
// member of that polarity. For probe_cert_recent, when the record knows
// the latest certificate of that polarity, the next attempt waits for the
// end of certprofile.ProbeCertRecent's window instead (P4: after an
// agent-side state loss nothing is known and the back-off applies; never
// a sticky hold).
func Fail(in Input, pol Polarity, code string) {
	a := in.Attempts.Get(pol)
	now := uint64(max(in.Now.Unix(), 0))
	a.LastCode = code
	if IsSticky(code) {
		a.Sticky = &hostcert.StickyHold{Code: code, Bundle: in.Bundle, Policy: in.Policy, Directory: in.Directory, At: now}
		return
	}
	a.NextAt, a.Failures = hostcert.NextBackoff(now, a.Failures+1, in.Committed.Get(pol).Parse())
	if code == "probe_cert_recent" {
		if issued, latest := LastIssued(in.Committed, in.Next, pol); issued > 0 {
			end := issued + min(uint64(3600), hostcert.Lifetime(latest)/3)
			if certprofile.ProbeCertRecent(issued, hostcert.Lifetime(latest), now) != "" && end > now && end <= now+hostcert.BackoffMax {
				a.NextAt = end
			}
		}
	}
}

// stickyDetails is the closed list of sticky refusals of 'Contracts frozen
// by this plan' (03-10b); every http_<status> of a 4xx other than 429 is
// sticky too.
var stickyDetails = map[string]bool{
	"host_key_not_enrolled": true, "host_name_mismatch": true, "signer_too_old": true, "malformed_request": true,
	"unknown_host": true, "host_key_not_listed": true, "host_key_revoked": true, "host_disabled": true,
	"host_pop_not_enabled": true, "probe_issue_no_installation_id": true, "probe_issue_installation_mismatch": true,
	"probe_issue_valid_for_not_zero": true,
}

var httpDetailRE = regexp.MustCompile(`^http_4([0-9]{2})$`)

// IsSticky reports whether a refusal detail holds a polarity until the
// accepted bundle, policy or directory version changes or 24 h pass: the
// closed list and http_<status> for a 4xx other than 429. Everything else
// (probe_cert_recent, request_time_skew, duplicate_request, the pop and
// key refusals, 5xx, transport errors, an unknown detail) is transient.
func IsSticky(detail string) bool {
	if stickyDetails[detail] {
		return true
	}
	return httpDetailRE.MatchString(detail) && detail != "http_429"
}

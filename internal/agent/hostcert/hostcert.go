// Package hostcert is the host agent's pure host-certificate core (03-09):
// the per-key file names, the host-certificate record and the attempts
// file, the outbox request and spool answer types, BuildRequest,
// VerifyAnswer and Decide. It reads no file and runs nothing, and it
// imports no agent-internal package and no serverclient: the applier
// (internal/agent/apply) and the fetcher (internal/agent/fetch) both use
// it, and only the fetcher maps its types to the server's.
//
// Every per-key name is keyed by the lowercase hex SHA-256 of the host
// key's SSH wire encoding (KeySHA256), never by key type: a directory host
// entry may list up to directory.MaxHostKeys keys of any host type, two of
// one algorithm included (03-09, D1).
package hostcert

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// Limits and timing (03-09, D-16 and the planner defaults, Q-09-6 and
// Q-09-7).
const (
	// MaxRecord bounds hostcert.json, MaxAttempts hostcert-attempts.json,
	// MaxAnswer a spool answer and MaxOutboxRequest an outbox request.
	MaxRecord        = 16 << 10
	MaxAttempts      = 16 << 10
	MaxAnswer        = 16 << 10
	MaxOutboxRequest = 16 << 10
	// MaxLifetime is the hard maximum of a host certificate's lifetime
	// V = ValidBefore - (ValidAfter + 300): 30 days (D-16). The signer
	// chooses the lifetime, min(MaxLifetime, the host cap in force), so
	// no cap is an input of VerifyAnswer or Decide (Q-09-6).
	MaxLifetime = 2592000
	// Backdate is how far cert.Build puts ValidAfter before the issuance
	// time.
	Backdate = 300
	// RequestTTL is how long an outbox request stays answerable: the
	// signer's freshness window plus 30 s. An older request is abandoned.
	RequestTTL = wire.MaxRequestSkewSeconds + 30
	// MaxPending is how many recent request IDs a key keeps.
	MaxPending = 4
	// BackoffMin and BackoffMax bound the transient back-off; a NextAt or
	// StickyHold.At later than now + BackoffMax counts as released (a
	// backward clock step).
	BackoffMin = 60
	BackoffMax = 3600
	// StickyRelease is how long a sticky refusal holds a key when no
	// accepted version changes.
	StickyRelease = 86400
	// RecordVersion and AttemptsVersion are the formats this package
	// writes and reads.
	RecordVersion   = 1
	AttemptsVersion = 1
)

// File names of the host-certificate state (03-09).
const (
	RecordFile   = "hostcert.json"
	AttemptsFile = "hostcert-attempts.json"
)

var (
	// CertFileRE matches CertFileName: <k>-<serial>-cert.pub.
	CertFileRE = regexp.MustCompile(`^([0-9a-f]{64})-([1-9][0-9]{0,19})-cert\.pub$`)
	// RequestFileRE matches RequestFileName, AnswerFileRE AnswerFileName.
	RequestFileRE = regexp.MustCompile(`^hostcert-([0-9a-f]{64})\.req$`)
	AnswerFileRE  = regexp.MustCompile(`^hostcert-([0-9a-f]{64})\.answer$`)

	hex64RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	requestIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// CodeRE is the grammar of every code this package records: a detail,
	// optionally qualified (refused:<detail>).
	CodeRE = regexp.MustCompile(`^[a-z0-9_]{1,64}(:[a-z0-9_]{1,64})?$`)
	// DetailRE is the grammar of a refusal detail in a spool answer.
	DetailRE = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
)

// KeySHA256 is the lowercase hex SHA-256 of pub's SSH wire encoding.
func KeySHA256(pub ssh.PublicKey) string {
	sum := sha256.Sum256(pub.Marshal())
	return hex.EncodeToString(sum[:])
}

// CertFileName is the immutable file name of the certificate with serial
// for key k, under the host-certificate directory.
func CertFileName(k string, serial uint64) string {
	return k + "-" + strconv.FormatUint(serial, 10) + "-cert.pub"
}

// RequestFileName is the outbox request of key k.
func RequestFileName(k string) string { return "hostcert-" + k + ".req" }

// AnswerFileName is the spool answer of key k.
func AnswerFileName(k string) string { return "hostcert-" + k + ".answer" }

// OutboxRequest is an outbox request file: the HostIssueRequest bytes
// (wire.HostIssueRequest.Marshal) the fetcher posts.
type OutboxRequest struct {
	Request []byte `json:"request"`
}

// Answer is a spool answer file the fetcher writes: the request ID it
// answers (32 hex digits) and either the certificate (SSH wire format) or
// a refusal detail.
type Answer struct {
	RequestID   string `json:"request_id"`
	Certificate []byte `json:"certificate,omitempty"`
	Refused     string `json:"refused,omitempty"`
}

// ParseAnswer decodes an answer strictly: canonical JSON, a request ID,
// and exactly one of a certificate and a refusal detail.
func ParseAnswer(data []byte) (*Answer, error) {
	if len(data) > MaxAnswer {
		return nil, errors.New("hostcert: answer too large")
	}
	var a Answer
	if err := trust.DecodeStrict(data, &a); err != nil {
		return nil, err
	}
	switch {
	case !requestIDRE.MatchString(a.RequestID):
		return nil, errors.New("hostcert: answer request ID")
	case (len(a.Certificate) == 0) == (a.Refused == ""):
		return nil, errors.New("hostcert: an answer carries a certificate or a refusal")
	case a.Refused != "" && !DetailRE.MatchString(a.Refused):
		return nil, errors.New("hostcert: answer refusal detail")
	}
	return &a, nil
}

// ParseOutboxRequest decodes an outbox request strictly.
func ParseOutboxRequest(data []byte) (*OutboxRequest, error) {
	if len(data) > MaxOutboxRequest {
		return nil, errors.New("hostcert: outbox request too large")
	}
	var r OutboxRequest
	if err := trust.DecodeStrict(data, &r); err != nil {
		return nil, err
	}
	if len(r.Request) == 0 {
		return nil, errors.New("hostcert: empty outbox request")
	}
	return &r, nil
}

// Entry is one installed (or candidate) host certificate: the key it
// certifies (KeySHA256 and trust.FormatKey form), its file name and
// SHA-256, its serial, its issuance time (ValidAfter + 300), ValidBefore,
// the renewal time drawn when the entry was saved, the SHA-256 of the CA
// key that signed it, and whether the served-certificate self-test saw
// sshd serve it.
type Entry struct {
	KeySHA256   string `json:"key_sha256"`
	Key         string `json:"key"`
	File        string `json:"file"`
	CertSHA256  string `json:"cert_sha256"`
	Serial      uint64 `json:"serial"`
	IssuedAt    uint64 `json:"issued_at"`
	ValidBefore uint64 `json:"valid_before"`
	RenewAt     uint64 `json:"renew_at"`
	CASHA256    string `json:"ca_sha256"`
	Served      bool   `json:"served"`
}

// Record is <state>/hostcert.json: the committed set of host certificates
// the drop-in names, and, while an install or a removal runs
// (InProgress), the candidate set. InProgress, not a nil Candidate, marks
// the install, so a removal of every line is representable (D1).
type Record struct {
	Version    int     `json:"version"`
	Committed  []Entry `json:"committed"`
	InProgress bool    `json:"in_progress"`
	Candidate  []Entry `json:"candidate"`
}

// ParseRecord decodes a record strictly (trust.DecodeStrict, at most
// MaxRecord bytes) and validates it.
func ParseRecord(data []byte) (*Record, error) {
	if len(data) > MaxRecord {
		return nil, fmt.Errorf("hostcert: record above %d bytes", MaxRecord)
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

// Validate checks a record: version 1; each set sorted by KeySHA256,
// unique and at most directory.MaxHostKeys entries; each entry's
// KeySHA256 the hash of its Key, File its CertFileName, hex fields of the
// right length, IssuedAt < ValidBefore and IssuedAt <= RenewAt <
// ValidBefore; Candidate empty unless InProgress.
func (r *Record) Validate() error {
	if r.Version != RecordVersion {
		return fmt.Errorf("hostcert: record version %d", r.Version)
	}
	if !r.InProgress && len(r.Candidate) != 0 {
		return errors.New("hostcert: a candidate set without an install in progress")
	}
	for _, set := range [][]Entry{r.Committed, r.Candidate} {
		if err := validateSet(set); err != nil {
			return err
		}
	}
	return nil
}

func validateSet(set []Entry) error {
	if len(set) > directory.MaxHostKeys {
		return fmt.Errorf("hostcert: more than %d entries", directory.MaxHostKeys)
	}
	for i, e := range set {
		if i > 0 && set[i-1].KeySHA256 >= e.KeySHA256 {
			return errors.New("hostcert: entries are not sorted by key_sha256 and unique")
		}
		if err := e.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (e *Entry) validate() error {
	switch {
	case !hex64RE.MatchString(e.KeySHA256), !hex64RE.MatchString(e.CertSHA256), !hex64RE.MatchString(e.CASHA256):
		return errors.New("hostcert: entry hex field")
	case e.Serial == 0:
		return errors.New("hostcert: entry serial 0")
	case e.File != CertFileName(e.KeySHA256, e.Serial):
		return errors.New("hostcert: entry file is not its CertFileName")
	case !(e.IssuedAt < e.ValidBefore) || e.RenewAt < e.IssuedAt || e.RenewAt >= e.ValidBefore:
		return errors.New("hostcert: entry times")
	}
	pub, err := trust.ParseKey(e.Key)
	if err != nil {
		return fmt.Errorf("hostcert: entry key: %w", err)
	}
	if KeySHA256(pub) != e.KeySHA256 {
		return errors.New("hostcert: entry key_sha256 is not the hash of its key")
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

// Find returns the entry for key k in set, or nil.
func Find(set []Entry, k string) *Entry {
	for i := range set {
		if set[i].KeySHA256 == k {
			return &set[i]
		}
	}
	return nil
}

// SortEntries sorts set by KeySHA256.
func SortEntries(set []Entry) {
	slices.SortFunc(set, func(a, b Entry) int {
		switch {
		case a.KeySHA256 < b.KeySHA256:
			return -1
		case a.KeySHA256 > b.KeySHA256:
			return 1
		}
		return 0
	})
}

// PendingRequest is one request ID the applier issued for a key: its 32
// hex digits, its CreatedAt and whether an answer for it was consumed.
type PendingRequest struct {
	ID        string `json:"id"`
	CreatedAt uint64 `json:"created_at"`
	Consumed  bool   `json:"consumed"`
}

// StickyHold records a sticky refusal (Q-09-7): its detail, the accepted
// bundle, policy and directory versions when it came, and when.
type StickyHold struct {
	Code      string `json:"code"`
	Bundle    uint64 `json:"bundle"`
	Policy    uint64 `json:"policy"`
	Directory uint64 `json:"directory"`
	At        uint64 `json:"at"`
}

// Attempt is one key's request state: its recent request IDs (at most
// MaxPending, each answerable for RequestTTL), the transient failure count
// and the time the back-off allows the next request (NextAt, never more
// than now + BackoffMax when written), the last code, the certificate
// file a verified answer or adoption kept for install (KeptFile), and a
// sticky refusal.
type Attempt struct {
	KeySHA256 string           `json:"key_sha256"`
	Requests  []PendingRequest `json:"requests"`
	Failures  uint64           `json:"failures"`
	NextAt    uint64           `json:"next_at"`
	LastCode  string           `json:"last_code"`
	KeptFile  string           `json:"kept_file"`
	Sticky    *StickyHold      `json:"sticky,omitempty"`
}

// Attempts is <state>/hostcert-attempts.json.
type Attempts struct {
	Version int       `json:"version"`
	Keys    []Attempt `json:"keys"`
}

// ParseAttempts decodes an attempts file strictly and validates it.
func ParseAttempts(data []byte) (*Attempts, error) {
	if len(data) > MaxAttempts {
		return nil, fmt.Errorf("hostcert: attempts above %d bytes", MaxAttempts)
	}
	var a Attempts
	if err := trust.DecodeStrict(data, &a); err != nil {
		return nil, err
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

// Validate checks the attempts: version 1, keys sorted and unique, at
// most directory.MaxHostKeys of them, each with at most MaxPending unique
// request IDs, codes in CodeRE's grammar and a KeptFile of its own key.
func (a *Attempts) Validate() error {
	if a.Version != AttemptsVersion {
		return fmt.Errorf("hostcert: attempts version %d", a.Version)
	}
	if len(a.Keys) > directory.MaxHostKeys {
		return fmt.Errorf("hostcert: attempts for more than %d keys", directory.MaxHostKeys)
	}
	for i, k := range a.Keys {
		if i > 0 && a.Keys[i-1].KeySHA256 >= k.KeySHA256 {
			return errors.New("hostcert: attempts are not sorted by key_sha256 and unique")
		}
		if !hex64RE.MatchString(k.KeySHA256) {
			return errors.New("hostcert: attempt key_sha256")
		}
		if len(k.Requests) > MaxPending {
			return fmt.Errorf("hostcert: more than %d requests for one key", MaxPending)
		}
		seen := map[string]bool{}
		for _, r := range k.Requests {
			if !requestIDRE.MatchString(r.ID) || seen[r.ID] {
				return errors.New("hostcert: attempt request ID")
			}
			seen[r.ID] = true
		}
		if k.LastCode != "" && !CodeRE.MatchString(k.LastCode) {
			return errors.New("hostcert: attempt code")
		}
		if k.KeptFile != "" {
			m := CertFileRE.FindStringSubmatch(k.KeptFile)
			if m == nil || m[1] != k.KeySHA256 {
				return errors.New("hostcert: attempt kept file")
			}
		}
		if s := k.Sticky; s != nil && !DetailRE.MatchString(s.Code) {
			return errors.New("hostcert: sticky code")
		}
	}
	return nil
}

// Encode is the attempts' canonical encoding.
func (a *Attempts) Encode() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return trust.CanonicalJSON(a)
}

// Get returns the attempt of key k, adding an empty one (in sorted
// position) when there is none.
func (a *Attempts) Get(k string) *Attempt {
	i, found := slices.BinarySearchFunc(a.Keys, k, func(x Attempt, k string) int {
		switch {
		case x.KeySHA256 < k:
			return -1
		case x.KeySHA256 > k:
			return 1
		}
		return 0
	})
	if !found {
		a.Keys = slices.Insert(a.Keys, i, Attempt{KeySHA256: k, Requests: []PendingRequest{}})
	}
	return &a.Keys[i]
}

// Lookup returns the attempt of key k, or nil.
func (a *Attempts) Lookup(k string) *Attempt {
	for i := range a.Keys {
		if a.Keys[i].KeySHA256 == k {
			return &a.Keys[i]
		}
	}
	return nil
}

// Drop removes the attempt of key k.
func (a *Attempts) Drop(k string) {
	a.Keys = slices.DeleteFunc(a.Keys, func(x Attempt) bool { return x.KeySHA256 == k })
}

// Live reports whether the request is still answerable at now.
func (p PendingRequest) Live(now uint64) bool {
	return now < p.CreatedAt+RequestTTL && now+BackoffMax >= p.CreatedAt
}

// AddRequest records a new request ID, keeping the MaxPending newest.
func (a *Attempt) AddRequest(id string, createdAt uint64) {
	a.Requests = append(a.Requests, PendingRequest{ID: id, CreatedAt: createdAt})
	if n := len(a.Requests); n > MaxPending {
		a.Requests = slices.Clone(a.Requests[n-MaxPending:])
	}
}

// Pending returns the key's live, unconsumed request, or nil.
func (a *Attempt) Pending(now uint64) *PendingRequest {
	for i := len(a.Requests) - 1; i >= 0; i-- {
		if r := &a.Requests[i]; !r.Consumed && r.Live(now) {
			return r
		}
	}
	return nil
}

// Answerable returns the unconsumed live request with ID id, or nil: an
// answer is read only for one of the applier's own recent request IDs.
func (a *Attempt) Answerable(id string, now uint64) *PendingRequest {
	for i := range a.Requests {
		if r := &a.Requests[i]; r.ID == id && !r.Consumed && r.Live(now) {
			return r
		}
	}
	return nil
}

// Abandoned returns the unconsumed requests that expired by now (one whose
// outbox file was never written included), and marks them consumed.
func (a *Attempt) Abandoned(now uint64) int {
	n := 0
	for i := range a.Requests {
		if r := &a.Requests[i]; !r.Consumed && !r.Live(now) {
			r.Consumed = true
			n++
		}
	}
	return n
}

// stickyDetails is Q-09-7's closed list of sticky refusals; every
// http_<status> of a 4xx other than 429 is sticky too (IsSticky).
var stickyDetails = map[string]bool{
	"cert_revoked": true, "host_key_revoked": true, "unknown_host": true, "host_key_not_listed": true,
	"host_disabled": true, "host_pop_not_enabled": true, "host_issue_no_installation_id": true,
	"host_issue_installation_mismatch": true, "host_key_not_enrolled": true, "host_name_mismatch": true,
	"signer_too_old": true, "malformed_request": true, "ttl_exceeds_host_cap": true,
	"host_issue_valid_for_not_zero": true,
}

var httpDetailRE = regexp.MustCompile(`^http_4([0-9]{2})$`)

// IsSticky reports whether a refusal detail is on Q-09-7's closed sticky
// list: the listed details and http_<status> for a 4xx other than 429.
// Everything else (request_time_skew, directory_changed, host_cert_recent,
// host_pop_invalid, an unknown detail) is transient.
func IsSticky(detail string) bool {
	if stickyDetails[detail] {
		return true
	}
	return httpDetailRE.MatchString(detail) && detail != "http_429"
}

// Lifetime returns a certificate's own lifetime V = ValidBefore -
// (ValidAfter + Backdate), 0 when it has none.
func Lifetime(c *ssh.Certificate) uint64 {
	if c.ValidAfter > c.ValidBefore || c.ValidBefore-c.ValidAfter <= Backdate {
		return 0
	}
	return c.ValidBefore - c.ValidAfter - Backdate
}

// IssuedAt is a certificate's issuance second, ValidAfter + Backdate.
func IssuedAt(c *ssh.Certificate) uint64 { return c.ValidAfter + Backdate }

// MissingMargin is min(60, V/6): a certificate this close to ValidBefore
// counts as missing.
func MissingMargin(v uint64) uint64 { return min(60, v/6) }

// jitterMax is min(3600, V/10).
func jitterMax(v uint64) uint64 { return min(3600, v/10) }

// RenewAt draws a certificate's renewal time: issued + 2V/3 - j, with j
// uniform in [0, min(3600, V/10)) from rnd (crypto/rand in production),
// drawn when the entry is saved.
func RenewAt(c *ssh.Certificate, rnd io.Reader) (uint64, error) {
	v := Lifetime(c)
	base := IssuedAt(c) + 2*v/3
	m := jitterMax(v)
	if m == 0 {
		return base, nil
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	j, err := rand.Int(rnd, new(big.Int).SetUint64(m))
	if err != nil {
		return 0, err
	}
	return base - j.Uint64(), nil
}

// NewEntry is the record entry for a verified certificate c of key pub,
// with c's bytes certBytes and a renewal time drawn from rnd.
func NewEntry(pub ssh.PublicKey, c *ssh.Certificate, certBytes []byte, rnd io.Reader) (Entry, error) {
	renew, err := RenewAt(c, rnd)
	if err != nil {
		return Entry{}, err
	}
	k := KeySHA256(pub)
	sum := sha256.Sum256(certBytes)
	return Entry{
		KeySHA256: k, Key: trust.FormatKey(pub), File: CertFileName(k, c.Serial), CertSHA256: hex.EncodeToString(sum[:]),
		Serial: c.Serial, IssuedAt: IssuedAt(c), ValidBefore: c.ValidBefore, RenewAt: renew, CASHA256: KeySHA256(c.SignatureKey),
	}, nil
}

// NextBackoff is the transient back-off after the failures-th consecutive
// failure (failures >= 1): 60 s, with the count reset, once a valid
// certificate is within min(3600, V/10) of ValidBefore or none is
// installed; otherwise min(60·2^(n-1), 3600). It returns NextAt and the
// failure count to store.
func NextBackoff(now uint64, failures uint64, installed *ssh.Certificate) (nextAt, n uint64) {
	if installed == nil || now+jitterMax(Lifetime(installed)) >= installed.ValidBefore {
		return now + BackoffMin, 0
	}
	n = max(failures, 1)
	d := uint64(BackoffMax)
	if n <= 6 {
		d = min(uint64(BackoffMin)<<(n-1), BackoffMax)
	}
	return now + d, n
}

// BuildRequest builds a HostIssueRequest for host key s: the installation,
// the entry's name, valid_for 0 (the signer chooses the lifetime, Q-09-6),
// a fresh request ID from rnd and CreatedAt now, signed with s over its
// signing bytes under wire.HostPoPNamespace (one host-pop/v1 evidence).
func BuildRequest(s ssh.Signer, installationID, hostName string, now time.Time, rnd io.Reader) (*wire.HostIssueRequest, error) {
	req := &wire.HostIssueRequest{
		InstallationID: installationID,
		HostName:       hostName,
		HostKey:        s.PublicKey().Marshal(),
		CreatedAt:      uint64(max(now.Unix(), 0)),
	}
	if _, err := io.ReadFull(rnd, req.RequestID[:]); err != nil {
		return nil, err
	}
	sig, err := sshsig.Sign(rnd, s, wire.HostPoPNamespace, req.SigningBytes())
	if err != nil {
		return nil, err
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceHostPoP, Blob: sig}}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return req, nil
}

// Answer verification codes (VerifyAnswer).
var (
	ErrAnswerMalformed        = errors.New("answer_malformed")
	ErrAnswerOtherKey         = errors.New("answer_other_key")
	ErrAnswerPrincipalsDiffer = errors.New("answer_principals_differ")
	ErrAnswerUnpinnedCA       = errors.New("answer_unpinned_ca")
	ErrAnswerExpired          = errors.New("answer_expired")
	ErrAnswerRevoked          = errors.New("answer_revoked")
	ErrAnswerTooLong          = errors.New("answer_too_long")
	ErrAnswerNotNewer         = errors.New("answer_not_newer")
)

// AnswerCheck is the state in force a certificate is verified against.
type AnswerCheck struct {
	Key        ssh.PublicKey   // the requested host key
	HostName   string          // the entry's name
	Principals []string        // the entry's principals
	CAKeys     []ssh.PublicKey // the host CA keys of the verified bundle in force
	KRL        *krl.Parsed     // the KRL in force (nil: none)
	Committed  uint64          // the committed serial for the key (0: none)
	Now        time.Time
}

// ParseCert parses a host certificate in SSH wire format.
func ParseCert(b []byte) (*ssh.Certificate, error) {
	pub, err := ssh.ParsePublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAnswerMalformed, err)
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("%w: not a certificate", ErrAnswerMalformed)
	}
	return c, nil
}

// Revoked reports whether the KRL k revokes certificate c: by serial or key
// ID under its CA key, or its key or CA key explicitly.
func Revoked(k *krl.Parsed, c *ssh.Certificate) bool {
	if k == nil {
		return false
	}
	ca := c.SignatureKey.Marshal()
	return k.RevokesSerial(ca, c.Serial) || k.RevokesKeyID(ca, c.KeyId) || k.RevokesKey(c.Key.Marshal()) || k.RevokesKey(ca)
}

// VerifyAnswer is the one check of any certificate before an install,
// re-run at every attempt (issued, re-delivered, kept or adopted): a host
// certificate of the requested key; principals equal to the entry's;
// signed by a host CA key of the verified bundle in force, with its
// signature verifying; a kr3 key ID with ca=host, sub the entry's name
// and ser the serial (its req may name any request: a re-delivery);
// 1 <= V <= MaxLifetime; ValidAfter <= now < ValidBefore - min(60, V/6);
// not revoked by the KRL in force; a serial above the committed one.
func VerifyAnswer(c *ssh.Certificate, in AnswerCheck) error {
	if c == nil || c.CertType != ssh.HostCert || c.Key == nil || c.SignatureKey == nil || in.Key == nil {
		return fmt.Errorf("%w: not a host certificate", ErrAnswerMalformed)
	}
	kid, err := cert.ParseKeyID(c.KeyId)
	if err != nil || !kid.V3 || kid.CA != wire.CARoleHost.String() || kid.Serial != c.Serial {
		return fmt.Errorf("%w: key ID %q", ErrAnswerMalformed, c.KeyId)
	}
	if kid.Subject != in.HostName {
		return fmt.Errorf("%w: key ID sub=%s, want %s", ErrAnswerMalformed, kid.Subject, in.HostName)
	}
	if !bytes.Equal(c.Key.Marshal(), in.Key.Marshal()) {
		return ErrAnswerOtherKey
	}
	if !samePrincipals(c.ValidPrincipals, in.Principals) {
		return ErrAnswerPrincipalsDiffer
	}
	if !slices.ContainsFunc(in.CAKeys, func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), c.SignatureKey.Marshal()) }) {
		return ErrAnswerUnpinnedCA
	}
	if len(c.ValidPrincipals) == 0 {
		return fmt.Errorf("%w: no principals", ErrAnswerMalformed)
	}
	v := Lifetime(c)
	if v == 0 {
		return fmt.Errorf("%w: no lifetime", ErrAnswerMalformed)
	}
	if v > MaxLifetime {
		return ErrAnswerTooLong
	}
	// The signature, checked at a time inside the certificate's window so
	// that only the signature (and the critical options) can fail.
	checker := &ssh.CertChecker{Clock: func() time.Time { return time.Unix(int64(c.ValidAfter), 0) }} //nolint:gosec // G115: ValidAfter < ValidBefore, a Unix time
	if err := checker.CheckCert(c.ValidPrincipals[0], c); err != nil {
		return fmt.Errorf("%w: %w", ErrAnswerUnpinnedCA, err)
	}
	now := uint64(max(in.Now.Unix(), 0))
	if now < c.ValidAfter || now+MissingMargin(v) >= c.ValidBefore {
		return ErrAnswerExpired
	}
	if Revoked(in.KRL, c) {
		return ErrAnswerRevoked
	}
	if c.Serial <= in.Committed {
		return ErrAnswerNotNewer
	}
	return nil
}

// Code returns the answer_* code of a VerifyAnswer error.
func Code(err error) string {
	for _, e := range []error{ErrAnswerMalformed, ErrAnswerOtherKey, ErrAnswerPrincipalsDiffer, ErrAnswerUnpinnedCA,
		ErrAnswerExpired, ErrAnswerRevoked, ErrAnswerTooLong, ErrAnswerNotNewer} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return ErrAnswerMalformed.Error()
}

func samePrincipals(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// CertAlgorithm is the certificate algorithm sshd offers for host key pub
// (the one hostkeyalgorithms must list), "" for a key type the agent does
// not certify (RSA).
func CertAlgorithm(pub ssh.PublicKey) string {
	switch pub.Type() {
	case ssh.KeyAlgoED25519:
		return ssh.CertAlgoED25519v01
	case ssh.KeyAlgoECDSA256:
		return ssh.CertAlgoECDSA256v01
	case ssh.KeyAlgoECDSA384:
		return ssh.CertAlgoECDSA384v01
	case ssh.KeyAlgoECDSA521:
		return ssh.CertAlgoECDSA521v01
	}
	return ""
}

// Hold codes (Decide). The write-nothing holds come first: under them
// HostCerts writes nothing at all. The host-level holds block answers,
// adoption, install, requests and GC for every key.
const (
	HoldNoGeneration           = "no_generation"
	HoldApplyUnfinished        = "apply_unfinished"
	HoldDirectoryUnauthorized  = "directory_unauthorized"
	HoldHostDisabled           = "host_disabled"
	HoldHostRemoved            = "host_removed"
	HoldHostKeysRotated        = "host_keys_rotated"
	HoldHostKeysDisagree       = "host_keys_disagree"
	HoldForeignHostCertificate = "foreign_host_certificate"
	HoldInMatch                = "hostcert_in_match"
	// Per-key defers.
	DeferAlgorithmDisabled = "host_cert_algorithm_disabled"
	DeferBackoff           = "backoff"
	DeferPending           = "request_pending"
	// DeferRefusedPrefix prefixes a sticky refusal's detail.
	DeferRefusedPrefix = "refused:"
)

// ActionKind is the kind of a Decide action.
type ActionKind int

// Decide's actions: a host-level Hold; a per-key Defer (back-off, a
// sticky refusal, a pending request, or host_cert_algorithm_disabled,
// which also defers the key's install); Remove a key's line; Request a
// certificate for a key; Keep a key's installed certificate.
const (
	Hold ActionKind = iota + 1
	Defer
	Remove
	Request
	Keep
)

// Action is one decision of Decide.
type Action struct {
	Kind ActionKind
	// Key is the key's KeySHA256 ("" for a Hold).
	Key string
	// Pub is the host key (nil for a Hold or a Remove).
	Pub ssh.PublicKey
	// Code is the hold or defer code, or why a key is requested
	// (missing, renew, principals_differ, revoked).
	Code string
	// WriteNothing marks the write-nothing holds (no_generation and
	// apply_unfinished).
	WriteNothing bool
}

// Input is everything Decide decides from.
type Input struct {
	Now time.Time
	// Served are the Ed25519 and ECDSA host keys sshd -T names, in HostKey
	// order; HostKeyAlgorithms is sshd -T hostkeyalgorithms (nil: every
	// algorithm).
	Served            []ssh.PublicKey
	HostKeyAlgorithms []string
	// Committed is the record's committed set, Installed the committed
	// certificates whose file is present and matches its SHA-256, by
	// KeySHA256.
	Committed []Entry
	Installed map[string]*ssh.Certificate
	Attempts  *Attempts
	// Entry is the directory entry holding the host's keys (nil: none),
	// Authorized whether the stored directory is authorized, HostStatus the
	// committed generation's host status.
	Entry      *directory.Host
	Authorized bool
	HostStatus string
	// NoGeneration: last-good is not the agent's generation.
	// ApplyUnfinished: a marker is pending, stuck() is set, or Apply's
	// recover predicate holds. Foreign: a HostCertificate directive outside
	// the agent's drop-in. InMatch: the drop-in is reached inside a Match.
	NoGeneration, ApplyUnfinished, Foreign, InMatch bool
	// The accepted bundle, policy and directory versions, which release a
	// sticky hold.
	Bundle, Policy, Directory uint64
	// CAKeys are the trusted host CA keys, KRL the KRL in force.
	CAKeys []ssh.PublicKey
	KRL    *krl.Parsed
}

// HostHold returns the host-level hold of in ("" for none) and whether it
// is a write-nothing hold. Holds come first (Planner decisions).
func HostHold(in Input) (string, bool) {
	switch {
	case in.NoGeneration:
		return HoldNoGeneration, true
	case in.ApplyUnfinished:
		return HoldApplyUnfinished, true
	case !in.Authorized:
		return HoldDirectoryUnauthorized, false
	case in.HostStatus == HoldHostKeysRotated:
		return HoldHostKeysRotated, false
	case in.HostStatus == HoldHostKeysDisagree:
		return HoldHostKeysDisagree, false
	case in.HostStatus == HoldHostRemoved, in.Entry == nil:
		return HoldHostRemoved, false
	case in.HostStatus == HoldHostDisabled, in.Entry.Status != directory.StatusActive:
		return HoldHostDisabled, false
	case in.Foreign:
		return HoldForeignHostCertificate, false
	case in.InMatch:
		return HoldInMatch, false
	}
	return "", false
}

// StickyReleased reports whether a sticky hold no longer holds at now: an
// accepted bundle, policy or directory version changed, 24 hours passed,
// or its time lies more than BackoffMax ahead (a backward clock step).
func StickyReleased(s *StickyHold, now, bundle, policy, dir uint64) bool {
	return s == nil || s.Bundle != bundle || s.Policy != policy || s.Directory != dir ||
		now >= s.At+StickyRelease || s.At > now+BackoffMax
}

// BackoffActive reports whether a NextAt still defers a request at now; a
// NextAt more than BackoffMax ahead counts as released.
func BackoffActive(nextAt, now uint64) bool { return nextAt > now && nextAt <= now+BackoffMax }

// Due returns why key k with installed certificate c (nil: none) needs a
// new certificate, "" when it does not: missing (none, or within
// min(60, V/6) of ValidBefore), principals_differ, revoked (by the KRL in
// force), or renew (at or after the entry's RenewAt).
func Due(now uint64, e *Entry, c *ssh.Certificate, principals []string, k *krl.Parsed) string {
	switch {
	case c == nil || e == nil:
		return "missing"
	case now+MissingMargin(Lifetime(c)) >= c.ValidBefore:
		return "missing"
	case !samePrincipals(c.ValidPrincipals, principals):
		return "principals_differ"
	case Revoked(k, c):
		return "revoked"
	case now >= e.RenewAt:
		return "renew"
	}
	return ""
}

// Decide is the pure decision of one host-certificate step. A host-level
// hold yields one Hold and nothing else. Otherwise, for each served key the
// entry lists (Ed25519 and ECDSA only): Defer when its certificate
// algorithm is not offered, Keep when its certificate is not due, and,
// when it is due, Defer while a request is pending, the back-off runs or a
// sticky refusal holds, else Request. Every committed key the entry no
// longer lists, or sshd no longer serves, is Removed. Renewal is lazy
// across a CA rotation: a certificate of a CA key that is still trusted is
// kept until it is due (X10).
func Decide(in Input) []Action {
	if code, nothing := HostHold(in); code != "" {
		return []Action{{Kind: Hold, Code: code, WriteNothing: nothing}}
	}
	now := uint64(max(in.Now.Unix(), 0))
	attempts := in.Attempts
	if attempts == nil {
		attempts = &Attempts{Version: AttemptsVersion}
	}
	var out []Action
	listed := map[string]bool{}
	for _, pub := range in.Served {
		alg := CertAlgorithm(pub)
		if alg == "" || !slices.Contains(in.Entry.Keys, trust.FormatKey(pub)) {
			continue
		}
		k := KeySHA256(pub)
		if listed[k] {
			continue
		}
		listed[k] = true
		if in.HostKeyAlgorithms != nil && !slices.Contains(in.HostKeyAlgorithms, alg) {
			out = append(out, Action{Kind: Defer, Key: k, Pub: pub, Code: DeferAlgorithmDisabled})
			continue
		}
		why := Due(now, Find(in.Committed, k), in.Installed[k], in.Entry.Principals, in.KRL)
		if why == "" {
			out = append(out, Action{Kind: Keep, Key: k, Pub: pub})
			continue
		}
		a := attempts.Lookup(k)
		switch {
		case a != nil && a.Pending(now) != nil:
			out = append(out, Action{Kind: Defer, Key: k, Pub: pub, Code: DeferPending})
		case a != nil && a.Sticky != nil && !StickyReleased(a.Sticky, now, in.Bundle, in.Policy, in.Directory):
			out = append(out, Action{Kind: Defer, Key: k, Pub: pub, Code: DeferRefusedPrefix + a.Sticky.Code})
		case a != nil && BackoffActive(a.NextAt, now):
			out = append(out, Action{Kind: Defer, Key: k, Pub: pub, Code: DeferBackoff})
		default:
			out = append(out, Action{Kind: Request, Key: k, Pub: pub, Code: why})
		}
	}
	for _, e := range in.Committed {
		if !listed[e.KeySHA256] {
			out = append(out, Action{Kind: Remove, Key: e.KeySHA256})
		}
	}
	return out
}

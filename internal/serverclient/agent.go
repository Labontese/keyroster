package serverclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/heartbeat"
)

// The agent routes (03-07, AGENT-02). keyroster-server serves them only on
// its agent listener (--agent-listen), which requires a client
// certificate; the browser listener registers none of them. The set is
// closed: enroll, state, heartbeat and identity (03-08). No route carries
// a command, script, path or template.
const (
	// AgentEnrollPath (POST): the one-time enrollment with the join
	// token and the host keys' proof of possession (AgentEnrollRequest);
	// 202 AgentEnrollAnswer.
	AgentEnrollPath = "/api/v1/agent/enroll"
	// AgentStatePath (GET): the signed state newer than the versions in
	// the query (AgentVersions.Query); 200 AgentStateResponse.
	AgentStatePath = "/api/v1/agent/state"
	// AgentHeartbeatPath (POST): the applier's status with the fetcher's
	// clock offset (heartbeat.Heartbeat, at most heartbeat.MaxBody bytes);
	// 200 HeartbeatAnswer (03-08, AGENT-07).
	AgentHeartbeatPath = "/api/v1/agent/heartbeat"
	// AgentIdentityPath (POST): rotate the agent's TLS identity
	// (AgentIdentityRequest), authenticated by the current identity over
	// mTLS; 200 (03-08, AGENT-02).
	AgentIdentityPath = "/api/v1/agent/identity"
)

// AgentIdentityDomain is the domain the old identity key signs a new
// identity's SPKI under: the signed message is the domain, one zero byte
// and the new SPKI's DER bytes.
const AgentIdentityDomain = "keyroster/agent-identity/v1"

// AgentIdentityMessage is the message the old identity key signs for a
// rotation to newSPKI.
func AgentIdentityMessage(newSPKI []byte) []byte {
	return append(append([]byte(AgentIdentityDomain), 0), newSPKI...)
}

// AgentIdentityRequest is the body of a POST to AgentIdentityPath: the new
// identity's SubjectPublicKeyInfo (DER, an Ed25519 key) and the old
// identity key's Ed25519 signature over AgentIdentityMessage(NewSPKI).
// Both are standard base64 in JSON.
type AgentIdentityRequest struct {
	NewSPKI []byte `json:"new_spki"`
	Sig     []byte `json:"sig"`
}

// MaxAgentIdentityBody bounds an identity rotation request.
const MaxAgentIdentityBody = 4 << 10

// The admin routes of host enrollment (03-07).
const (
	// AdminJoinTokensPath (POST): mint a one-time join token
	// (JoinTokenRequest); 201 JoinTokenAnswer.
	AdminJoinTokensPath = "/api/v1/admin/join-tokens" //nolint:gosec // G101: a route, not a credential
	// AdminPendingHostsPath (GET): the enrolled agents no directory host
	// entry approves yet; 200 PendingHostsAnswer.
	AdminPendingHostsPath = "/api/v1/admin/hosts/pending"
	// AdminForgetHostPath (POST): delete the agents enrolled under a host
	// name, so their identities and host keys are free again
	// (ForgetHostRequest); 200 ForgetHostAnswer (PR #71 review D-R1).
	AdminForgetHostPath = "/api/v1/admin/hosts/forget"
	// AdminHostsStatusPath (GET): every agent the directory approved
	// once, with its newest heartbeat and the current versions; 200
	// HostsStatusAnswer (03-08, AGENT-07).
	AdminHostsStatusPath = "/api/v1/admin/hosts/status"
)

// MaxAgentStateResponse bounds one encoded state response (F12): the
// server fills a response within it, and the fetcher refuses a larger body
// before decoding (ErrStateResponseTooLarge). It is above the three
// largest single items together (a maximum KRL document, a maximum
// directory with its signatures and a maximum bundle and policy, each in
// base64), so the current-only answer always fits.
const MaxAgentStateResponse = 8 << 20

// MaxAgentStatePerKind is the most bundle and the most directory versions
// one state response carries.
const MaxAgentStatePerKind = 16

// MaxAgentStateRounds bounds the state requests of one fetcher poll while
// the server answers more: true. The server's per-identity burst for
// enrolled agents is at least this, so a host catching up is never
// refused inside one poll (PR #71 review F4).
const MaxAgentStateRounds = 64

// MaxJoinTokenTTLSeconds is the longest join token lifetime the server
// mints (1 h), and DefaultJoinTokenTTLSeconds the one it uses when the
// request names none (30 min).
const (
	MaxJoinTokenTTLSeconds     = 3600
	DefaultJoinTokenTTLSeconds = 1800
)

// The refusals of the agent and host enrollment routes. Each is the exact
// error text of the JSON body.
const (
	AgentErrUnknown          = "unknown_agent"
	AgentErrNotApproved      = "not_approved"
	AgentErrHostPoPNotEnable = "host_pop_not_enabled"
	AgentErrTokenUnknown     = "token_unknown" //nolint:gosec // G101: a refusal code, not a credential
	AgentErrTokenUsed        = "token_used"    //nolint:gosec // G101: a refusal code, not a credential
	AgentErrTokenExpired     = "token_expired" //nolint:gosec // G101: a refusal code, not a credential
	AgentErrHostKeysInUse    = "host_keys_in_use"
	AgentErrIdentityInUse    = "identity_in_use"
	AgentErrPoPInvalid       = "enroll_pop_invalid"
	AgentErrMalformed        = "malformed request"
	AdminErrNoAgentListener  = "no_agent_listener"
	AdminErrTTL              = "ttl_above_hour"
	AdminErrHostNotEnrolled  = "host_not_enrolled"
	AdminErrHostInDirectory  = "host_in_directory"
	// AdminErrRemovalNotApplied refuses keyroster host forget while the
	// host's newest heartbeat does not show a committed directory version
	// at or above the one that removed its entry (03-08, owner decision
	// 2026-10-28); --host-gone overrides it.
	AdminErrRemovalNotApplied = "host_removal_not_applied"
	// AgentErrStaleHeartbeat is a heartbeat whose seq is not above the
	// stored one (409); the fetcher treats it as quiet.
	AgentErrStaleHeartbeat = "stale_heartbeat"
	// AgentErrHeartbeatField is a heartbeat field outside its rule (400);
	// the answer's field names it.
	AgentErrHeartbeatField = "heartbeat_field_invalid"
	// AgentErrHeartbeatSeqFuture is a heartbeat whose seq is more than
	// heartbeat.MaxSeqAhead beyond the server's clock (400): it stores
	// nothing but the clock offset (owner decision D-R2, PR #72 review).
	AgentErrHeartbeatSeqFuture = "heartbeat_seq_future"
	// AgentErrRotationTooSoon is a rotation within an hour of the row's
	// last one (429 with Retry-After; PR #72 review C10, C15).
	AgentErrRotationTooSoon = "identity_rotation_too_soon"
	// AgentErrIdentitySig is a rotation whose signature does not verify
	// under the current identity, or whose new SPKI is not an Ed25519
	// key other than the current one (403).
	AgentErrIdentitySig = "identity_rotation_invalid"
)

// HeartbeatAnswer is the 200 answer of AgentHeartbeatPath: the seq the
// server stored.
type HeartbeatAnswer struct {
	Seq uint64 `json:"seq"`
}

// HeartbeatRefusal is the 400 answer of AgentHeartbeatPath: the refusal
// and the field that broke its rule.
type HeartbeatRefusal struct {
	Error string `json:"error"`
	Field string `json:"field"`
}

// ErrStateResponseTooLarge is a state response above
// MaxAgentStateResponse, refused before decoding (F12).
var ErrStateResponseTooLarge = errors.New("state_response_too_large")

// ErrChainOutOfOrder is a state response whose bundles or directories are
// not in strictly ascending version order, or whose items are incomplete:
// nothing of it is written.
var ErrChainOutOfOrder = errors.New("chain_out_of_order")

// JoinTokenRequest is the body of a POST to AdminJoinTokensPath.
// TTLSeconds 0 is DefaultJoinTokenTTLSeconds; above
// MaxJoinTokenTTLSeconds is refused.
type JoinTokenRequest struct {
	ExpectedName string `json:"expected_name"`
	TTLSeconds   int64  `json:"ttl_seconds"`
}

// JoinTokenAnswer is its 201 answer: the token (unpadded base64url of 32
// random bytes; the server keeps only its SHA-256), its expiry (RFC 3339
// UTC, whole seconds) and the TCP port of the agent listener, on the
// server's host name the CLI already pins.
type JoinTokenAnswer struct {
	ExpectedName string `json:"expected_name"`
	Token        string `json:"token"`
	ExpiresAt    string `json:"expires_at"`
	AgentPort    int    `json:"agent_port"`
}

// PendingHostsAnswer is the 200 answer of AdminPendingHostsPath: Hosts
// wait for an approval; Served were approved once and are no longer
// approved by the directory (removed, disabled, or their entry's keys
// changed), and keep getting signed state until keyroster host forget
// (PR #71 review D-R1). A served host never waits for approval, so host
// approve never picks one (03-08 carry-over a).
type PendingHostsAnswer struct {
	Hosts  []PendingHost `json:"hosts"`
	Served []ServedHost  `json:"served"`
}

// The directory states of a served host (ServedHost.State,
// HostStatusRow.State), and of an approved one.
const (
	HostStateActive      = "active"
	HostStateRemoved     = "removed"
	HostStateDisabled    = "disabled"
	HostStateKeysChanged = "keys_changed"
)

// ServedHost is an agent approved once that the directory no longer
// approves, with why (HostStateRemoved, HostStateDisabled or
// HostStateKeysChanged).
type ServedHost struct {
	PendingHost
	State string `json:"state"`
}

// PendingHost is one enrolled agent that no active directory host entry
// with exactly its host keys approves. IdentitySPKISHA256 is the lowercase
// hex SHA-256 of its TLS identity's SPKI, HostKeys its sorted host keys
// (trust.FormatKey), EnrolledAt RFC 3339. Everything here is the server's
// and the host's word; the CLI re-derives every fingerprint it prints.
type PendingHost struct {
	ExpectedName       string       `json:"expected_name"`
	IdentitySPKISHA256 string       `json:"identity_spki_sha256"`
	HostKeys           []string     `json:"host_keys"`
	Facts              enroll.Facts `json:"facts"`
	EnrolledAt         string       `json:"enrolled_at"`
}

// ForgetHostRequest is the body of a POST to AdminForgetHostPath: the host
// name the agents were enrolled under. HostGone overrides
// host_removal_not_applied for a host that will never report again; the
// server logs it and the CLI prints it.
type ForgetHostRequest struct {
	ExpectedName string `json:"expected_name"`
	HostGone     bool   `json:"host_gone,omitempty"`
}

// ForgetHostAnswer is its 200 answer: every agent the server deleted, as
// PendingHost (the CLI re-derives every fingerprint it prints).
type ForgetHostAnswer struct {
	Forgotten []PendingHost `json:"forgotten"`
}

// AgentEnrollRequest is the body of a POST to AgentEnrollPath: the join
// token (unpadded base64url), the host keys the proof covers, one armored
// SSHSIG per host key in the same order (standard base64 in JSON) and the
// facts. The server rebuilds the enroll.PoP from these, the token's hash,
// the TLS identity and its installation ID, and verifies every signature.
type AgentEnrollRequest struct {
	Token    string       `json:"token"`
	HostKeys []string     `json:"host_keys"`
	Sigs     [][]byte     `json:"sigs"`
	Facts    enroll.Facts `json:"facts"`
}

// AgentEnrollAnswer is the 202 answer of AgentEnrollPath: the agent is
// pending until an admin approves it.
type AgentEnrollAnswer struct {
	ExpectedName string `json:"expected_name"`
	Status       string `json:"status"`
}

// AgentVersions are the versions an agent holds, by kind; 0 is none.
type AgentVersions struct {
	Bundle, Directory, KRL uint64
}

// Query is v as the query string of a state request: "?" and the kinds
// with a version, or "" for none.
func (v AgentVersions) Query() string {
	q := url.Values{}
	for _, kv := range []struct {
		name string
		v    uint64
	}{{"bundle", v.Bundle}, {"directory", v.Directory}, {"krl", v.KRL}} {
		if kv.v != 0 {
			q.Set(kv.name, strconv.FormatUint(kv.v, 10))
		}
	}
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}

// AgentStateResponse is the 200 answer of AgentStatePath: every bundle
// and directory above the agent's versions, each kind in strictly
// ascending order and at most MaxAgentStatePerKind of each, and the KRL
// when it is newer, filled in that order within the server's byte budget.
// More is set when the server left something out; the fetcher then asks
// again at once with its new versions. Byte slices are standard base64 in
// JSON. Nothing here is trusted until the applier verified it.
type AgentStateResponse struct {
	Bundles     []AgentBundle    `json:"bundles"`
	Directories []AgentDirectory `json:"directories"`
	KRL         *AgentKRL        `json:"krl"`
	More        bool             `json:"more"`
}

// AgentBundle is one trust bundle version with its policy.
type AgentBundle struct {
	Version       uint64 `json:"version"`
	Bundle        []byte `json:"bundle"`
	BundleSigs    []byte `json:"bundle_sigs"`
	PolicyVersion uint64 `json:"policy_version"`
	Policy        []byte `json:"policy"`
	PolicySigs    []byte `json:"policy_sigs"`
}

// AgentDirectory is one directory version with its admin signatures.
type AgentDirectory struct {
	Version   uint64 `json:"version"`
	Directory []byte `json:"directory"`
	Sigs      []byte `json:"sigs"`
}

// AgentKRL is the published KRL with its manifest and the ops key's
// signature.
type AgentKRL struct {
	Version  uint64 `json:"version"`
	KRL      []byte `json:"krl"`
	Manifest []byte `json:"manifest"`
	Sig      []byte `json:"sig"`
}

// Check refuses a response the fetcher must not write: a version of 0, a
// bundle or directory list that is not strictly ascending (a repeat
// included), or an item without its documents (ErrChainOutOfOrder).
func (r *AgentStateResponse) Check() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrChainOutOfOrder}, args...)...)
	}
	var last uint64
	for _, b := range r.Bundles {
		if b.Version == 0 || b.Version <= last {
			return bad("bundle version %d after %d", b.Version, last)
		}
		if len(b.Bundle) == 0 || len(b.BundleSigs) == 0 || b.PolicyVersion == 0 || len(b.Policy) == 0 || len(b.PolicySigs) == 0 {
			return bad("bundle version %d is incomplete", b.Version)
		}
		last = b.Version
	}
	last = 0
	for _, d := range r.Directories {
		if d.Version == 0 || d.Version <= last {
			return bad("directory version %d after %d", d.Version, last)
		}
		if len(d.Directory) == 0 || len(d.Sigs) == 0 {
			return bad("directory version %d is incomplete", d.Version)
		}
		last = d.Version
	}
	if k := r.KRL; k != nil && (k.Version == 0 || len(k.KRL) == 0 || len(k.Manifest) == 0 || len(k.Sig) == 0) {
		return bad("the KRL item is incomplete")
	}
	return nil
}

// CheckSince is Check, and refuses an answer that does not follow on from
// since, the versions the request named (PR #71 review F3/F7):
//   - with since 0 for a kind, at most one item of it (the current one);
//     otherwise its items must be since+1, since+2, ... with no gap;
//   - a KRL at or below since.KRL, or whose manifest's krl_version is not
//     the item's version.
//
// The fetcher cannot verify any signature, so this only keeps a server's
// answer from naming spool files that no later honest answer replaces.
func (r *AgentStateResponse) CheckSince(since AgentVersions) error {
	if err := r.Check(); err != nil {
		return err
	}
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrChainOutOfOrder}, args...)...)
	}
	follows := func(kind string, vs []uint64, from uint64) error {
		if from == 0 {
			if len(vs) > 1 {
				return bad("%d %s versions for a request that named none", len(vs), kind)
			}
			return nil
		}
		for i, v := range vs {
			if v != from+uint64(i)+1 { //nolint:gosec // G115: i is a slice index
				return bad("%s version %d does not follow version %d", kind, v, from+uint64(i)) //nolint:gosec // G115: i is a slice index
			}
		}
		return nil
	}
	var bs, ds []uint64
	for _, b := range r.Bundles {
		bs = append(bs, b.Version)
	}
	for _, d := range r.Directories {
		ds = append(ds, d.Version)
	}
	if err := follows("bundle", bs, since.Bundle); err != nil {
		return err
	}
	if err := follows("directory", ds, since.Directory); err != nil {
		return err
	}
	if k := r.KRL; k != nil {
		if k.Version <= since.KRL {
			return bad("KRL version %d, at or below the requested %d", k.Version, since.KRL)
		}
		var m struct {
			KRLVersion uint64 `json:"krl_version"`
		}
		if err := json.Unmarshal(k.Manifest, &m); err != nil || m.KRLVersion != k.Version {
			return bad("the KRL item's version %d is not its manifest's krl_version", k.Version)
		}
	}
	return nil
}

// AgentEnroll POSTs the enrollment. A refusal is an *HTTPError whose
// APIErrorIs names the code (AgentErr...).
func (c *Client) AgentEnroll(ctx context.Context, req *AgentEnrollRequest) (*AgentEnrollAnswer, error) {
	var ans AgentEnrollAnswer
	if err := c.PostJSON(ctx, AgentEnrollPath, req, &ans); err != nil {
		return nil, err
	}
	return &ans, nil
}

// AgentState GETs the state newer than v. The body is read under
// MaxAgentStateResponse, not the 4 MiB of every other route, and a larger
// one is ErrStateResponseTooLarge before anything is decoded (F12). The
// decoded response must pass CheckSince against v. A refusal is an *HTTPError
// (AgentErrNotApproved while the host waits for its approval).
func (c *Client) AgentState(ctx context.Context, v AgentVersions) (*AgentStateResponse, error) {
	r, _, err := c.AgentStateAt(ctx, v)
	return r, err
}

// SilentAfterS is how long the server waits after an agent's last
// authenticated request before it flags the host silent: a host last seen
// exactly 180 s ago is not silent, one 181 s ago is (D-10).
const SilentAfterS = 180

// HostsStatusAnswer is the 200 answer of AdminHostsStatusPath: the
// server's current bundle, directory and KRL versions, and one row per
// agent the directory approved once. It is the server's word; the host's
// own proof is keyroster-agent check there.
type HostsStatusAnswer struct {
	Current HostVersions    `json:"current"`
	Hosts   []HostStatusRow `json:"hosts"`
}

// HostVersions are the server's current versions (0: none).
type HostVersions struct {
	Bundle    uint64 `json:"bundle"`
	Directory uint64 `json:"directory"`
	KRL       uint64 `json:"krl"`
}

// HostStatusRow is one host in AdminHostsStatusPath's answer:
//   - Name is the directory entry's name (ExpectedName, the name the join
//     token named, when no entry holds the agent's keys);
//   - State is HostStateActive, or why the directory no longer approves it
//     (removed, disabled, keys_changed: served until keyroster host
//     forget);
//   - LastSeen is the agent's last authenticated request (RFC 3339), and
//     Silent is set when it is more than SilentAfterS seconds old on the
//     server's clock (or the agent was never seen);
//   - ReceivedAt is when the stored heartbeat arrived ("" for none), and
//     Heartbeat the newest heartbeat by seq (nil for none), every field
//     validated before it was stored;
//   - ClockOffsetS is the clock offset of the agent's newest heartbeat
//     that parsed, stored or refused (owner decision D-R2), and ClockSkew
//     |ClockOffsetS| > heartbeat.ClockSkewS; NeverApplied is no heartbeat
//     or generation 0;
//   - IdentityRotatedAt is when the agent's identity last rotated (RFC
//     3339, "" for never) and IdentityRotations how often it has (owner
//     decision D-R1): host status shows a rotation of the last 7 days;
//   - SeqRegressed is set while the host is not silent and its heartbeats
//     since the stored one carry a lower seq (heartbeat_seq_regressed,
//     D-R2): its status is frozen at the stored one.
type HostStatusRow struct {
	Name               string               `json:"name"`
	ExpectedName       string               `json:"expected_name"`
	IdentitySPKISHA256 string               `json:"identity_spki_sha256"`
	State              string               `json:"state"`
	LastSeen           string               `json:"last_seen"`
	Silent             bool                 `json:"silent"`
	ReceivedAt         string               `json:"received_at"`
	ClockOffsetS       int64                `json:"clock_offset_s"`
	ClockSkew          bool                 `json:"clock_skew"`
	SeqRegressed       bool                 `json:"seq_regressed"`
	IdentityRotatedAt  string               `json:"identity_rotated_at"`
	IdentityRotations  int64                `json:"identity_rotations"`
	NeverApplied       bool                 `json:"never_applied"`
	Heartbeat          *heartbeat.Heartbeat `json:"heartbeat"`
}

// AgentStateAt is AgentState that also returns the response's Date header
// (the zero time when it is missing or does not parse), from which the
// fetcher measures its clock offset.
func (c *Client) AgentStateAt(ctx context.Context, v AgentVersions) (*AgentStateResponse, time.Time, error) {
	var (
		r    AgentStateResponse
		date time.Time
	)
	err := c.sendHeader(ctx, http.MethodGet, AgentStatePath+v.Query(), nil, &r, nil, MaxAgentStateResponse, func(h http.Header) {
		if d, perr := http.ParseTime(h.Get("Date")); perr == nil {
			date = d
		}
	})
	if errors.Is(err, ErrResponseTooLarge) {
		return nil, date, fmt.Errorf("%w: %w", ErrStateResponseTooLarge, err)
	}
	if err != nil {
		return nil, date, err
	}
	if err := r.CheckSince(v); err != nil {
		return nil, date, err
	}
	return &r, date, nil
}

// AgentHeartbeat POSTs one heartbeat body (canonical JSON of
// heartbeat.Heartbeat). A refusal is an *HTTPError: 409
// AgentErrStaleHeartbeat for a seq the server holds already, 400
// AgentErrHeartbeatField for a field outside its rule.
func (c *Client) AgentHeartbeat(ctx context.Context, body []byte) error {
	return c.send(ctx, http.MethodPost, AgentHeartbeatPath, body, nil, nil, maxResponse)
}

// AgentRotateIdentity POSTs an identity rotation with the client's
// current certificate. A refusal is an *HTTPError.
func (c *Client) AgentRotateIdentity(ctx context.Context, req *AgentIdentityRequest) error {
	return c.PostJSON(ctx, AgentIdentityPath, req, nil)
}

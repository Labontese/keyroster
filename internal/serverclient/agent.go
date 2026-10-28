package serverclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Labontese/keyroster/internal/agent/enroll"
)

// The agent routes (03-07, AGENT-02). keyroster-server serves them only on
// its agent listener (--agent-listen), which requires a client
// certificate; the browser listener registers none of them. The set is
// closed: enroll and state. No route carries a command, script, path or
// template.
const (
	// AgentEnrollPath (POST): the one-time enrollment with the join
	// token and the host keys' proof of possession (AgentEnrollRequest);
	// 202 AgentEnrollAnswer.
	AgentEnrollPath = "/api/v1/agent/enroll"
	// AgentStatePath (GET): the signed state newer than the versions in
	// the query (AgentVersions.Query); 200 AgentStateResponse.
	AgentStatePath = "/api/v1/agent/state"
)

// The admin routes of host enrollment (03-07).
const (
	// AdminJoinTokensPath (POST): mint a one-time join token
	// (JoinTokenRequest); 201 JoinTokenAnswer.
	AdminJoinTokensPath = "/api/v1/admin/join-tokens" //nolint:gosec // G101: a route, not a credential
	// AdminPendingHostsPath (GET): the enrolled agents no directory host
	// entry approves yet; 200 PendingHostsAnswer.
	AdminPendingHostsPath = "/api/v1/admin/hosts/pending"
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
)

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

// PendingHostsAnswer is the 200 answer of AdminPendingHostsPath.
type PendingHostsAnswer struct {
	Hosts []PendingHost `json:"hosts"`
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
// decoded response must pass Check. A refusal is an *HTTPError
// (AgentErrNotApproved while the host waits for its approval).
func (c *Client) AgentState(ctx context.Context, v AgentVersions) (*AgentStateResponse, error) {
	var r AgentStateResponse
	err := c.send(ctx, http.MethodGet, AgentStatePath+v.Query(), nil, &r, nil, MaxAgentStateResponse)
	if errors.Is(err, ErrResponseTooLarge) {
		return nil, fmt.Errorf("%w: %w", ErrStateResponseTooLarge, err)
	}
	if err != nil {
		return nil, err
	}
	if err := r.Check(); err != nil {
		return nil, err
	}
	return &r, nil
}

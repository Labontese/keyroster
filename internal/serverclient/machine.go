package serverclient

import "context"

// The machine renew route (03-11b, D-15). An automation host renews its
// machine certificate by proof of possession of its own key: it signs a
// wire.MachineIssueRequest locally and posts it to MachineRenewPath on the
// main listener, anonymously. The server checks only the request's form and
// relays it; the signer alone decides, from the admin-signed directory.
const (
	// MachineRenewPath (POST): a machine certificate request
	// (MachineRenewRequest, at most MaxMachineRenewBody bytes), relayed to
	// the signer; 200 MachineRenewAnswer. Unauthenticated, rate limited
	// per client address.
	MachineRenewPath = "/api/v1/machine/renew"
	// MaxMachineRenewBody bounds a renew request. It is below the wire
	// maximum of a request on purpose: a real one is under 2 KiB.
	MaxMachineRenewBody = 16 << 10
)

// The route's own error details (APIError.Error). A refusal the signer
// gives with a detail that reveals nothing about an entry, or only after
// the proof of possession, keeps the signer's detail.
const (
	// MachineErrNotAuthenticated is every other refusal by the signer
	// (403): the machine is not listed, its key does not match, or its
	// proof of possession does not verify, and the answer does not say
	// which (T-03-397).
	MachineErrNotAuthenticated = "machine_not_authenticated"
	// MachineErrPoPNotEnabled is the installed policy without pop.machines
	// (403); the server then calls no signer.
	MachineErrPoPNotEnabled = "machine_pop_not_enabled"
	// MachineErrSignerTooOld is a signer that does not know the machine
	// request (403): upgrade the signer.
	MachineErrSignerTooOld = AgentErrSignerTooOld
	// MachineErrMalformed is a body that is not the strict JSON of
	// MachineRenewRequest, or a request that does not parse (400).
	MachineErrMalformed = "malformed_request"
)

// MachineRenewRequest is the body of a POST to MachineRenewPath: the
// wire.MachineIssueRequest bytes (its Marshal), standard base64 in JSON.
type MachineRenewRequest struct {
	Request []byte `json:"request"`
}

// MachineRenewAnswer is the 200 answer of MachineRenewPath: the issued
// machine certificate in SSH wire format.
type MachineRenewAnswer struct {
	Certificate []byte `json:"certificate"`
}

// MachineRenew POSTs a machine certificate request and returns the
// answer. A refusal is an *HTTPError, whose Detail is the server's error
// text; a 503 is ErrSignerUnavailable.
func (c *Client) MachineRenew(ctx context.Context, req *MachineRenewRequest) (*MachineRenewAnswer, error) {
	var a MachineRenewAnswer
	if err := c.PostJSON(ctx, MachineRenewPath, req, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

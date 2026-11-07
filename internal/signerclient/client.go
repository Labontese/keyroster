// Package signerclient sends requests to keyroster-signer over its Unix
// socket: one connection, one request frame, one response frame.
package signerclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Labontese/keyroster/internal/wire"
)

// defaultTimeout bounds a request when ctx has no deadline. It matches the
// signer's per-connection deadline.
const defaultTimeout = 10 * time.Second

// maxAwait bounds what AwaitClose reads and discards after a response
// frame. The signer writes nothing after its one frame.
const maxAwait = 64 << 10

// Client makes signer calls over the Unix socket Socket, F16 (03-08h).
// AwaitClose makes every call read on after its response frame until the
// signer closes the connection, bounded by the deadline already on the
// connection (ctx's, or for LoginSend the read deadline after the send)
// and by maxAwait bytes, and then return exactly what the frame said.
// keyroster-server sets it, so that a call returns only after the signer
// has freed the connection's slot, which the signer does before it
// closes: the server's live connections at the signer then never exceed
// its calls in flight. The CLI does not set it; the package functions are
// Client{Socket: socket} and return as soon as the frame is read.
type Client struct {
	Socket     string
	AwaitClose bool
}

// Issue sends req to the signer listening on c.Socket and returns its
// response. A refusal comes back as a *wire.ErrorResponse error.
func (c Client) Issue(ctx context.Context, req *wire.IssueRequest) (*wire.IssueResponse, error) {
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := c.roundTrip(ctx, wire.TypeIssueRequest, body, wire.TypeIssueResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseIssueResponse(respBody)
}

// Issue is Client{Socket: socket}.Issue: the call returns as soon as
// the response frame is read.
func Issue(ctx context.Context, socket string, req *wire.IssueRequest) (*wire.IssueResponse, error) {
	return Client{Socket: socket}.Issue(ctx, req)
}

// Login sends a passkey login request to the signer and returns the issued
// certificate. A refusal comes back as a *wire.ErrorResponse error.
func (c Client) Login(ctx context.Context, req *wire.LoginIssueRequest) (*wire.IssueResponse, error) {
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := c.roundTrip(ctx, wire.TypeLoginIssueRequest, body, wire.TypeIssueResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseIssueResponse(respBody)
}

// Login is Client{Socket: socket}.Login: the call returns as soon as
// the response frame is read.
func Login(ctx context.Context, socket string, req *wire.LoginIssueRequest) (*wire.IssueResponse, error) {
	return Client{Socket: socket}.Login(ctx, req)
}

// LoginSend is Login with a deadline for sending only (03-02 pre-merge
// review): ctx's deadline bounds the dial and the write of the request,
// and the answer is read for up to readTimeout after the request was
// written. A request not written by ctx's deadline is never sent; one the
// signer has taken is read to its answer although ctx's deadline passes
// meanwhile, so a certificate the signer issues and logs reaches the
// caller. A refusal comes back as a *wire.ErrorResponse error.
func (c Client) LoginSend(ctx context.Context, req *wire.LoginIssueRequest, readTimeout time.Duration) (*wire.IssueResponse, error) {
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := c.roundTripRead(ctx, wire.TypeLoginIssueRequest, body, wire.TypeIssueResponse, readTimeout)
	if err != nil {
		return nil, err
	}
	return wire.ParseIssueResponse(respBody)
}

// LoginSend is Client{Socket: socket}.LoginSend: the call returns as soon as
// the response frame is read.
func LoginSend(ctx context.Context, socket string, req *wire.LoginIssueRequest, readTimeout time.Duration) (*wire.IssueResponse, error) {
	return Client{Socket: socket}.LoginSend(ctx, req, readTimeout)
}

// HostIssue sends a host agent's host certificate request (03-09) to the
// signer and returns the issued (or re-delivered) certificate. A refusal
// comes back as a *wire.ErrorResponse error.
func (c Client) HostIssue(ctx context.Context, req *wire.HostIssueRequest) (*wire.IssueResponse, error) {
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := c.roundTrip(ctx, wire.TypeHostIssueRequest, body, wire.TypeIssueResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseIssueResponse(respBody)
}

// HostIssue is Client{Socket: socket}.HostIssue: the call returns as soon
// as the response frame is read.
func HostIssue(ctx context.Context, socket string, req *wire.HostIssueRequest) (*wire.IssueResponse, error) {
	return Client{Socket: socket}.HostIssue(ctx, req)
}

// ProbeIssue sends a host agent's probe certificate request (03-10) to the
// signer and returns the issued certificate. A refusal comes back as a
// *wire.ErrorResponse error.
func (c Client) ProbeIssue(ctx context.Context, req *wire.ProbeIssueRequest) (*wire.IssueResponse, error) {
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := c.roundTrip(ctx, wire.TypeProbeIssueRequest, body, wire.TypeIssueResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseIssueResponse(respBody)
}

// ProbeIssue is Client{Socket: socket}.ProbeIssue: the call returns as
// soon as the response frame is read.
func ProbeIssue(ctx context.Context, socket string, req *wire.ProbeIssueRequest) (*wire.IssueResponse, error) {
	return Client{Socket: socket}.ProbeIssue(ctx, req)
}

// InstallDirectory sends an admin-signed directory version to the signer
// and returns what it installed. A refusal comes back as a
// *wire.ErrorResponse error.
func (c Client) InstallDirectory(ctx context.Context, req *wire.InstallDirectoryRequest) (*wire.InstallDirectoryResponse, error) {
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := c.roundTrip(ctx, wire.TypeInstallDirectory, body, wire.TypeInstallDirectoryResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseInstallDirectoryResponse(respBody)
}

// InstallDirectory is Client{Socket: socket}.InstallDirectory: the call returns as soon as
// the response frame is read.
func InstallDirectory(ctx context.Context, socket string, req *wire.InstallDirectoryRequest) (*wire.InstallDirectoryResponse, error) {
	return Client{Socket: socket}.InstallDirectory(ctx, req)
}

// GetDirectory asks the signer for its installed directory: version (0 for
// none), canonical bytes, signatures and whether it is authorized under
// the policy in force. A refusal comes back as a *wire.ErrorResponse
// error.
func (c Client) GetDirectory(ctx context.Context) (*wire.GetDirectoryResponse, error) {
	respBody, err := c.roundTrip(ctx, wire.TypeGetDirectory, nil, wire.TypeGetDirectoryResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseGetDirectoryResponse(respBody)
}

// GetDirectory is Client{Socket: socket}.GetDirectory: the call returns as soon as
// the response frame is read.
func GetDirectory(ctx context.Context, socket string) (*wire.GetDirectoryResponse, error) {
	return Client{Socket: socket}.GetDirectory(ctx)
}

// Status asks the signer for its own report (D-18): each online key's
// algorithm, custody and fingerprint, the trust bundle and policy it runs
// on with their signatures, and the installed directory's version, hash
// and authorization. Custody shown to users comes only from here. A
// refusal (for example trust_changed after a bundle install under the
// running signer) comes back as a *wire.ErrorResponse error.
func (c Client) Status(ctx context.Context) (*wire.StatusResponse, error) {
	respBody, err := c.roundTrip(ctx, wire.TypeStatus, nil, wire.TypeStatusResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseStatusResponse(respBody)
}

// Status is Client{Socket: socket}.Status: the call returns as soon as
// the response frame is read.
func Status(ctx context.Context, socket string) (*wire.StatusResponse, error) {
	return Client{Socket: socket}.Status(ctx)
}

// Revoke sends an admin-signed revocation request to the signer and
// returns the KRL version it published and the log entries that record
// it. A refusal comes back as a *wire.ErrorResponse error.
func (c Client) Revoke(ctx context.Context, req *wire.RevokeRequest) (*wire.RevokeResponse, error) {
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := c.roundTrip(ctx, wire.TypeRevokeRequest, body, wire.TypeRevokeResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseRevokeResponse(respBody)
}

// Revoke is Client{Socket: socket}.Revoke: the call returns as soon as
// the response frame is read.
func Revoke(ctx context.Context, socket string, req *wire.RevokeRequest) (*wire.RevokeResponse, error) {
	return Client{Socket: socket}.Revoke(ctx, req)
}

// ForgetAgent sends an admin-signed forget request, with the server's own
// statement of its row (ServerApprovedOnce), to the signer and returns the
// index of the host_forget entry that records it (03-08c). A refusal comes
// back as a *wire.ErrorResponse error.
func (c Client) ForgetAgent(ctx context.Context, req *wire.ForgetRequest) (*wire.ForgetResponse, error) {
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := c.roundTrip(ctx, wire.TypeForgetAgentRequest, body, wire.TypeForgetAgentResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseForgetResponse(respBody)
}

// ForgetAgent is Client{Socket: socket}.ForgetAgent: the call returns as soon as
// the response frame is read.
func ForgetAgent(ctx context.Context, socket string, req *wire.ForgetRequest) (*wire.ForgetResponse, error) {
	return Client{Socket: socket}.ForgetAgent(ctx, req)
}

// GetKRL asks the signer for the published KRL with its manifest and the
// ops key's signature (all empty when none is published). A refusal comes
// back as a *wire.ErrorResponse error.
func (c Client) GetKRL(ctx context.Context) (*wire.GetKRLResponse, error) {
	respBody, err := c.roundTrip(ctx, wire.TypeGetKRL, nil, wire.TypeGetKRLResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseGetKRLResponse(respBody)
}

// GetKRL is Client{Socket: socket}.GetKRL: the call returns as soon as
// the response frame is read.
func GetKRL(ctx context.Context, socket string) (*wire.GetKRLResponse, error) {
	return Client{Socket: socket}.GetKRL(ctx)
}

// GetBundle asks the signer for the installed trust bundle of version v,
// with its policy and both signature files (03-07). A version never
// installed is refused not_found, as a *wire.ErrorResponse error.
func (c Client) GetBundle(ctx context.Context, v uint64) (*wire.GetBundleResponse, error) {
	body, err := (&wire.GetBundleRequest{Version: v}).Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := c.roundTrip(ctx, wire.TypeGetBundle, body, wire.TypeGetBundleResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseGetBundleResponse(respBody)
}

// GetBundle is Client{Socket: socket}.GetBundle: the call returns as soon as
// the response frame is read.
func GetBundle(ctx context.Context, socket string, v uint64) (*wire.GetBundleResponse, error) {
	return Client{Socket: socket}.GetBundle(ctx, v)
}

// GetDirectoryVersion asks the signer for the installed directory of
// version v with its signatures (03-07). A version never installed is
// refused not_found, as a *wire.ErrorResponse error.
func (c Client) GetDirectoryVersion(ctx context.Context, v uint64) (*wire.GetDirectoryVersionResponse, error) {
	body, err := (&wire.GetDirectoryVersionRequest{Version: v}).Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := c.roundTrip(ctx, wire.TypeGetDirectoryVersion, body, wire.TypeGetDirectoryVersionResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseGetDirectoryVersionResponse(respBody)
}

// GetDirectoryVersion is Client{Socket: socket}.GetDirectoryVersion: the call returns as soon as
// the response frame is read.
func GetDirectoryVersion(ctx context.Context, socket string, v uint64) (*wire.GetDirectoryVersionResponse, error) {
	return Client{Socket: socket}.GetDirectoryVersion(ctx, v)
}

// roundTrip sends one message of msgType and returns the body of the
// response, which must be of type want; an error response comes back as a
// *wire.ErrorResponse error.
func (c Client) roundTrip(ctx context.Context, msgType byte, body []byte, want byte) ([]byte, error) {
	return c.roundTripRead(ctx, msgType, body, want, 0)
}

// roundTripRead is roundTrip, except that a readTimeout above zero
// replaces ctx's deadline for the read: ctx's deadline then bounds the
// dial and the write only, and the response is read for up to readTimeout
// after the write. With AwaitClose, once a whole response frame arrived,
// whatever it said, it waits for the signer's close (awaitClose) before
// it returns; when no whole frame arrived it returns at once.
func (c Client) roundTripRead(ctx context.Context, msgType byte, body []byte, want byte, readTimeout time.Duration) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, fmt.Errorf("signerclient: connect: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			return nil, err
		}
	}
	if err := wire.WriteMessage(conn, msgType, body); err != nil {
		return nil, fmt.Errorf("signerclient: send: %w", err)
	}
	if readTimeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return nil, err
		}
	}
	return readResponse(conn, want, c.AwaitClose)
}

// awaitClose reads and discards from r until the signer closes the
// connection (EOF), the deadline already on it passes, or maxAwait bytes
// were read, F16 (03-08h). Each of those ends the wait the same way: the
// frame already read is the call's result, so an issued certificate is
// never lost to the wait.
func awaitClose(r io.Reader) {
	_, _ = io.CopyN(io.Discard, r, maxAwait)
}

// receiveError is the error for a response frame that did not arrive
// whole. It names both reasons the signer closes a connection unanswered.
func receiveError(err error) error {
	return fmt.Errorf("signerclient: receive (the signer closes connections unanswered from peers that are not on its allowlist and from accounts over its connection limits): %w", err)
}

// readResponse reads one response frame from r and returns its body, which
// must be of type want; an error response comes back as a
// *wire.ErrorResponse error. A frame of any other type is refused after its
// 6 bytes of length and header, before its body is allocated or read. With
// await, once a whole frame was read, whatever it said, it waits for the
// signer's close (awaitClose) and then returns what the frame said; when
// no whole frame arrived it returns at once.
func readResponse(r io.Reader, want byte, await bool) ([]byte, error) {
	respType, respBody, err := wire.ReadMessage(r, wire.ResponseCaps(want))
	if err != nil {
		return nil, receiveError(err)
	}
	if await {
		awaitClose(r)
	}
	return responseBody(respType, respBody)
}

// responseBody is the body of a response frame of respType: an error
// response comes back as a *wire.ErrorResponse error.
func responseBody(respType byte, respBody []byte) ([]byte, error) {
	if respType == wire.TypeError {
		e, err := wire.ParseErrorResponse(respBody)
		if err != nil {
			return nil, err
		}
		return nil, e
	}
	// ResponseCaps(want) accepts only want and TypeError: any other type
	// was refused after its header (wire.ErrUnexpectedType).
	return respBody, nil
}

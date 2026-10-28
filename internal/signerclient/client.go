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

// Issue sends req to the signer listening on socket and returns its
// response. A refusal comes back as a *wire.ErrorResponse error.
func Issue(ctx context.Context, socket string, req *wire.IssueRequest) (*wire.IssueResponse, error) {
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := roundTrip(ctx, socket, wire.TypeIssueRequest, body, wire.TypeIssueResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseIssueResponse(respBody)
}

// Login sends a passkey login request to the signer and returns the issued
// certificate. A refusal comes back as a *wire.ErrorResponse error.
func Login(ctx context.Context, socket string, req *wire.LoginIssueRequest) (*wire.IssueResponse, error) {
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := roundTrip(ctx, socket, wire.TypeLoginIssueRequest, body, wire.TypeIssueResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseIssueResponse(respBody)
}

// LoginSend is Login with a deadline for sending only (03-02 pre-merge
// review): ctx's deadline bounds the dial and the write of the request,
// and the answer is read for up to readTimeout after the request was
// written. A request not written by ctx's deadline is never sent; one the
// signer has taken is read to its answer although ctx's deadline passes
// meanwhile, so a certificate the signer issues and logs reaches the
// caller. A refusal comes back as a *wire.ErrorResponse error.
func LoginSend(ctx context.Context, socket string, req *wire.LoginIssueRequest, readTimeout time.Duration) (*wire.IssueResponse, error) {
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := roundTripRead(ctx, socket, wire.TypeLoginIssueRequest, body, wire.TypeIssueResponse, readTimeout)
	if err != nil {
		return nil, err
	}
	return wire.ParseIssueResponse(respBody)
}

// InstallDirectory sends an admin-signed directory version to the signer
// and returns what it installed. A refusal comes back as a
// *wire.ErrorResponse error.
func InstallDirectory(ctx context.Context, socket string, req *wire.InstallDirectoryRequest) (*wire.InstallDirectoryResponse, error) {
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := roundTrip(ctx, socket, wire.TypeInstallDirectory, body, wire.TypeInstallDirectoryResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseInstallDirectoryResponse(respBody)
}

// GetDirectory asks the signer for its installed directory: version (0 for
// none), canonical bytes, signatures and whether it is authorized under
// the policy in force. A refusal comes back as a *wire.ErrorResponse
// error.
func GetDirectory(ctx context.Context, socket string) (*wire.GetDirectoryResponse, error) {
	respBody, err := roundTrip(ctx, socket, wire.TypeGetDirectory, nil, wire.TypeGetDirectoryResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseGetDirectoryResponse(respBody)
}

// Status asks the signer for its own report (D-18): each online key's
// algorithm, custody and fingerprint, the trust bundle and policy it runs
// on with their signatures, and the installed directory's version, hash
// and authorization. Custody shown to users comes only from here. A
// refusal (for example trust_changed after a bundle install under the
// running signer) comes back as a *wire.ErrorResponse error.
func Status(ctx context.Context, socket string) (*wire.StatusResponse, error) {
	respBody, err := roundTrip(ctx, socket, wire.TypeStatus, nil, wire.TypeStatusResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseStatusResponse(respBody)
}

// Revoke sends an admin-signed revocation request to the signer and
// returns the KRL version it published and the log entries that record
// it. A refusal comes back as a *wire.ErrorResponse error.
func Revoke(ctx context.Context, socket string, req *wire.RevokeRequest) (*wire.RevokeResponse, error) {
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := roundTrip(ctx, socket, wire.TypeRevokeRequest, body, wire.TypeRevokeResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseRevokeResponse(respBody)
}

// GetKRL asks the signer for the published KRL with its manifest and the
// ops key's signature (all empty when none is published). A refusal comes
// back as a *wire.ErrorResponse error.
func GetKRL(ctx context.Context, socket string) (*wire.GetKRLResponse, error) {
	respBody, err := roundTrip(ctx, socket, wire.TypeGetKRL, nil, wire.TypeGetKRLResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseGetKRLResponse(respBody)
}

// GetBundle asks the signer for the installed trust bundle of version v,
// with its policy and both signature files (03-07). A version never
// installed is refused not_found, as a *wire.ErrorResponse error.
func GetBundle(ctx context.Context, socket string, v uint64) (*wire.GetBundleResponse, error) {
	body, err := (&wire.GetBundleRequest{Version: v}).Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := roundTrip(ctx, socket, wire.TypeGetBundle, body, wire.TypeGetBundleResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseGetBundleResponse(respBody)
}

// GetDirectoryVersion asks the signer for the installed directory of
// version v with its signatures (03-07). A version never installed is
// refused not_found, as a *wire.ErrorResponse error.
func GetDirectoryVersion(ctx context.Context, socket string, v uint64) (*wire.GetDirectoryVersionResponse, error) {
	body, err := (&wire.GetDirectoryVersionRequest{Version: v}).Marshal()
	if err != nil {
		return nil, err
	}
	respBody, err := roundTrip(ctx, socket, wire.TypeGetDirectoryVersion, body, wire.TypeGetDirectoryVersionResponse)
	if err != nil {
		return nil, err
	}
	return wire.ParseGetDirectoryVersionResponse(respBody)
}

// roundTrip sends one message of msgType and returns the body of the
// response, which must be of type want; an error response comes back as a
// *wire.ErrorResponse error.
func roundTrip(ctx context.Context, socket string, msgType byte, body []byte, want byte) ([]byte, error) {
	return roundTripRead(ctx, socket, msgType, body, want, 0)
}

// roundTripRead is roundTrip, except that a readTimeout above zero
// replaces ctx's deadline for the read: ctx's deadline then bounds the
// dial and the write only, and the response is read for up to readTimeout
// after the write.
func roundTripRead(ctx context.Context, socket string, msgType byte, body []byte, want byte, readTimeout time.Duration) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
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
	return readResponse(conn, want)
}

// readResponse reads one response frame from r and returns its body, which
// must be of type want; an error response comes back as a
// *wire.ErrorResponse error. A frame of any other type is refused after its
// 6 bytes of length and header, before its body is allocated or read.
func readResponse(r io.Reader, want byte) ([]byte, error) {
	respType, respBody, err := wire.ReadMessage(r, wire.ResponseCaps(want))
	if err != nil {
		return nil, fmt.Errorf("signerclient: receive (the signer closes connections from peers that are not on its allowlist): %w", err)
	}
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

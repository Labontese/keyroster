// Package signerclient sends requests to keyroster-signer over its Unix
// socket: one connection, one request frame, one response frame.
package signerclient

import (
	"context"
	"errors"
	"fmt"
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

// roundTrip sends one message of msgType and returns the body of the
// response, which must be of type want; an error response comes back as a
// *wire.ErrorResponse error.
func roundTrip(ctx context.Context, socket string, msgType byte, body []byte, want byte) ([]byte, error) {
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
	respType, respBody, err := wire.ReadMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("signerclient: receive (the signer closes connections from peers that are not on its allowlist): %w", err)
	}
	switch respType {
	case want:
		return respBody, nil
	case wire.TypeError:
		e, err := wire.ParseErrorResponse(respBody)
		if err != nil {
			return nil, err
		}
		return nil, e
	default:
		return nil, errors.New("signerclient: unexpected message type in response")
	}
}

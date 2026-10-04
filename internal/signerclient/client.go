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
	if err := wire.WriteMessage(conn, wire.TypeIssueRequest, body); err != nil {
		return nil, fmt.Errorf("signerclient: send: %w", err)
	}
	msgType, respBody, err := wire.ReadMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("signerclient: receive (the signer closes connections from peers that are not on its allowlist): %w", err)
	}
	switch msgType {
	case wire.TypeIssueResponse:
		return wire.ParseIssueResponse(respBody)
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

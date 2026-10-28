//go:build linux

package signer

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/wire"
)

// TestChain (03-07): GetBundle and GetDirectoryVersion read one installed
// version, exactly as stored, over the socket; a version never installed
// is refused not_found, and a request without a version is malformed.
func TestChain(t *testing.T) {
	e := newLoginEnv(t, newPasskeys(t), NewFixture(t, 1, 1), true, true)
	want := e.s.GetDirectory()
	e.close()
	sock, _, db, _ := serveStatusSigner(t, e)
	ctx := context.Background()
	t.Run("get_bundle", func(t *testing.T) {
		row, err := db.LatestBundle(ctx)
		if err != nil {
			t.Fatal(err)
		}
		b, err := signerclient.GetBundle(ctx, sock, row.Version)
		if err != nil {
			t.Fatal(err)
		}
		if b.Version != row.Version || !bytes.Equal(b.Bundle, row.Bundle) || !bytes.Equal(b.BundleSigs, row.BundleSigs) ||
			!bytes.Equal(b.Policy, row.Policy) || !bytes.Equal(b.PolicySigs, row.PolicySigs) {
			t.Fatalf("GetBundle(%d) is not the stored row", row.Version)
		}
	})
	t.Run("get_directory_version", func(t *testing.T) {
		d, err := signerclient.GetDirectoryVersion(ctx, sock, want.Version)
		if err != nil {
			t.Fatal(err)
		}
		if d.Version != want.Version || !bytes.Equal(d.Directory, want.Directory) || !bytes.Equal(d.Sigs, want.Sigs) {
			t.Fatalf("GetDirectoryVersion(%d) is not the installed directory", want.Version)
		}
	})
	t.Run("absent_version_not_found", func(t *testing.T) {
		for name, call := range map[string]func() error{
			"bundle":    func() error { _, err := signerclient.GetBundle(ctx, sock, 7); return err },
			"directory": func() error { _, err := signerclient.GetDirectoryVersion(ctx, sock, want.Version+1); return err },
		} {
			var er *wire.ErrorResponse
			if err := call(); !errors.As(err, &er) || er.Message != "not_found" {
				t.Errorf("%s: an absent version: %v, want not_found", name, err)
			}
		}
	})
	t.Run("version_zero_malformed", func(t *testing.T) {
		for _, typ := range []byte{wire.TypeGetBundle, wire.TypeGetDirectoryVersion} {
			for _, body := range [][]byte{{0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 1, 0}, nil} {
				conn, err := net.Dial("unix", sock)
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if err := wire.WriteMessage(conn, typ, body); err != nil {
					t.Fatal(err)
				}
				got, resp, err := wire.ReadMessage(conn, wire.ResponseCaps(typ|0x80))
				_ = conn.Close()
				if err != nil || got != wire.TypeError {
					t.Fatalf("type %#x body %x: type %#x, %v; want an error response", typ, body, got, err)
				}
				if er, err := wire.ParseErrorResponse(resp); err != nil || er.Message != "malformed_request" {
					t.Fatalf("type %#x body %x: %+v, %v; want malformed_request", typ, body, er, err)
				}
			}
		}
	})
}

//go:build linux

package signer_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// TestDirectoryOverSocket (T-02-12): through the real socket, a directory
// larger than MaxFrame installs and GetDirectory returns it byte for byte,
// because the directory messages have their own frame cap; a frame one
// byte above that cap is refused after its header, and the signer keeps
// serving (control).
func TestDirectoryOverSocket(t *testing.T) {
	ts := newTestSigner(t, signerOpts{})
	ctx := context.Background()

	d := &directory.Directory{Version: 1, Prev: trust.GenesisPrev}
	for i := range 2000 {
		d.Users = append(d.Users, directory.User{Name: fmt.Sprintf("user%04d", i), Status: directory.StatusDisabled})
	}
	d.Sort()
	doc, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if len(doc) <= wire.MaxFrame {
		t.Fatalf("the test directory has %d bytes, want more than MaxFrame (%d)", len(doc), wire.MaxFrame)
	}
	sig, err := sshsig.Sign(rand.Reader, ts.fx.Admins[0], directory.Namespace, doc)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("larger_than_max_frame_installs", func(t *testing.T) {
		resp, err := signerclient.InstallDirectory(ctx, ts.Socket, &wire.InstallDirectoryRequest{Directory: doc, Sigs: sig})
		if err != nil || resp.Version != 1 {
			t.Fatalf("install of a %d-byte directory: %+v, %v", len(doc), resp, err)
		}
		got, err := signerclient.GetDirectory(ctx, ts.Socket)
		if err != nil {
			t.Fatalf("GetDirectory of a %d-byte directory: %v", len(doc), err)
		}
		if got.Version != 1 || !bytes.Equal(got.Directory, doc) || !bytes.Equal(got.Sigs, sig) || !got.Authorized {
			t.Fatalf("GetDirectory = version %d, directory equal %v, signatures equal %v, authorized %v",
				got.Version, bytes.Equal(got.Directory, doc), bytes.Equal(got.Sigs, sig), got.Authorized)
		}
	})

	t.Run("frame_above_directory_cap_refused", func(t *testing.T) {
		conn, err := net.Dial("unix", ts.Socket)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		hdr := binary.BigEndian.AppendUint32(nil, wire.MaxDirectoryFrame+1)
		if _, err := conn.Write(append(hdr, wire.Version, wire.TypeInstallDirectory)); err != nil {
			t.Fatal(err)
		}
		typ, body, err := wire.ReadMessage(conn)
		if err != nil || typ != wire.TypeError {
			t.Fatalf("response %#x, %v; want an error response", typ, err)
		}
		e, err := wire.ParseErrorResponse(body)
		if err != nil || e.Message != "malformed_frame" {
			t.Fatalf("refusal %+v, %v; want malformed_frame", e, err)
		}
		// Control: the signer still serves, and still holds version 1.
		if got, err := signerclient.GetDirectory(ctx, ts.Socket); err != nil || got.Version != 1 {
			t.Fatalf("GetDirectory after the refused frame: %+v, %v", got, err)
		}
	})
}

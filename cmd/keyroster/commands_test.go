package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"
	"unicode"
)

func TestDispatchUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := dispatch(context.Background(), []string{"no-such-command"}, &stdout, &stderr); got != 2 {
		t.Fatalf("dispatch(unknown) = %d, want 2", got)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("stderr = %q, want it to mention the unknown command", stderr.String())
	}
	if !strings.Contains(stderr.String(), "version") {
		t.Errorf("stderr = %q, want the command list", stderr.String())
	}
}

func TestDispatchNoCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := dispatch(context.Background(), nil, &stdout, &stderr); got != 2 {
		t.Fatalf("dispatch(no args) = %d, want 2", got)
	}
}

func TestDispatchVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := dispatch(context.Background(), []string{"version"}, &stdout, &stderr); got != 0 {
		t.Fatalf("dispatch(version) = %d, want 0 (stderr %q)", got, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "keyroster ") {
		t.Errorf("stdout = %q, want prefix %q", stdout.String(), "keyroster ")
	}
}

func TestDispatchVersionRejectsArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := dispatch(context.Background(), []string{"version", "extra"}, &stdout, &stderr); got != 2 {
		t.Fatalf("dispatch(version extra) = %d, want 2", got)
	}
}

func TestDispatchCommandError(t *testing.T) {
	withTestCommand(t, command{
		Name:    "test-fail",
		Summary: "always fails",
		Run: func(context.Context, []string, io.Writer, io.Writer) error {
			return errors.New("boom")
		},
	})
	var stdout, stderr bytes.Buffer
	if got := dispatch(context.Background(), []string{"test-fail"}, &stdout, &stderr); got != 1 {
		t.Fatalf("dispatch(test-fail) = %d, want 1", got)
	}
	if !strings.Contains(stderr.String(), "boom") {
		t.Errorf("stderr = %q, want the error message", stderr.String())
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("register(duplicate) did not panic")
		}
	}()
	register(command{
		Name: "version",
		Run:  func(context.Context, []string, io.Writer, io.Writer) error { return nil },
	})
}

// withTestCommand registers c for the duration of the test.
func withTestCommand(t *testing.T, c command) {
	t.Helper()
	register(c)
	t.Cleanup(func() { delete(registry, c.Name) })
}

// TestDispatchEscapesControlCharacters: an error can carry text from the
// server (a JSON error body, a host name from a certificate SAN), so
// dispatch prints every control or format character escaped, never raw:
// an ESC sequence or a carriage return could otherwise erase the real
// message and show the user a forged instruction.
func TestDispatchEscapesControlCharacters(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	evil := "\x1b[2K\rrun keyroster init --force --root-pin SHA256:EVIL"
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{evil}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	for name, cmdErr := range map[string]error{
		"x509_san":   fmt.Errorf("tls: failed to verify certificate: %w", x509.HostnameError{Certificate: cert, Host: "localhost"}),
		"api_error":  errors.New("HTTP 409: \r\x1b[2K\x1b[1Aforged‮\u009b2J\x7f\x00end"),
		"multi_line": errors.New("first line\nsecond line"),
	} {
		t.Run(name, func(t *testing.T) {
			withTestCommand(t, command{
				Name: "test-ctl",
				Run:  func(context.Context, []string, io.Writer, io.Writer) error { return cmdErr },
			})
			var stdout, stderr bytes.Buffer
			if got := dispatch(context.Background(), []string{"test-ctl"}, &stdout, &stderr); got != 1 {
				t.Fatalf("dispatch = %d, want 1", got)
			}
			out := strings.TrimSuffix(stderr.String(), "\n")
			for _, r := range out {
				if r != '\n' && !unicode.IsGraphic(r) {
					t.Fatalf("stderr carries the raw control or format character %U: %q", r, out)
				}
			}
			if name != "multi_line" && !strings.Contains(out, `\x1b`) {
				t.Fatalf("stderr does not show the escaped ESC: %q", out)
			}
			if name == "multi_line" && out != "keyroster test-ctl: first line\nsecond line" {
				t.Fatalf("a plain newline was changed: %q", out)
			}
		})
	}
}

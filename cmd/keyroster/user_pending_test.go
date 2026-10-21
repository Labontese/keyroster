package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
)

// pendingEntry is a well-formed pending credential for a, as the server
// lists it.
func pendingEntry(t *testing.T, alg int64) (serverclient.PendingCredential, string) {
	t.Helper()
	a, err := webauthntest.New(alg)
	if err != nil {
		t.Fatal(err)
	}
	c := a.Credential()
	fp := webauthn.Fingerprint(c.SPKI)
	return serverclient.PendingCredential{
		ID: base64.RawURLEncoding.EncodeToString(c.ID), Alg: c.Alg, SPKI: base64.StdEncoding.EncodeToString(c.SPKI),
		Fingerprint: fp, BackupEligible: true, BackedUp: false, RegisteredAt: "2026-10-21T12:00:00+02:00",
	}, fp
}

// list answers 200 with entries, after checking that the request is the
// body-less signed GET of carol's pending route.
func list(t *testing.T, entries ...serverclient.PendingCredential) func(http.ResponseWriter, *http.Request, []byte) {
	return func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.Method != http.MethodGet || r.URL.Path != serverclient.AdminPendingPath("carol") || len(body) != 0 {
			t.Errorf("request %s %s with %d body bytes, want a body-less GET %s", r.Method, r.URL.Path, len(body), serverclient.AdminPendingPath("carol"))
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(append([]serverclient.PendingCredential{}, entries...))
	}
}

func TestUserPending(t *testing.T) {
	agentCustody := "user=agent, host=agent, machine=agent, ops=agent, log=agent"
	t.Run("lists_pending_with_computed_fingerprint", func(t *testing.T) {
		entry, fp := pendingEntry(t, webauthn.AlgES256)
		e := newUserAddEnv(t, agentCustody, list(t, entry))
		code, stdout, stderr := run(t, "user", "pending", "carol")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		for _, want := range []string{"Pending passkey for carol", "fingerprint  " + fp + "\n", "algorithm    ES256\n",
			"synced       no (backup eligible: yes)\n", "registered   2026-10-21T10:00:00Z\n"} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("stdout lacks %q:\n%s", want, stdout)
			}
		}
		if len(e.requests) != 1 {
			t.Fatalf("%d admin requests, want 1", len(e.requests))
		}
	})
	// KEY-06: the evaluation-only banner reaches the admin on this
	// server-talking command too, exactly once.
	t.Run("software_custody_banner_once", func(t *testing.T) {
		entry, _ := pendingEntry(t, webauthn.AlgES256)
		newUserAddEnv(t, "user=software, host=software, machine=software, ops=software, log=software", list(t, entry))
		code, _, stderr := run(t, "user", "pending", "carol")
		if code != 0 || strings.Count(stderr, custodytext.SoftwareCABanner([]string{"user", "host", "machine", "ops", "log"})) != 1 {
			t.Fatalf("exit %d, stderr:\n%s\nwant the evaluation-only banner once", code, stderr)
		}
	})
	t.Run("none_registered_yet", func(t *testing.T) {
		newUserAddEnv(t, agentCustody, list(t))
		code, stdout, stderr := run(t, "user", "pending", "carol")
		if code != 0 || !strings.Contains(stdout, "carol has an open invite but has not registered a passkey yet") {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})
	t.Run("not_pending", func(t *testing.T) {
		newUserAddEnv(t, agentCustody, answer(http.StatusNotFound, mustJSON(t, serverclient.APIError{Error: serverclient.AdminErrNotPending})))
		code, stdout, stderr := run(t, "user", "pending", "carol")
		if code != 1 || stdout != "" || !strings.Contains(stderr, "carol is not pending") {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})
	t.Run("bad_name_refused_locally", func(t *testing.T) {
		e := newUserAddEnv(t, agentCustody, list(t))
		code, _, stderr := run(t, "user", "pending", "Carol!")
		if code == 0 || e.hits != 0 {
			t.Fatalf("exit %d, %d requests, stderr %q; want a local refusal", code, e.hits, stderr)
		}
	})
}

// TestUserPendingPeerText: text the server chooses in a pending list
// never reaches the admin. Every field is validated, the fingerprint is
// computed from the SPKI and must equal the server's, and a refusal never
// repeats the server's text; the CLI's own words come last (T-02-93).
func TestUserPendingPeerText(t *testing.T) {
	agentCustody := "user=agent, host=agent, machine=agent, ops=agent, log=agent"
	good, _ := pendingEntry(t, webauthn.AlgEdDSA)
	other, otherFP := pendingEntry(t, webauthn.AlgEdDSA)
	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: the point is a too-short key
	if err != nil {
		t.Fatal(err)
	}
	smallSPKI, err := x509.MarshalPKIXPublicKey(&small.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	edit := func(f func(*serverclient.PendingCredential)) serverclient.PendingCredential {
		c := good
		f(&c)
		return c
	}
	bad := errBadPendingAnswer
	for _, tc := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request, []byte)
		advice  error
	}{
		{"forged_fingerprint_text", list(t, edit(func(c *serverclient.PendingCredential) { c.Fingerprint = paddedAdvice })), bad},
		// Another key's real fingerprint: the server cannot make the admin
		// read a fingerprint that is not the listed key's.
		{"fingerprint_of_another_key", list(t, edit(func(c *serverclient.PendingCredential) { c.Fingerprint = otherFP })), bad},
		{"spki_of_another_key_with_its_fingerprint_but_wrong_alg", list(t, edit(func(c *serverclient.PendingCredential) {
			c.SPKI, c.Fingerprint, c.Alg = other.SPKI, other.Fingerprint, webauthn.AlgES256
		})), bad},
		{"padded_spki", list(t, edit(func(c *serverclient.PendingCredential) { c.SPKI += paddedAdvice })), bad},
		{"rsa1024_spki", list(t, edit(func(c *serverclient.PendingCredential) {
			c.Alg, c.SPKI, c.Fingerprint = webauthn.AlgRS256, base64.StdEncoding.EncodeToString(smallSPKI), webauthn.Fingerprint(smallSPKI)
		})), bad},
		{"unknown_algorithm", list(t, edit(func(c *serverclient.PendingCredential) { c.Alg = -35 })), bad},
		{"padded_id", list(t, edit(func(c *serverclient.PendingCredential) { c.ID = attackerAdvice })), bad},
		{"padded_time", list(t, edit(func(c *serverclient.PendingCredential) { c.RegisteredAt = "2026-10-21T12:00:00Z" + paddedAdvice })), bad},
		{"backed_up_not_eligible", list(t, edit(func(c *serverclient.PendingCredential) { c.BackupEligible, c.BackedUp = false, true })), bad},
		{"padded_404", answer(http.StatusNotFound, mustJSON(t, serverclient.APIError{Error: paddedAdvice})), nil},
		// The test server is not at a policy origin, so the diagnosis's
		// advice is the CLI's last word (adminOriginDiagnosis).
		{"padded_401", answer(http.StatusUnauthorized, mustJSON(t, serverclient.APIError{Error: paddedAdvice})), errAdminOriginAdvice},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newUserAddEnv(t, agentCustody, tc.handler)
			code, stdout, stderr := run(t, "user", "pending", "carol")
			if code != 1 || stdout != "" {
				t.Fatalf("exit %d, stdout %q; want a refusal that prints nothing on stdout", code, stdout)
			}
			requirePeerTextContained(t, stderr, tc.advice)
			if strings.Contains(stderr, "SHA256:") {
				t.Fatalf("stderr repeats a fingerprint: %q", stderr)
			}
		})
	}
	t.Run("control_good_entry", func(t *testing.T) {
		newUserAddEnv(t, agentCustody, list(t, good))
		if code, stdout, stderr := run(t, "user", "pending", "carol"); code != 0 || !strings.Contains(stdout, good.Fingerprint) {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})
}

// TestUserAddReinviteText: user add --reinvite says that the old invite
// and any unapproved passkey registered with it no longer work, and that a
// proposal directory already written for the user must be discarded.
func TestUserAddReinviteText(t *testing.T) {
	var e *userAddEnv
	e = newUserAddEnv(t, "user=agent, host=agent, machine=agent, ops=agent, log=agent", func(w http.ResponseWriter, r *http.Request, b []byte) { e.created(w, r, b) })
	code, stdout, stderr := run(t, "user", "add", "carol", "--reinvite")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{"The previous invite for carol no longer works", "passkey carol registered with it", "(keyroster user approve --out), discard it."} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if code, stdout, _ := run(t, "user", "add", "dave"); code != 0 || strings.Contains(stdout, "previous invite") {
		t.Fatalf("a plain add (exit %d) mentions a previous invite:\n%s", code, stdout)
	}
}

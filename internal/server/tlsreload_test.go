package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// certCA issues test leaves under one P-256 root.
type certCA struct {
	root *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCertCA(t *testing.T) *certCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tlsreload test root"},
		NotBefore: t0.Add(-365 * 24 * time.Hour), NotAfter: t0.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &certCA{root: root, key: key}
}

// leafFiles is one issued leaf: its PEM files and its DER.
type leafFiles struct {
	cert, key string
	der       []byte
	notAfter  time.Time
}

// issue writes a leaf for name valid from notBefore to notAfter into dir
// as <base>.pem and <base>.key.
func (ca *certCA) issue(t *testing.T, dir, base, name string, notBefore, notAfter time.Time) leafFiles {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.root, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	lf := leafFiles{cert: filepath.Join(dir, base+".pem"), key: filepath.Join(dir, base+".key"), der: der, notAfter: notAfter}
	writeFile(t, lf.cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(t, lf.key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return lf
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // G703: a path inside the test's TempDir
		t.Fatal(err)
	}
}

// install copies src's files over the live cert and key paths and moves
// their mtime forward by step seconds, so a change is visible even on a
// coarse file-system clock.
func install(t *testing.T, live, src leafFiles, step int) {
	t.Helper()
	for _, p := range [][2]string{{src.cert, live.cert}, {src.key, live.key}} {
		data, err := os.ReadFile(p[0]) //nolint:gosec // G304: test file
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, p[1], data)
		mt := time.Now().Add(time.Duration(step) * time.Second)
		if err := os.Chtimes(p[1], mt, mt); err != nil {
			t.Fatal(err)
		}
	}
}

// holderEnv is a CertHolder on live files with an injected clock and a
// recording logger.
type holderEnv struct {
	h     *CertHolder
	ca    *certCA
	dir   string
	live  leafFiles
	clock *testClock
	log   *logBuffer
}

// newHolderEnv issues a leaf for testRPID valid 90 days from t0 as the
// live files and builds a holder on them (not yet loaded).
func newHolderEnv(t *testing.T, validFor time.Duration) *holderEnv {
	t.Helper()
	e := &holderEnv{ca: newCertCA(t), dir: t.TempDir(), clock: &testClock{now: t0}}
	e.live = e.ca.issue(t, e.dir, "live", testRPID, t0.Add(-time.Hour), t0.Add(validFor))
	logger, buf := newLogger()
	e.log = buf
	e.h = NewCertHolder(CertConfig{CertFile: e.live.cert, KeyFile: e.live.key, RPID: testRPID, Clock: e.clock.Now, Logger: logger})
	return e
}

// served returns the DER of the certificate the holder serves.
func (e *holderEnv) served(t *testing.T) []byte {
	t.Helper()
	c, err := e.h.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	return c.Certificate[0]
}

// records returns the parsed log records whose msg is msg.
func (e *holderEnv) records(t *testing.T, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range e.log.Lines() {
		var rec map[string]any
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("log line is not one JSON object: %q", l)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// requireLoaded checks the i-th "tls certificate loaded" record: level
// INFO, the leaf's fingerprint and not_after, and trigger.
func (e *holderEnv) requireLoaded(t *testing.T, i int, lf leafFiles, trigger string) {
	t.Helper()
	recs := e.records(t, "tls certificate loaded")
	if len(recs) <= i {
		t.Fatalf("%d tls certificate loaded records, want record %d:\n%s", len(recs), i, e.log.String())
	}
	sum := sha256.Sum256(lf.der)
	want := map[string]any{"level": "INFO", "fingerprint": hex.EncodeToString(sum[:]), "not_after": lf.notAfter.UTC().Format(time.RFC3339), "trigger": trigger}
	for k, v := range want {
		if recs[i][k] != v {
			t.Errorf("tls certificate loaded record %d: %s = %v, want %v", i, k, recs[i][k], v)
		}
	}
}

// waitUntil polls cond for up to 5 s.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// startWatch runs Watch until the test ends and returns its signal
// channel and a func that stops Watch and waits for it to return.
func (e *holderEnv) startWatch(t *testing.T, interval time.Duration, hup chan os.Signal) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.h.Watch(ctx, interval, hup)
		close(done)
	}()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Watch did not return after its context was cancelled")
		}
	}
	t.Cleanup(stop)
	return stop
}

func TestCertHolder(t *testing.T) {
	const days90 = 90 * 24 * time.Hour

	t.Run("swaps_new_valid", func(t *testing.T) {
		e := newHolderEnv(t, days90)
		if err := e.h.Reload("start"); err != nil {
			t.Fatal(err)
		}
		next := e.ca.issue(t, e.dir, "next", testRPID, t0.Add(-time.Hour), t0.Add(days90+time.Hour))
		install(t, e.live, next, 1)
		if err := e.h.Reload("sighup"); err != nil {
			t.Fatalf("Reload of a new valid certificate: %v", err)
		}
		if string(e.served(t)) != string(next.der) {
			t.Fatal("the holder did not swap in the new certificate")
		}
		e.requireLoaded(t, 1, next, "sighup")
	})

	refused := func(t *testing.T, name string, bad func(e *holderEnv)) {
		t.Run(name, func(t *testing.T) {
			e := newHolderEnv(t, days90)
			if err := e.h.Reload("start"); err != nil {
				t.Fatal(err)
			}
			good := e.served(t)
			bad(e)
			if err := e.h.Reload("sighup"); err == nil {
				t.Fatal("Reload accepted bad files")
			}
			if string(e.served(t)) != string(good) {
				t.Fatal("the holder dropped the last good certificate")
			}
			if n := len(e.records(t, "tls certificate loaded")); n != 1 {
				t.Fatalf("%d tls certificate loaded records, want only the start one", n)
			}
			if len(e.records(t, "tls certificate reload refused")) != 1 {
				t.Fatalf("no error record for the refused reload:\n%s", e.log.String())
			}
		})
	}
	refused(t, "keeps_last_good_on_mismatch", func(e *holderEnv) {
		other := e.ca.issue(t, e.dir, "other", testRPID, t0.Add(-time.Hour), t0.Add(days90))
		data, err := os.ReadFile(other.key) //nolint:gosec // G304: test file
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, e.live.key, data) // the live cert with another key
	})
	refused(t, "keeps_last_good_on_expired", func(e *holderEnv) {
		install(t, e.live, e.ca.issue(t, e.dir, "expired", testRPID, t0.Add(-48*time.Hour), t0.Add(-time.Hour)), 1)
	})
	refused(t, "keeps_last_good_on_wrong_host", func(e *holderEnv) {
		install(t, e.live, e.ca.issue(t, e.dir, "wrong", "other.example", t0.Add(-time.Hour), t0.Add(days90)), 1)
	})
	refused(t, "keeps_last_good_on_unreadable", func(e *holderEnv) {
		if err := os.Remove(e.live.key); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("logs_successful_load", func(t *testing.T) {
		e := newHolderEnv(t, days90)
		if err := e.h.Reload("start"); err != nil {
			t.Fatal(err)
		}
		e.requireLoaded(t, 0, e.live, "start")
		hup := make(chan os.Signal, 1)
		e.startWatch(t, 20*time.Millisecond, hup)

		next := e.ca.issue(t, e.dir, "next", testRPID, t0.Add(-time.Hour), t0.Add(days90+2*time.Hour))
		install(t, e.live, next, 2)
		waitUntil(t, "a file_change load", func() bool { return len(e.records(t, "tls certificate loaded")) == 2 })
		e.requireLoaded(t, 1, next, "file_change")

		// A SIGHUP reloads and logs although nothing changed on disk.
		hup <- syscall.SIGHUP
		waitUntil(t, "a sighup load", func() bool { return len(e.records(t, "tls certificate loaded")) == 3 })
		e.requireLoaded(t, 2, next, "sighup")

		// A refused reload writes its error and no loaded record.
		if err := os.Remove(e.live.key); err != nil {
			t.Fatal(err)
		}
		hup <- syscall.SIGHUP
		waitUntil(t, "a refused reload", func() bool { return len(e.records(t, "tls certificate reload refused")) == 1 })
		if n := len(e.records(t, "tls certificate loaded")); n != 3 {
			t.Fatalf("%d tls certificate loaded records after a refused reload, want 3", n)
		}
	})

	t.Run("reload_on_sighup", func(t *testing.T) {
		e := newHolderEnv(t, days90)
		if err := e.h.Reload("start"); err != nil {
			t.Fatal(err)
		}
		// An hour-long interval: only the signal can start this reload.
		hup := make(chan os.Signal, 1)
		e.startWatch(t, time.Hour, hup)
		next := e.ca.issue(t, e.dir, "next", testRPID, t0.Add(-time.Hour), t0.Add(days90))
		install(t, e.live, next, 1)
		hup <- syscall.SIGHUP
		waitUntil(t, "the SIGHUP reload", func() bool { return string(e.served(t)) == string(next.der) })
	})

	t.Run("watch_picks_up_file_change", func(t *testing.T) {
		e := newHolderEnv(t, days90)
		if err := e.h.Reload("start"); err != nil {
			t.Fatal(err)
		}
		e.startWatch(t, 20*time.Millisecond, make(chan os.Signal, 1))
		// Unchanged files are not reloaded.
		time.Sleep(100 * time.Millisecond)
		if n := len(e.records(t, "tls certificate loaded")); n != 1 {
			t.Fatalf("%d loads with unchanged files, want only the start one", n)
		}
		next := e.ca.issue(t, e.dir, "next", testRPID, t0.Add(-time.Hour), t0.Add(days90))
		install(t, e.live, next, 1)
		waitUntil(t, "the file_change reload", func() bool { return string(e.served(t)) == string(next.der) })
	})

	t.Run("warns_under_14_days", func(t *testing.T) {
		e := newHolderEnv(t, 10*24*time.Hour)
		if err := e.h.Reload("start"); err != nil {
			t.Fatal(err)
		}
		warns := func() []map[string]any { return e.records(t, "tls certificate expires soon") }
		if w := warns(); len(w) != 1 || w[0]["level"] != "WARN" || w[0]["not_after"] != e.live.notAfter.UTC().Format(time.RFC3339) {
			t.Fatalf("expiry warnings after the start load = %v, want one WARN with not_after:\n%s", w, e.log.String())
		}
		for _, l := range e.log.Lines() {
			if strings.Contains(l, "expires soon") && strings.Contains(l, "tls certificate loaded") {
				t.Fatalf("the expiry warning contains the loaded message: %s", l)
			}
		}
		e.clock.set(t0.Add(time.Hour))
		if err := e.h.Reload("sighup"); err != nil {
			t.Fatal(err)
		}
		if n := len(warns()); n != 1 {
			t.Fatalf("%d expiry warnings within a day, want 1", n)
		}
		// The next day the watcher's tick warns again, once.
		e.clock.set(t0.Add(25 * time.Hour))
		e.startWatch(t, 10*time.Millisecond, make(chan os.Signal, 1))
		waitUntil(t, "the next day's warning", func() bool { return len(warns()) == 2 })
		time.Sleep(60 * time.Millisecond)
		if n := len(warns()); n != 2 {
			t.Fatalf("%d expiry warnings on the second day, want 2 in total", n)
		}

		// Control: 30 days left gives no warning.
		c := newHolderEnv(t, 30*24*time.Hour)
		if err := c.h.Reload("start"); err != nil {
			t.Fatal(err)
		}
		if n := len(c.records(t, "tls certificate expires soon")); n != 0 {
			t.Fatalf("%d expiry warnings with 30 days left, want 0", n)
		}
	})

	t.Run("queued_sighup_reloads_once", func(t *testing.T) {
		e := newHolderEnv(t, days90)
		if err := e.h.Reload("start"); err != nil {
			t.Fatal(err)
		}
		// A SIGHUP that arrived during start-up waits in the buffer.
		hup := make(chan os.Signal, 1)
		hup <- syscall.SIGHUP
		stop := e.startWatch(t, time.Hour, hup)
		waitUntil(t, "the queued sighup load", func() bool {
			for _, r := range e.records(t, "tls certificate loaded") {
				if r["trigger"] == "sighup" {
					return true
				}
			}
			return false
		})
		stop()
		n := 0
		for _, l := range e.log.Lines() {
			if strings.Contains(l, `"trigger":"sighup"`) {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("%d lines with trigger sighup, want exactly 1:\n%s", n, e.log.String())
		}
	})
}

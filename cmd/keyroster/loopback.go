package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// loopbackCodePattern is the form of a login code: the unpadded base64url
// of 32 bytes.
var loopbackCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// errNotApprovedInTime ends a login whose callback did not arrive before
// the server's approval deadline.
var errNotApprovedInTime = errors.New("login not approved in time; run keyroster login again")

// loopback is keyroster login's callback listener on 127.0.0.1 (D-12,
// RESEARCH Pitfalls 4, 5 and 12). It accepts only GET /callback with Host
// exactly 127.0.0.1:<port> and the login's state, compared in constant
// time; any other request is refused and the listener keeps waiting. The
// first valid callback delivers its code once and is answered with a
// small no-store page; the listener is then closed.
type loopback struct {
	srv   *http.Server
	port  int
	host  string
	state string
	codes chan string

	mu   sync.Mutex
	done bool

	closeOnce sync.Once
}

// listenLoopback listens on 127.0.0.1 on a port the system picks and
// serves the callback for state.
func listenLoopback(state string) (*loopback, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	l := &loopback{port: port, host: "127.0.0.1:" + strconv.Itoa(port), state: state, codes: make(chan string, 1)}
	l.srv = &http.Server{Handler: http.HandlerFunc(l.handle), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = l.srv.Serve(ln) }()
	return l, nil
}

const loopbackPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>keyroster login</title></head>
<body><p>keyroster: approved, you can close this tab.</p></body></html>
`

func (l *loopback) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.URL.Path != "/callback" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Host != l.host {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	code := q.Get("code")
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(l.state)) != 1 || !loopbackCodePattern.MatchString(code) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	l.mu.Lock()
	first := !l.done
	l.done = true
	l.mu.Unlock()
	if !first {
		http.Error(w, "this login was already handed over", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(loopbackPage))
	l.codes <- code
}

// wait returns the code of the first valid callback, or fails when ctx
// ends or timeout fires first.
func (l *loopback) wait(ctx context.Context, timeout <-chan time.Time) (string, error) {
	select {
	case code := <-l.codes:
		return code, nil
	case <-timeout:
		return "", errNotApprovedInTime
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// close stops the listener; the callback answer in flight, if any, is
// given a moment to finish. It is safe to call more than once.
func (l *loopback) close() {
	l.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = l.srv.Shutdown(ctx)
	})
}

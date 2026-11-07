package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/wire"
)

// settle is how long a capacity test waits once a count was reached
// before it checks that the count did not grow.
const settle = 100 * time.Millisecond

// waitFor polls cond until it holds, failing the test after 10 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// gateSigner is TestSignerBudget's double, a fakeSigner whose every
// budgeted method waits at one shared gate, or for the end of its ctx,
// before it answers as the fake does. It counts the calls in flight and
// their peak, in all and for the agent calls (GetBundle and
// GetDirectoryVersion) alone. GetKRL, which the budget does not hold
// (Q-G5), is counted in calls only and passes the gate, so a test can see
// it reach the double and return while the gate is shut. With fail set,
// every gated method fails at once with it.
type gateSigner struct {
	*fakeSigner

	mu                       sync.Mutex
	gate                     chan struct{}
	opened                   bool
	fail                     error
	calls                    map[string]int
	inFlight, peak           int
	agentInFlight, agentPeak int
}

func newGateSigner() *gateSigner {
	f := newFakeSigner(&wire.StatusResponse{})
	f.bundles = map[uint64]*wire.GetBundleResponse{1: {Version: 1}}
	f.dirVersions = map[uint64]*wire.GetDirectoryVersionResponse{1: {Version: 1}}
	return &gateSigner{fakeSigner: f, gate: make(chan struct{}), calls: map[string]int{}}
}

// wait is the gate step of every budgeted method.
func (g *gateSigner) wait(ctx context.Context, method string) error {
	agent := method == "GetBundle" || method == "GetDirectoryVersion" || method == "HostIssue" || method == "ProbeIssue"
	g.mu.Lock()
	g.calls[method]++
	g.inFlight++
	g.peak = max(g.peak, g.inFlight)
	if agent {
		g.agentInFlight++
		g.agentPeak = max(g.agentPeak, g.agentInFlight)
	}
	gate, fail := g.gate, g.fail
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.inFlight--
		if agent {
			g.agentInFlight--
		}
		g.mu.Unlock()
	}()
	if fail != nil {
		return fail
	}
	select {
	case <-gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// open lets every call at the gate, and every later one, through.
func (g *gateSigner) open() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.opened {
		g.opened = true
		close(g.gate)
	}
}

// shut puts a new, shut gate in front of every later call.
func (g *gateSigner) shut() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gate, g.opened = make(chan struct{}), false
}

func (g *gateSigner) setFail(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fail = err
}

// gated returns how many calls of method reached the double.
func (g *gateSigner) gated(method string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls[method]
}

// load returns the calls in flight and their peak, in all and for the
// agent calls.
func (g *gateSigner) load() (inFlight, peak, agentInFlight, agentPeak int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inFlight, g.peak, g.agentInFlight, g.agentPeak
}

func (g *gateSigner) Status(ctx context.Context) (*wire.StatusResponse, error) {
	if err := g.wait(ctx, "Status"); err != nil {
		return nil, err
	}
	return g.fakeSigner.Status(ctx)
}

func (g *gateSigner) GetDirectory(ctx context.Context) (*wire.GetDirectoryResponse, error) {
	if err := g.wait(ctx, "GetDirectory"); err != nil {
		return nil, err
	}
	return g.fakeSigner.GetDirectory(ctx)
}

func (g *gateSigner) InstallDirectory(ctx context.Context, req *wire.InstallDirectoryRequest) (*wire.InstallDirectoryResponse, error) {
	if err := g.wait(ctx, "InstallDirectory"); err != nil {
		return nil, err
	}
	return g.fakeSigner.InstallDirectory(ctx, req)
}

func (g *gateSigner) Login(ctx context.Context, req *wire.LoginIssueRequest) (*wire.IssueResponse, error) {
	if err := g.wait(ctx, "Login"); err != nil {
		return nil, err
	}
	return g.fakeSigner.Login(ctx, req)
}

func (g *gateSigner) Revoke(ctx context.Context, req *wire.RevokeRequest) (*wire.RevokeResponse, error) {
	if err := g.wait(ctx, "Revoke"); err != nil {
		return nil, err
	}
	return g.fakeSigner.Revoke(ctx, req)
}

func (g *gateSigner) GetKRL(ctx context.Context) (*wire.GetKRLResponse, error) {
	g.mu.Lock()
	g.calls["GetKRL"]++
	g.mu.Unlock()
	return g.fakeSigner.GetKRL(ctx)
}

func (g *gateSigner) GetBundle(ctx context.Context, v uint64) (*wire.GetBundleResponse, error) {
	if err := g.wait(ctx, "GetBundle"); err != nil {
		return nil, err
	}
	return g.fakeSigner.GetBundle(ctx, v)
}

func (g *gateSigner) GetDirectoryVersion(ctx context.Context, v uint64) (*wire.GetDirectoryVersionResponse, error) {
	if err := g.wait(ctx, "GetDirectoryVersion"); err != nil {
		return nil, err
	}
	return g.fakeSigner.GetDirectoryVersion(ctx, v)
}

func (g *gateSigner) ForgetAgent(ctx context.Context, req *wire.ForgetRequest) (*wire.ForgetResponse, error) {
	if err := g.wait(ctx, "ForgetAgent"); err != nil {
		return nil, err
	}
	return g.fakeSigner.ForgetAgent(ctx, req)
}

func (g *gateSigner) HostIssue(ctx context.Context, req *wire.HostIssueRequest) (*wire.IssueResponse, error) {
	if err := g.wait(ctx, "HostIssue"); err != nil {
		return nil, err
	}
	return g.fakeSigner.HostIssue(ctx, req)
}

func (g *gateSigner) ProbeIssue(ctx context.Context, req *wire.ProbeIssueRequest) (*wire.IssueResponse, error) {
	if err := g.wait(ctx, "ProbeIssue"); err != nil {
		return nil, err
	}
	return g.fakeSigner.ProbeIssue(ctx, req)
}

// callSigner makes one call of method through sg.
func callSigner(ctx context.Context, sg signerAPI, method string) error {
	var err error
	switch method {
	case "Status":
		_, err = sg.Status(ctx)
	case "GetDirectory":
		_, err = sg.GetDirectory(ctx)
	case "InstallDirectory":
		_, err = sg.InstallDirectory(ctx, &wire.InstallDirectoryRequest{})
	case "Login":
		_, err = sg.Login(ctx, &wire.LoginIssueRequest{})
	case "Revoke":
		_, err = sg.Revoke(ctx, &wire.RevokeRequest{})
	case "GetKRL":
		_, err = sg.GetKRL(ctx)
	case "GetBundle":
		_, err = sg.GetBundle(ctx, 1)
	case "GetDirectoryVersion":
		_, err = sg.GetDirectoryVersion(ctx, 1)
	case "ForgetAgent":
		_, err = sg.ForgetAgent(ctx, &wire.ForgetRequest{})
	case "HostIssue":
		_, err = sg.HostIssue(ctx, &wire.HostIssueRequest{})
	case "ProbeIssue":
		_, err = sg.ProbeIssue(ctx, &wire.ProbeIssueRequest{})
	default:
		panic("callSigner: unknown method " + method)
	}
	return err
}

// goCalls starts n concurrent calls through sg, the i-th of them
// method(i), and returns the channel each sends its error on.
func goCalls(ctx context.Context, sg signerAPI, n int, method func(i int) string) <-chan error {
	errs := make(chan error, n)
	for i := range n {
		go func() { errs <- callSigner(ctx, sg, method(i)) }()
	}
	return errs
}

// collect waits for n calls of goCalls and fails the test on any error.
func collect(t *testing.T, errs <-chan error, n int) {
	t.Helper()
	for i := range n {
		select {
		case err := <-errs:
			if err != nil {
				t.Errorf("call %d of %d: %v", i+1, n, err)
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("%d of %d calls never returned", n-i, n)
		}
	}
}

func only(method string) func(int) string { return func(int) string { return method } }

func alternate(a, b string) func(int) string {
	return func(i int) string {
		if i%2 == 0 {
			return a
		}
		return b
	}
}

// TestSignerBudget pins the server's signer-call budget, F11 (03-08g), on
// withSignerBudget directly: at most maxSignerCalls calls in flight, at
// most maxAgentCalls of them relayed for host agents, which take their
// agent token before their total token, so interactive calls always find
// room; a waiter whose ctx ends takes and keeps nothing; every error path
// gives its tokens back; GetKRL is outside the budget (Q-G5).
func TestSignerBudget(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*gateSigner, signerAPI) {
		t.Helper()
		g := newGateSigner()
		t.Cleanup(g.open)
		return g, withSignerBudget(g)
	}
	// The owner's rule (Q-G1), not the constant under test: the agent share
	// is at most half the total, and the other half stays open to
	// interactive calls.
	share := maxSignerCalls / 2
	// Every budgeted method, each alone (pre-merge review fix round 1):
	// an interactive method fills the whole budget and no more; an agent
	// method fills its share and no more, so 20 of them alone peak at the
	// share, not at the total.
	t.Run("total_bounded", func(t *testing.T) {
		for _, tc := range []struct {
			method string
			agent  bool
		}{
			{"Status", false}, {"GetDirectory", false}, {"InstallDirectory", false}, {"Login", false},
			{"Revoke", false}, {"ForgetAgent", false}, {"GetBundle", true}, {"GetDirectoryVersion", true}, {"HostIssue", true},
			{"ProbeIssue", true},
		} {
			t.Run(tc.method, func(t *testing.T) {
				g, b := setup(t)
				want, wantAgent := maxSignerCalls, 0
				if tc.agent {
					want, wantAgent = share, share
				}
				errs := goCalls(ctx, b, 20, only(tc.method))
				waitFor(t, "the calls in flight", func() bool { n, _, _, _ := g.load(); return n >= want })
				time.Sleep(settle)
				if n, peak, _, agentPeak := g.load(); n != want || peak != want || agentPeak != wantAgent {
					t.Fatalf("20 calls of %s: %d in flight, peak %d, agent peak %d; want %d, %d, %d", tc.method, n, peak, agentPeak, want, want, wantAgent)
				}
				g.open()
				collect(t, errs, 20)
			})
		}
	})
	// With the agent share held, each interactive method alone fills the
	// room the share leaves, maxSignerCalls - share, and the agent calls
	// stay at their share (pre-merge review fix round 1: one method at a
	// time, so a method that queued behind the agent share, or skipped the
	// budget, cannot hide behind another).
	t.Run("catch_up_bounded_interactive_room", func(t *testing.T) {
		for _, method := range []string{"Login", "Revoke", "InstallDirectory", "ForgetAgent", "GetDirectory", "Status"} {
			t.Run(method, func(t *testing.T) {
				g, b := setup(t)
				agents := goCalls(ctx, b, 20, alternate("GetBundle", "GetDirectoryVersion"))
				waitFor(t, "the agent share in flight", func() bool { _, _, a, _ := g.load(); return a >= share })
				// The 14 queued agent calls reach their token waits before the
				// interactive calls start (plan check 1, item 5).
				time.Sleep(settle)
				interactive := goCalls(ctx, b, 20, only(method))
				waitFor(t, "the interactive room in flight", func() bool { n, _, a, _ := g.load(); return n-a >= maxSignerCalls-share })
				time.Sleep(settle)
				n, peak, a, agentPeak := g.load()
				if n-a != maxSignerCalls-share || a != share || agentPeak != share || peak != maxSignerCalls {
					t.Fatalf("%s: interactive in flight %d, agent in flight %d, agent peak %d, total peak %d; want %d, %d, %d, %d",
						method, n-a, a, agentPeak, peak, maxSignerCalls-share, share, share, maxSignerCalls)
				}
				g.open()
				collect(t, agents, 20)
				collect(t, interactive, 20)
			})
		}
	})
	t.Run("waiter_ctx_ends", func(t *testing.T) {
		g, b := setup(t)
		logins := goCalls(ctx, b, maxSignerCalls, only("Login"))
		waitFor(t, "the total in flight", func() bool { n, _, _, _ := g.load(); return n >= maxSignerCalls })
		wctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		err := callSigner(wctx, b, "Status")
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || g.gated("Status") != 0 {
			t.Fatalf("a Status whose ctx ended while it waited = %v after %d calls at the signer; want its ctx's error and none", err, g.gated("Status"))
		}
		dead, kill := context.WithCancel(ctx)
		kill()
		if err := callSigner(dead, b, "Status"); !errors.Is(err, context.Canceled) || g.gated("Status") != 0 {
			t.Fatalf("a Status with an ended ctx = %v after %d calls at the signer; want context.Canceled and none", err, g.gated("Status"))
		}
		actx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		err = callSigner(actx, b, "GetBundle")
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || g.gated("GetBundle") != 0 {
			t.Fatalf("an agent call whose ctx ended at the total wait = %v after %d calls at the signer", err, g.gated("GetBundle"))
		}
		g.open()
		collect(t, logins, maxSignerCalls)
		// With tokens free, an ended ctx still takes none and reaches
		// nothing.
		for range 50 {
			if err := callSigner(dead, b, "Status"); !errors.Is(err, context.Canceled) {
				t.Fatalf("a Status with an ended ctx and free tokens = %v", err)
			}
		}
		if n := g.gated("Status"); n != 0 {
			t.Fatalf("%d Status calls with an ended ctx reached the signer", n)
		}
		// The agent token of the call that gave up was given back: the
		// whole agent share gets in at once.
		g.shut()
		agents := goCalls(ctx, b, maxAgentCalls, only("GetBundle"))
		waitFor(t, "the whole agent share in flight", func() bool { _, _, a, _ := g.load(); return a >= maxAgentCalls })
		g.open()
		collect(t, agents, maxAgentCalls)
	})
	t.Run("tokens_released_on_error", func(t *testing.T) {
		g, b := setup(t)
		boom := errors.New("signer down")
		g.setFail(boom)
		for i := range 3 * maxSignerCalls {
			m := alternate("Login", "GetBundle")(i)
			cctx, cancel := context.WithTimeout(ctx, time.Second)
			err := callSigner(cctx, b, m)
			cancel()
			if !errors.Is(err, boom) {
				t.Fatalf("failing call %d (%s) = %v, want the signer's error (a token was kept)", i+1, m, err)
			}
		}
		g.setFail(nil)
		g.open()
		for _, m := range []string{"Login", "GetBundle"} {
			cctx, cancel := context.WithTimeout(ctx, time.Second)
			err := callSigner(cctx, b, m)
			cancel()
			if err != nil {
				t.Fatalf("%s after %d failing calls = %v", m, 3*maxSignerCalls, err)
			}
		}
	})
	t.Run("getkrl_outside_budget", func(t *testing.T) {
		g, b := setup(t)
		logins := goCalls(ctx, b, maxSignerCalls, only("Login"))
		waitFor(t, "the total in flight", func() bool { n, _, _, _ := g.load(); return n >= maxSignerCalls })
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := callSigner(cctx, b, "GetKRL")
		cancel()
		if err != nil || g.gated("GetKRL") != 1 {
			t.Fatalf("GetKRL with the total full = %v after %d calls at the signer; want nil after 1", err, g.gated("GetKRL"))
		}
		if _, peak, _, _ := g.load(); peak != maxSignerCalls {
			t.Fatalf("budgeted peak %d, want %d", peak, maxSignerCalls)
		}
		g.open()
		collect(t, logins, maxSignerCalls)
	})
}

// TestKRLDuringFullBudget pins Q-G5 on the server (F11, 03-08g): with
// every budget token held, GET /api/v1/krl still answers while the status
// cache is fresh, because GetKRL takes no token, and GetKRL stays
// coalesced to one call in flight, which the bound of maxSignerCalls + 1
// signer calls rests on. Beyond statusTTL this claims nothing (T-03-308).
func TestKRLDuringFullBudget(t *testing.T) {
	t.Run("krl_route_answers_inside_status_ttl", func(t *testing.T) {
		e := newAgentEnv(t, true)
		e.publishKRL(t, 101)
		get := func() *http.Request {
			return signedReq(t, nil, http.MethodGet, serverclient.KRLPath, serverclient.KRLPath, nil, e.clock.Now())
		}
		if rec := serve(e.s.Handler(), get()); rec.Code != http.StatusOK {
			t.Fatalf("the first GET krl = %d %s", rec.Code, rec.Body.String())
		}
		e.s.mu.Lock()
		e.s.krl = nil
		e.s.mu.Unlock()
		entered, release := e.fake.hold("Login")
		t.Cleanup(release)
		logins := goCalls(context.Background(), e.s.signer, maxSignerCalls, only("Login"))
		for i := range maxSignerCalls {
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatalf("%d of %d Logins reached the signer", i, maxSignerCalls)
			}
		}
		before := e.fake.count("GetKRL")
		req := get()
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- serve(e.s.Handler(), req) }()
		select {
		case rec := <-done:
			var doc serverclient.KRLDocument
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &doc) != nil || string(doc.KRL) != "krl version 101" {
				t.Fatalf("GET krl with the budget full = %d %s", rec.Code, rec.Body.String())
			}
		case <-time.After(2 * time.Second):
			t.Fatal("GET krl with the budget full did not answer within 2 s (GetKRL waits for a token)")
		}
		if n := e.fake.count("GetKRL") - before; n != 1 {
			t.Fatalf("%d GetKRL calls, want 1", n)
		}
		release()
		collect(t, logins, maxSignerCalls)
	})
	t.Run("getkrl_coalesced_one_call", func(t *testing.T) {
		e := newAgentEnv(t, true)
		e.s.mu.Lock()
		e.s.krl = nil
		e.s.mu.Unlock()
		before := e.fake.count("GetKRL")
		entered, release := e.fake.hold("GetKRL")
		t.Cleanup(release)
		type answer struct {
			resp *wire.GetKRLResponse
			err  error
		}
		answers := make(chan answer, 20)
		for range 20 {
			go func() {
				resp, err := e.s.currentKRL(context.Background())
				answers <- answer{resp, err}
			}()
		}
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("no GetKRL reached the signer")
		}
		time.Sleep(settle)
		if n := len(entered); n != 0 {
			t.Fatalf("%d more GetKRL calls entered the signer, want none", n)
		}
		release()
		for range 20 {
			select {
			case a := <-answers:
				if a.err != nil || a.resp == nil || string(a.resp.KRL) != "krl version 100" {
					t.Fatalf("currentKRL = %+v, %v", a.resp, a.err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("a currentKRL call never returned")
			}
		}
		if n := e.fake.count("GetKRL") - before; n != 1 {
			t.Fatalf("%d GetKRL calls for 20 concurrent reads, want 1", n)
		}
	})
}

// agentsAt enrolls n agents, web1 to webn, each with one host key, and
// installs directory versions up to top, each naming all n hosts, so every
// agent is approved and top-1 versions behind at directory 1.
func agentsAt(t *testing.T, e *agentEnv, n, top int) []agentID {
	t.Helper()
	var ids []agentID
	var hosts []directory.Host
	for i := 1; i <= n; i++ {
		name := "web" + strconv.Itoa(i)
		id, keys := newAgentID(t), hostSigners(t, 1)
		if rec := e.enroll(t, id, e.mustMint(t, name, 0).Token, keys); rec.Code != http.StatusAccepted {
			t.Fatalf("enroll %s: %d %s", name, rec.Code, rec.Body.String())
		}
		ids = append(ids, id)
		hosts = append(hosts, hostEntry(name, keys))
	}
	for len(e.dirs) < top {
		e.installDir(t, hosts...)
	}
	return ids
}

// heldStates is a set of state requests sent with GetDirectoryVersion held
// at the fake: entered counts the calls that reached it.
type heldStates struct {
	entered atomic.Int64
	answers chan *httptest.ResponseRecorder
	release func()
}

// holdStates holds GetDirectoryVersion and sends per concurrent
// GET state?directory=1 requests as each of ids.
func holdStates(t *testing.T, e *agentEnv, ids []agentID, per int) *heldStates {
	t.Helper()
	entered, release := e.fake.hold("GetDirectoryVersion")
	stop := make(chan struct{})
	t.Cleanup(func() { release(); close(stop) })
	h := &heldStates{answers: make(chan *httptest.ResponseRecorder, len(ids)*per), release: release}
	go func() {
		for {
			select {
			case <-entered:
				h.entered.Add(1)
			case <-stop:
				return
			}
		}
	}()
	for _, id := range ids {
		for range per {
			go func() { h.answers <- e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath+"?directory=1", nil) }()
		}
	}
	return h
}

// settleAt waits until want calls entered, settles, and fails the test
// when the count grew.
func (h *heldStates) settleAt(t *testing.T, want int64) {
	t.Helper()
	waitFor(t, strconv.FormatInt(want, 10)+" held signer calls", func() bool { return h.entered.Load() >= want })
	time.Sleep(settle)
	if n := h.entered.Load(); n != want {
		t.Fatalf("%d calls entered the signer, want %d", n, want)
	}
}

// quiet fails the test when any request was answered while the calls
// were held (a 429 answers at once).
func (h *heldStates) quiet(t *testing.T) {
	t.Helper()
	if n := len(h.answers); n != 0 {
		rec := <-h.answers
		t.Fatalf("%d requests were answered while the calls were held, the first %d %s", n, rec.Code, rec.Body.String())
	}
}

// answered waits for n answers and fails the test unless each is code.
func (h *heldStates) answered(t *testing.T, n, code int) []*httptest.ResponseRecorder {
	t.Helper()
	var out []*httptest.ResponseRecorder
	for i := range n {
		select {
		case rec := <-h.answers:
			if rec.Code != code {
				t.Fatalf("answer %d of %d: %d %s, want %d", i+1, n, rec.Code, rec.Body.String(), code)
			}
			out = append(out, rec)
		case <-time.After(30 * time.Second):
			t.Fatalf("%d of %d requests never answered", n-i, n)
		}
	}
	return out
}

// TestAgentInFlight pins F11 (03-08g) on the agent routes: catch-up reads
// relayed for host agents take at most the agent share of the budget, and
// leave the server's own reads room; one agent has at most
// maxAgentInFlight requests in flight on the state and heartbeat routes
// together, a further one is answered 429 with Retry-After 1, and the slot
// is freed when the request ends.
// hostCertAgent is one approved agent with its host key and name.
type hostCertAgent struct {
	id   agentID
	key  ssh.Signer
	name string
}

// hostCertAgents enrolls and approves n agents (web1..webn).
func hostCertAgents(t *testing.T, e *agentEnv, n int) []hostCertAgent {
	t.Helper()
	var out []hostCertAgent
	var hosts []directory.Host
	for i := 1; i <= n; i++ {
		name := "web" + strconv.Itoa(i)
		id, keys := newAgentID(t), hostSigners(t, 1)
		if rec := e.enroll(t, id, e.mustMint(t, name, 0).Token, keys); rec.Code != http.StatusAccepted {
			t.Fatalf("enroll %s: %d %s", name, rec.Code, rec.Body.String())
		}
		out = append(out, hostCertAgent{id: id, key: keys[0], name: name})
		hosts = append(hosts, hostEntry(name, keys))
	}
	e.installDir(t, hosts...)
	return out
}

// holdHostCerts holds HostIssue at the fake and sends per concurrent host
// certificate requests as each agent.
func holdHostCerts(t *testing.T, e *agentEnv, agents []hostCertAgent, per int) *heldStates {
	t.Helper()
	return holdAgentCerts(t, e, agents, per, "HostIssue", serverclient.AgentHostCertPath, func(a hostCertAgent) []byte {
		_, body := hostCertBody(t, a.key, a.name)
		return body
	})
}

// holdProbeCerts holds ProbeIssue at the fake and sends per concurrent
// probe certificate requests as each agent (03-10).
func holdProbeCerts(t *testing.T, e *agentEnv, agents []hostCertAgent, per int) *heldStates {
	t.Helper()
	return holdAgentCerts(t, e, agents, per, "ProbeIssue", serverclient.AgentProbeCertPath, func(a hostCertAgent) []byte {
		_, body := probeCertBody(t, a.key, a.name)
		return body
	})
}

// holdAgentCerts holds method at the fake and sends per concurrent
// requests to path as each agent, with the body bodyOf gives.
func holdAgentCerts(t *testing.T, e *agentEnv, agents []hostCertAgent, per int, method, path string, bodyOf func(hostCertAgent) []byte) *heldStates {
	t.Helper()
	entered, release := e.fake.hold(method)
	stop := make(chan struct{})
	t.Cleanup(func() { release(); close(stop) })
	h := &heldStates{answers: make(chan *httptest.ResponseRecorder, len(agents)*per), release: release}
	go func() {
		for {
			select {
			case <-entered:
				h.entered.Add(1)
			case <-stop:
				return
			}
		}
	}()
	for _, a := range agents {
		for range per {
			body := bodyOf(a)
			go func() { h.answers <- e.agentDo(t, a.id, http.MethodPost, path, body) }()
		}
	}
	return h
}

func TestAgentInFlight(t *testing.T) {
	t.Run("host_cert_route_takes_agent_slot", func(t *testing.T) {
		e := newAgentEnv(t, true)
		h := holdHostCerts(t, e, hostCertAgents(t, e, 1), 4)
		h.settleAt(t, maxAgentInFlight)
		h.answered(t, 4-maxAgentInFlight, http.StatusTooManyRequests)
		h.release()
		h.answered(t, maxAgentInFlight, http.StatusOK)
	})
	t.Run("probe_cert_route_takes_agent_slot", func(t *testing.T) {
		e := newAgentEnv(t, true)
		h := holdProbeCerts(t, e, hostCertAgents(t, e, 1), 4)
		h.settleAt(t, maxAgentInFlight)
		h.answered(t, 4-maxAgentInFlight, http.StatusTooManyRequests)
		h.release()
		h.answered(t, maxAgentInFlight, http.StatusOK)
	})
	t.Run("probe_cert_burst_leaves_interactive_half", func(t *testing.T) {
		e := newAgentEnv(t, true)
		h := holdProbeCerts(t, e, hostCertAgents(t, e, 6), 2)
		h.settleAt(t, maxAgentCalls)
		h.quiet(t)
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := e.s.signer.Status(cctx); err != nil {
			t.Fatalf("Status with the agent share held by probe certificate requests: %v", err)
		}
		h.release()
		h.answered(t, 12, http.StatusOK)
	})
	t.Run("host_cert_burst_leaves_interactive_half", func(t *testing.T) {
		e := newAgentEnv(t, true)
		h := holdHostCerts(t, e, hostCertAgents(t, e, 6), 2)
		h.settleAt(t, maxAgentCalls)
		h.quiet(t)
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := e.s.signer.Status(cctx); err != nil {
			t.Fatalf("Status with the agent share held by host certificate requests: %v", err)
		}
		h.release()
		h.answered(t, 12, http.StatusOK)
	})
	t.Run("catch_up_reads_leave_room", func(t *testing.T) {
		e := newAgentEnv(t, true)
		ids := agentsAt(t, e, 6, 18)
		h := holdStates(t, e, ids, 2)
		h.settleAt(t, maxAgentCalls)
		h.quiet(t)
		// While they are held, the server's own reads get in: Status
		// through the budget, GetKRL outside it.
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := e.s.signer.Status(cctx); err != nil {
			t.Fatalf("Status with the agent share held: %v", err)
		}
		if _, err := e.s.signer.GetKRL(cctx); err != nil {
			t.Fatalf("GetKRL with the agent share held: %v", err)
		}
		h.release()
		h.answered(t, 12, http.StatusOK)
	})
	t.Run("one_agent_bounded_in_flight", func(t *testing.T) {
		e := newAgentEnv(t, true)
		ids := agentsAt(t, e, 1, 18)
		h := holdStates(t, e, ids, 12)
		h.settleAt(t, maxAgentInFlight)
		for _, rec := range h.answered(t, 12-maxAgentInFlight, http.StatusTooManyRequests) {
			if rec.Header().Get("Retry-After") != "1" || apiError(rec) != "rate limited" {
				t.Fatalf("a refused request: Retry-After %q, %s; want 1, rate limited", rec.Header().Get("Retry-After"), rec.Body.String())
			}
		}
		h.release()
		h.answered(t, maxAgentInFlight, http.StatusOK)
	})
	t.Run("heartbeat_shares_cap", func(t *testing.T) {
		// As polledAgent, with the agent's host in every later version, so
		// no removal is recorded and the heartbeat relays no signer call.
		e := newAgentEnv(t, true)
		id, _ := e.approvedAgent(t)
		if rec := e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath, nil); rec.Code != http.StatusOK {
			t.Fatalf("the first state: %d %s", rec.Code, rec.Body.String())
		}
		for len(e.dirs) < 18 {
			e.installDir(t, e.webEntry(t))
		}
		h := holdStates(t, e, []agentID{id}, maxAgentInFlight)
		h.settleAt(t, maxAgentInFlight)
		h.quiet(t)
		before := e.fake.count("GetDirectoryVersion")
		rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(10, 18)})
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" || apiError(rec) != "rate limited" {
			t.Fatalf("a heartbeat with 2 state requests in flight = %d, Retry-After %q, %s; want 429, 1, rate limited",
				rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
		}
		// A guard only: without a pending removal the heartbeat relays no
		// call anyway; the 429 is what this case pins.
		if n := e.fake.count("GetDirectoryVersion"); n != before {
			t.Fatalf("the refused heartbeat made %d signer calls", n-before)
		}
		h.release()
		h.answered(t, maxAgentInFlight, http.StatusOK)
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(10, 18)}); rec.Code != http.StatusOK {
			t.Fatalf("the heartbeat after the state requests ended = %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("cap_released_after_answer", func(t *testing.T) {
		e := newAgentEnv(t, true)
		ids := agentsAt(t, e, 1, 18)
		for range 2 {
			h := holdStates(t, e, ids, maxAgentInFlight)
			h.settleAt(t, maxAgentInFlight)
			h.quiet(t)
			h.release()
			h.answered(t, maxAgentInFlight, http.StatusOK)
		}
		e.s.inFlightMu.Lock()
		n := len(e.s.agentInFlight)
		e.s.inFlightMu.Unlock()
		if n != 0 {
			t.Fatalf("the in-flight map holds %d keys after every request ended, want 0", n)
		}
	})
	t.Run("cap_per_agent", func(t *testing.T) {
		e := newAgentEnv(t, true)
		ids := agentsAt(t, e, 2, 18)
		h := holdStates(t, e, ids, maxAgentInFlight)
		h.settleAt(t, 2*maxAgentInFlight)
		h.quiet(t)
		h.release()
		h.answered(t, 2*maxAgentInFlight, http.StatusOK)
	})
}

// countEntered counts, until the test ends, the calls that signal entered
// (the channel of fakeSigner.hold, whose sends block).
func countEntered(t *testing.T, entered <-chan struct{}) *atomic.Int64 {
	t.Helper()
	n := &atomic.Int64{}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-entered:
				n.Add(1)
			case <-stop:
				return
			}
		}
	}()
	return n
}

// dirResult is one currentDirectory answer.
type dirResult struct {
	v   *directoryView
	err error
}

// goDirectories starts n concurrent currentDirectory calls with ctx.
func goDirectories(ctx context.Context, e *agentEnv, n int) <-chan dirResult {
	out := make(chan dirResult, n)
	for range n {
		go func() {
			v, err := e.s.currentDirectory(ctx)
			out <- dirResult{v, err}
		}()
	}
	return out
}

// results waits for n answers of goDirectories.
func results(t *testing.T, ch <-chan dirResult, n int) []dirResult {
	t.Helper()
	var out []dirResult
	for i := range n {
		select {
		case r := <-ch:
			out = append(out, r)
		case <-time.After(20 * time.Second):
			t.Fatalf("%d of %d currentDirectory calls never returned", n-i, n)
		}
	}
	return out
}

// mirrorEnv is newAgentEnv with one directory installed, the status cached
// and the mirror empty.
func mirrorEnv(t *testing.T) *agentEnv {
	t.Helper()
	e := newAgentEnv(t, true)
	e.installDir(t, hostEntry("web1", hostSigners(t, 1)))
	if _, err := e.s.currentStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e
}

// mirrorEntry returns the mirror's held entry.
func mirrorEntry(e *agentEnv) *directoryView {
	e.s.mirror.mu.Lock()
	defer e.s.mirror.mu.Unlock()
	return e.s.mirror.entry
}

// TestDirectoryMirrorFill pins F12 (03-08g): while the mirror holds no
// entry for the SHA-256 and version Status reports, every concurrent
// caller of currentDirectory shares one detached GetDirectory fetch for
// them; each waiter stops at the end of its own ctx, a failed fetch is
// never cached, a caller whose ctx has ended starts none, a fetch for an
// older Status never becomes the entry, and a mismatch still drops the
// status cache.
func TestDirectoryMirrorFill(t *testing.T) {
	ctx := context.Background()
	t.Run("concurrent_misses_one_fetch", func(t *testing.T) {
		e := mirrorEnv(t)
		before := e.fake.count("GetDirectory")
		entered, release := e.fake.hold("GetDirectory")
		t.Cleanup(release)
		n := countEntered(t, entered)
		ch := goDirectories(ctx, e, 24)
		waitFor(t, "a GetDirectory at the signer", func() bool { return n.Load() >= 1 })
		time.Sleep(settle)
		release()
		want := sha256.Sum256(e.dirs[0])
		for _, r := range results(t, ch, 24) {
			if r.err != nil || r.v.version != 1 || r.v.sha256 != want {
				t.Fatalf("currentDirectory = %+v, %v; want version 1 with the installed SHA-256", r.v, r.err)
			}
		}
		if got := e.fake.count("GetDirectory") - before; got != 1 {
			t.Fatalf("%d GetDirectory calls for 24 concurrent misses, want 1", got)
		}
	})
	t.Run("failure_not_cached", func(t *testing.T) {
		e := mirrorEnv(t)
		e.fake.setDirectory(nil, errors.New("signer down"))
		entered, release := e.fake.hold("GetDirectory")
		t.Cleanup(release)
		n := countEntered(t, entered)
		ch := goDirectories(ctx, e, 5)
		waitFor(t, "a GetDirectory at the signer", func() bool { return n.Load() >= 1 })
		time.Sleep(settle)
		release()
		for _, r := range results(t, ch, 5) {
			if !errors.Is(r.err, errMirrorStale) {
				t.Fatalf("a waiter of the failed fetch = %v, want errMirrorStale", r.err)
			}
		}
		e.fake.setDirectory(&wire.GetDirectoryResponse{}, nil)
		before := e.fake.count("GetDirectory")
		if v, err := e.s.currentDirectory(ctx); err != nil || v.version != 1 {
			t.Fatalf("the call after the failure = %v; want version 1 (the failure was cached)", err)
		}
		if got := e.fake.count("GetDirectory") - before; got != 1 {
			t.Fatalf("the call after the failure made %d GetDirectory calls, want 1", got)
		}
	})
	t.Run("waiter_ctx_ends_fetch_continues", func(t *testing.T) {
		e := mirrorEnv(t)
		start := e.fake.count("GetDirectory")
		entered, release := e.fake.hold("GetDirectory")
		t.Cleanup(release)
		first, cancel := context.WithCancel(ctx)
		defer cancel()
		a := goDirectories(first, e, 1)
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("no GetDirectory reached the signer")
		}
		b := goDirectories(ctx, e, 1)
		time.Sleep(settle) // the second waiter joins the fetch
		cancel()
		if r := results(t, a, 1)[0]; !errors.Is(r.err, context.Canceled) {
			t.Fatalf("the first caller after its ctx ended = %v, want context.Canceled", r.err)
		}
		release()
		if r := results(t, b, 1)[0]; r.err != nil || r.v.version != 1 {
			t.Fatalf("the second waiter = %v; want version 1 (the fetch went on)", r.err)
		}
		// One fetch in all: the second waiter shared the first caller's,
		// also when it joined only after the cancel (pre-merge review fix
		// round 1).
		if got := e.fake.count("GetDirectory") - start; got != 1 {
			t.Fatalf("%d GetDirectory calls for the two waiters, want 1 (the second waiter shared the fetch)", got)
		}
		before := e.fake.count("GetDirectory")
		if m := mirrorEntry(e); m == nil || m.version != 1 {
			t.Fatal("the mirror holds no entry after the fetch the first caller left")
		}
		if _, err := e.s.currentDirectory(ctx); err != nil || e.fake.count("GetDirectory") != before {
			t.Fatalf("the next call = %v after %d GetDirectory calls; want the held entry and none", err, e.fake.count("GetDirectory")-before)
		}
	})
	t.Run("ended_ctx_starts_no_fetch", func(t *testing.T) {
		e := mirrorEnv(t)
		dead, kill := context.WithCancel(ctx)
		kill()
		before := e.fake.count("GetDirectory")
		if _, err := e.s.currentDirectory(dead); !errors.Is(err, context.Canceled) {
			t.Fatalf("currentDirectory with an ended ctx = %v, want context.Canceled", err)
		}
		time.Sleep(settle) // a detached fetch would have reached the signer
		if got := e.fake.count("GetDirectory") - before; got != 0 {
			t.Fatalf("a caller with an ended ctx started %d GetDirectory calls, want 0", got)
		}
		if v, err := e.s.currentDirectory(ctx); err != nil || v.version != 1 {
			t.Fatalf("currentDirectory with a live ctx = %v", err)
		}
	})
	t.Run("new_sha_new_fetch", func(t *testing.T) {
		e := mirrorEnv(t)
		entered1, release1 := e.fake.hold("GetDirectory")
		t.Cleanup(release1)
		a := goDirectories(ctx, e, 1)
		select {
		case <-entered1:
		case <-time.After(10 * time.Second):
			t.Fatal("the version-1 fetch never reached the signer")
		}
		// Version 2 is installed (installDir drops the status cache), and
		// its fetch is held at a second gate, so the version-1 fetch ends
		// first, while the version-2 fetch is in flight.
		e.installDir(t, hostEntry("web2", hostSigners(t, 1)))
		entered2, release2 := e.fake.hold("GetDirectory")
		t.Cleanup(release2)
		b := goDirectories(ctx, e, 1)
		select {
		case <-entered2:
		case <-time.After(10 * time.Second):
			t.Fatal("the version-2 fetch never reached the signer")
		}
		release1()
		if r := results(t, a, 1)[0]; r.err != nil || r.v.version != 1 {
			t.Fatalf("the version-1 caller = %v, want the version it was read under", r.err)
		}
		if m := mirrorEntry(e); m != nil {
			t.Fatalf("the mirror holds version %d while the version-2 fetch is in flight, want no entry", m.version)
		}
		before := e.fake.count("GetDirectory")
		c := goDirectories(ctx, e, 1)
		time.Sleep(settle) // the third caller joins the version-2 fetch
		if got := e.fake.count("GetDirectory") - before; got != 0 {
			t.Fatalf("a caller for version 2 started %d GetDirectory calls with the version-2 fetch in flight, want 0", got)
		}
		release2()
		want := sha256.Sum256(e.dirs[1])
		for _, r := range append(results(t, b, 1), results(t, c, 1)...) {
			if r.err != nil || r.v.version != 2 || r.v.sha256 != want {
				t.Fatalf("a version-2 caller = %+v, %v", r.v, r.err)
			}
		}
		if m := mirrorEntry(e); m == nil || m.version != 2 || m.sha256 != want {
			t.Fatal("the mirror does not hold version 2 after its fetch")
		}
	})
	// Pre-merge review fix round 1: callers with competing Status snapshots
	// (old, new, old, new) never replace each other's pending fetch. One
	// GetDirectory runs per SHA-256 and version, and only the fetch for the
	// Status the server holds when it ends becomes the entry.
	t.Run("competing_status_one_fetch_per_key", func(t *testing.T) {
		e := mirrorEnv(t)
		oldView, err := e.s.currentStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// late is a caller that read oldView, the version-1 Status, and
		// reaches the mirror only now.
		late := func() <-chan dirResult {
			out := make(chan dirResult, 1)
			go func() {
				v, err := e.s.directoryUnder(ctx, oldView)
				out <- dirResult{v, err}
			}()
			return out
		}
		before := e.fake.count("GetDirectory")
		entered1, release1 := e.fake.hold("GetDirectory")
		t.Cleanup(release1)
		a := goDirectories(ctx, e, 1)
		select {
		case <-entered1:
		case <-time.After(10 * time.Second):
			t.Fatal("the version-1 fetch never reached the signer")
		}
		e.installDir(t, hostEntry("web2", hostSigners(t, 1)))
		entered2, release2 := e.fake.hold("GetDirectory")
		t.Cleanup(release2)
		b := goDirectories(ctx, e, 1)
		select {
		case <-entered2:
		case <-time.After(10 * time.Second):
			t.Fatal("the version-2 fetch never reached the signer")
		}
		// The server holds the version-2 Status now. A late version-1
		// caller, then another version-2 caller.
		c := late()
		time.Sleep(settle)
		d := goDirectories(ctx, e, 1)
		time.Sleep(settle)
		if got := e.fake.count("GetDirectory") - before; got != 2 {
			t.Fatalf("%d GetDirectory calls for the callers of versions 1, 2, 1 and 2, want 2 (one per SHA-256 and version)", got)
		}
		release1()
		release2()
		for want, rs := range map[uint64][]dirResult{1: append(results(t, a, 1), results(t, c, 1)...), 2: append(results(t, b, 1), results(t, d, 1)...)} {
			sha := sha256.Sum256(e.dirs[want-1])
			for _, r := range rs {
				if r.err != nil || r.v.version != want || r.v.sha256 != sha {
					t.Fatalf("a version-%d caller = %+v, %v", want, r.v, r.err)
				}
			}
		}
		if m := mirrorEntry(e); m == nil || m.version != 2 {
			t.Fatal("the mirror does not hold version 2, the version of the Status the server holds")
		}
		// A late version-1 caller once that fetch has ended starts a fetch
		// of its own, which fails closed (the signer serves version 2 now)
		// and leaves the newer entry alone.
		if r := <-late(); !errors.Is(r.err, errMirrorStale) {
			t.Fatalf("the late version-1 caller = %v, want errMirrorStale", r.err)
		}
		if m := mirrorEntry(e); m == nil || m.version != 2 {
			t.Fatal("a caller with the older version-1 Status dropped the version-2 entry")
		}
	})
	t.Run("mismatch_drops_status", func(t *testing.T) {
		e := mirrorEnv(t)
		// Status keeps reporting version 1 with its SHA-256; the signer's
		// directory answer has other bytes.
		e.fake.mu.Lock()
		st := *e.fake.status
		st.DirectoryVersion, st.DirectorySHA256, st.DirectoryAuthorized = 1, sha256.Sum256(e.dirs[0]), true
		e.fake.status, e.fake.chain = &st, false
		e.fake.dir = &wire.GetDirectoryResponse{Version: 1, Directory: []byte("other bytes"), Sigs: []byte("sigs"), Authorized: true}
		e.fake.mu.Unlock()
		e.s.dropStatus()
		if _, err := e.s.currentStatus(ctx); err != nil {
			t.Fatal(err)
		}
		entered, release := e.fake.hold("GetDirectory")
		t.Cleanup(release)
		n := countEntered(t, entered)
		ch := goDirectories(ctx, e, 5)
		waitFor(t, "a GetDirectory at the signer", func() bool { return n.Load() >= 1 })
		time.Sleep(settle)
		release()
		for _, r := range results(t, ch, 5) {
			if !errors.Is(r.err, errMirrorStale) {
				t.Fatalf("a waiter of the mismatched fetch = %v, want errMirrorStale", r.err)
			}
		}
		st0 := e.fake.count("Status")
		if _, err := e.s.currentDirectory(ctx); !errors.Is(err, errMirrorStale) {
			t.Fatalf("the next call = %v, want errMirrorStale", err)
		}
		if got := e.fake.count("Status") - st0; got != 1 {
			t.Fatalf("the next call made %d Status calls with the clock still, want 1 (the mismatch dropped the status cache)", got)
		}
	})
}

// TestSocketSignerAwaitsClose (F16 (03-08h)): socketSigner's calls return
// only after the signer has closed the connection, so budgetSigner frees a
// token only once the signer has freed that connection's slot. Its test
// signer answers a Login and holds the connection open.
func TestSocketSignerAwaitsClose(t *testing.T) {
	dir, err := os.MkdirTemp("", "krsw") // t.TempDir can exceed macOS's socket path limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	resp, err := (&wire.IssueResponse{Cert: []byte("cert"), Serial: 7, LeafIndex: 9}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	answered, release := make(chan time.Time, 1), make(chan struct{})
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if _, _, err := wire.ReadMessage(conn, wire.RequestCaps); err != nil {
			return
		}
		_ = wire.WriteMessage(conn, wire.TypeIssueResponse, resp)
		answered <- time.Now()
		<-release
	}()
	type result struct {
		resp *wire.IssueResponse
		err  error
	}
	got := make(chan result, 1)
	go func() {
		r, err := socketSigner{socket: socket}.Login(context.Background(), &wire.LoginIssueRequest{SubjectKey: []byte{1}, Subject: "alice"})
		got <- result{r, err}
	}()
	<-answered
	select {
	case r := <-got:
		close(release)
		t.Fatalf("Login returned (%+v, %v) while the signer held the connection open, want it to wait for the close", r.resp, r.err)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	r := <-got
	if r.err != nil || string(r.resp.Cert) != "cert" {
		t.Fatalf("Login after the close = %+v, %v; want the signer's answer", r.resp, r.err)
	}
}

// serveWithin serves req on h in a goroutine and returns its answer, or
// fails the test after 10 s with a message naming what.
func serveWithin(t *testing.T, h http.Handler, req *http.Request, what string) *httptest.ResponseRecorder {
	t.Helper()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- serve(h, req) }()
	select {
	case rec := <-done:
		return rec
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: no answer within 10 s", what)
		return nil
	}
}

// TestRoutesPastStatusTTLWithHeldCall (03-08i) pins the server's half of
// delivery during a slow signature, against the test double: fakeSigner's
// Status never waits and no signature is held, so neither case has a RED
// on origin/main. With one signer call held, GET /api/v1/krl and an
// approved agent's state answer 200 past statusTTL from one fresh status
// refresh. With every budget token held, the refresh waits for a token
// until statusTimeout and the KRL route answers 503 (Q-I2 A). The whole
// claim, a real server in front of the real signer during a held
// signature, is TestDeliveryDuringHeldSignature (test/e2e).
func TestRoutesPastStatusTTLWithHeldCall(t *testing.T) {
	setup := func(t *testing.T) (*agentEnv, agentID, func() *http.Request) {
		t.Helper()
		e := newAgentEnv(t, true)
		e.publishKRL(t, 101)
		id, _ := e.approvedAgent(t)
		get := func() *http.Request {
			return signedReq(t, nil, http.MethodGet, serverclient.KRLPath, serverclient.KRLPath, nil, e.clock.Now())
		}
		if rec := serve(e.s.Handler(), get()); rec.Code != http.StatusOK {
			t.Fatalf("the first GET krl = %d %s", rec.Code, rec.Body.String())
		}
		if c := e.state(t, id); c != http.StatusOK {
			t.Fatalf("the first state request = %d", c)
		}
		return e, id, get
	}
	stateReq := func(id agentID) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "https://"+testRPID+":8443"+serverclient.AgentStatePath, nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{id.cert}}
		return req
	}
	hold := func(t *testing.T, e *agentEnv, n int) (func(), <-chan error) {
		t.Helper()
		entered, release := e.fake.hold("Login")
		t.Cleanup(release)
		logins := goCalls(context.Background(), e.s.signer, n, only("Login"))
		for i := range n {
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatalf("%d of %d Logins reached the signer", i, n)
			}
		}
		return release, logins
	}
	t.Run("krl_and_state_past_status_ttl", func(t *testing.T) {
		e, id, get := setup(t)
		release, logins := hold(t, e, 1)
		e.clock.set(e.clock.Now().Add(statusTTL + time.Second))
		before := e.fake.count("Status")
		rec := serveWithin(t, e.s.Handler(), get(), "GET krl past statusTTL with one call held")
		var doc serverclient.KRLDocument
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &doc) != nil || string(doc.KRL) != "krl version 101" {
			t.Fatalf("GET krl past statusTTL with one call held = %d %s", rec.Code, rec.Body.String())
		}
		if rec := serveWithin(t, e.s.AgentHandler(), stateReq(id), "state past statusTTL with one call held"); rec.Code != http.StatusOK {
			t.Fatalf("state past statusTTL with one call held = %d %s", rec.Code, rec.Body.String())
		}
		if n := e.fake.count("Status") - before; n != 1 {
			t.Fatalf("%d Status calls past statusTTL, want 1 (one fresh refresh)", n)
		}
		release()
		collect(t, logins, 1)
	})
	t.Run("budget_full_status_waits", func(t *testing.T) {
		e, _, get := setup(t)
		release, logins := hold(t, e, maxSignerCalls)
		e.clock.set(e.clock.Now().Add(statusTTL + time.Second))
		before := e.fake.count("Status")
		if rec := serveWithin(t, e.s.Handler(), get(), "GET krl past statusTTL with the budget full"); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("GET krl past statusTTL with the budget full = %d %s; want 503", rec.Code, rec.Body.String())
		}
		if n := e.fake.count("Status") - before; n != 0 {
			t.Fatalf("%d Status calls with the budget full, want 0 (the refresh waits for a token)", n)
		}
		release()
		collect(t, logins, maxSignerCalls)
	})
}

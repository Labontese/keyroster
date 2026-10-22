package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

func init() {
	register(command{
		Name:    "login",
		Summary: "get a short-lived SSH certificate into your ssh-agent after approving the request with your passkey",
		Run:     runLogin,
	})
}

// The server routes keyroster login uses (02-12).
const (
	loginOptionsRoute = "/api/v1/login/options"
	loginBeginRoute   = "/api/v1/login/begin"
	loginRoutePrefix  = "/api/v1/login/"
)

const (
	// maxLoginSkew is the largest clock difference to the server that
	// keyroster login accepts (RESEARCH Pitfall 8).
	maxLoginSkew = 60 * time.Second
	// minLoginRemaining is the least validity a certificate must have
	// left when it arrives; the agent lifetime is what is left.
	minLoginRemaining = 60
	// minLoginTTL is the shortest TTL keyroster login requests, so that
	// a certificate can still have minLoginRemaining seconds left after
	// the approval.
	minLoginTTL = 2 * time.Minute
	// certBackdate is cert.Build's backdate of ValidAfter, in seconds.
	certBackdate = 300
	// callbackGrace is how long past the server's approval deadline the
	// CLI keeps waiting for the loopback callback.
	callbackGrace = 5 * time.Second
)

// loginNow is keyroster login's clock, and loginTimer its timer for the
// callback wait; tests replace them.
var (
	loginNow   = time.Now
	loginTimer = func(d time.Duration) <-chan time.Time { return time.After(d) }
)

// loginOptions is the server's GET loginOptionsRoute answer. Nothing in it
// is trusted: every name is checked against the directory rules before it
// is printed or signed, and the user CA cap comes from the root-verified
// policy.
type loginOptions struct {
	ServerTime      int64              `json:"server_time"`
	User            string             `json:"user"`
	CAMaxTTLSeconds uint64             `json:"ca_max_ttl_seconds"`
	Roles           []loginOptionsRole `json:"roles"`
}

type loginOptionsRole struct {
	Name          string   `json:"name"`
	Principals    []string `json:"principals"`
	MaxTTLSeconds uint64   `json:"max_ttl_seconds"`
	Extensions    []string `json:"extensions"`
}

type loginBeginBody struct {
	Request             []byte `json:"request"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	State               string `json:"state"`
	RedirectPort        int    `json:"redirect_port"`
}

type loginBeginAnswer struct {
	LoginID     string `json:"login_id"`
	ApprovalURL string `json:"approval_url"`
	ExpiresAt   int64  `json:"expires_at"`
}

type loginRedeemBody struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

type loginRedeemAnswer struct {
	Certificate []byte `json:"certificate"`
}

var (
	loginIDPattern   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	extensionPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,63}$`)
)

// errBadLoginOptions refuses a login options answer the CLI cannot check.
// It never repeats the server's text.
var errBadLoginOptions = errors.New("the server's login options do not check out, so no login was started")

// signerLoginRefusals are the signer's refusal details of a login (the
// closed list in internal/signer), printed in full. Any other refusal text
// is the server's and is shown only as a PeerError excerpt.
var signerLoginRefusals = []string{
	"request_time_skew", "missing_evidence", "too_many_evidence", "unknown_evidence_type",
	"no_webauthn_policy", "directory_not_installed", "directory_not_authorized",
	"unknown_user", "user_disabled", "role_not_granted", "bad_evidence", "unknown_credential",
	"credential_mismatch", "bad_authenticator_data", "rp_mismatch", "user_presence_missing",
	"user_verification_missing", "bad_client_data", "type_mismatch", "challenge_mismatch",
	"origin_mismatch", "cross_origin_refused", "unsupported_algorithm", "assertion_signature_invalid",
	"principals_mismatch", "ca_not_configured", "ttl_exceeds_role", "duplicate_extension",
	"extension_not_allowed", "bad_subject_key", "duplicate_request", "bad_validity",
}

// runLogin is keyroster login [--role R]... [--ttl DURATION] [--no-browser]:
// the D-12 browser-loopback login. It makes an ephemeral Ed25519 key in
// memory, builds the login request from the server's options for the
// configured user (principals and TTL as the selected roles grant them),
// prints the key's fingerprint, begins the login with PKCE S256 and a
// state, has the user approve the exact request with a passkey on the
// approval page, takes the code from its 127.0.0.1 loopback and redeems
// it. The certificate is accepted only from the root-pinned user CA, for
// its own key, with exactly the requested principals, a kr2 key ID naming
// the user and the request, and at least 60 s left; then it goes into the
// agent with a lifetime equal to its remaining validity. The private key
// is never written to a file.
func runLogin(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("login", flag.ContinueOnError)
	fset.SetOutput(stderr)
	var roles stringList
	fset.Var(&roles, "role", "log in with only this role (repeatable; default: all your roles)")
	ttl := fset.Duration("ttl", 0, "certificate lifetime, at least 2m (default and maximum: the smallest cap of the selected roles)")
	noBrowser := fset.Bool("no-browser", false, "print the approval URL instead of opening a browser")
	if err := fset.Parse(args); err != nil {
		return errUsage
	}
	if fset.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "login: no positional arguments")
		return errUsage
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if !directory.ValidUserName(cfg.User) {
		return errors.New("the keyroster config names no valid user; run keyroster init with --user NAME --force")
	}
	client, err := serverclient.New(serverclient.Config{Server: cfg.Server, RootsPEM: cfg.TLSRootsPEM, Pins: cfg.TLSPins, Stderr: stderr})
	if err != nil {
		return err
	}
	bundle, policy, err := client.Trust(ctx, cfg.TrustPins, cfg.TrustThreshold)
	if err != nil {
		return err
	}
	ca, err := activeUserCA(bundle)
	if err != nil {
		return err
	}
	l := &loginRun{client: client, cfg: cfg, policy: policy, ca: ca, stdout: stdout, stderr: stderr}
	return l.run(ctx, roles, *ttl, *noBrowser)
}

// activeUserCA returns the active user CA key of the root-verified bundle.
func activeUserCA(b *trust.Bundle) (ssh.PublicKey, error) {
	for _, c := range b.CAs {
		if c.Role == trust.RoleUser && c.State == "active" {
			return trust.ParseKey(c.Key)
		}
	}
	return nil, errors.New("the root-signed trust bundle has no active user CA")
}

// loginRun is one keyroster login.
type loginRun struct {
	client *serverclient.Client
	cfg    *Config
	policy *trust.Policy
	ca     ssh.PublicKey
	stdout io.Writer
	stderr io.Writer
}

// loginPlan is what the login asks for, from the checked options.
type loginPlan struct {
	roles      []string // nil: all the user's roles
	principals []string
	extensions []string
	ttl        time.Duration
	skew       time.Duration // server time minus local time
}

func (l *loginRun) run(ctx context.Context, roles []string, ttl time.Duration, noBrowser bool) error {
	user := l.cfg.User
	var opts loginOptions
	if err := l.client.GetJSON(ctx, loginOptionsRoute+"?user="+url.QueryEscape(user), &opts); err != nil {
		var he *serverclient.HTTPError
		if errors.As(err, &he) && he.Code == http.StatusNotFound {
			return fmt.Errorf("the server has no usable passkey for %s: the user is not in the installed directory, is disabled, or has no approved passkey", user)
		}
		return err
	}
	plan, err := l.plan(&opts, roles, ttl)
	if err != nil {
		return err
	}

	// The ephemeral key: memory only, zeroed on every return path (best
	// effort; the agent holds its own copy for the certificate's lifetime).
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	defer clear(priv)
	if err != nil {
		return err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	req := &wire.LoginIssueRequest{
		SubjectKey:      sshPub.Marshal(),
		Subject:         user,
		Roles:           plan.roles,
		Principals:      plan.principals,
		ValidForSeconds: uint32(plan.ttl / time.Second), //nolint:gosec // G115: at most the user CA cap, a policy uint32
		CreatedAt:       uint64(loginNow().Unix()),      //nolint:gosec // G115: a clock after 1970
		Extensions:      plan.extensions,
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		return err
	}
	reqBytes, err := req.Marshal()
	if err != nil {
		return err
	}
	fingerprint := ssh.FingerprintSHA256(sshPub)
	_, _ = fmt.Fprintf(l.stderr, "Login for %s: principals %s, valid %s\nKey fingerprint: %s\nApprove in your browser only if it shows this fingerprint.\n",
		user, strings.Join(plan.principals, ", "), plan.ttl, fingerprint)

	verifier, err := randomB64(32)
	if err != nil {
		return err
	}
	state, err := randomB64(32)
	if err != nil {
		return err
	}
	challenge := sha256.Sum256([]byte(verifier))
	lb, err := listenLoopback(state)
	if err != nil {
		return err
	}
	defer lb.close()

	var begin loginBeginAnswer
	if err := l.client.PostJSON(ctx, loginBeginRoute, loginBeginBody{
		Request:             reqBytes,
		CodeChallenge:       base64.RawURLEncoding.EncodeToString(challenge[:]),
		CodeChallengeMethod: "S256",
		State:               state,
		RedirectPort:        lb.port,
	}, &begin); err != nil {
		return err
	}
	approvalURL, err := l.checkBegin(&begin, opts.ServerTime)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(l.stderr, "Approve this login in your browser: %s\n", approvalURL)
	if !noBrowser {
		if err := openBrowser(approvalURL); err != nil {
			_, _ = fmt.Fprintf(l.stderr, "warning: could not open a browser (%v); open the URL above yourself\n", err)
		}
	}

	deadline := callbackDeadline(begin.ExpiresAt, plan.skew)
	code, err := lb.wait(ctx, loginTimer(deadline.Sub(loginNow())))
	if err != nil {
		return err
	}
	lb.close()

	var redeemed loginRedeemAnswer
	if err := l.client.PostJSON(ctx, loginRoutePrefix+begin.LoginID+"/redeem", loginRedeemBody{Code: code, CodeVerifier: verifier}, &redeemed); err != nil {
		return redeemFailure(err)
	}
	now := loginNow()
	c, remaining, err := checkLoginCert(redeemed.Certificate, l.ca, sshPub, req, plan.ttl, now)
	if err != nil {
		return fmt.Errorf("login not completed: the certificate does not check out (%w), so nothing was added to the agent; run keyroster login again", err)
	}
	if err := addLoginToAgent(ctx, priv, c, remaining); err != nil {
		return err
	}
	until := time.Unix(int64(c.ValidBefore), 0).Local() //nolint:gosec // G115: checked against now above
	_, _ = fmt.Fprintf(l.stdout, "Logged in as %s: principals %s\nSerial: %d\nKey ID: %s\nValid until: %s\n",
		user, strings.Join(c.ValidPrincipals, ", "), c.Serial, c.KeyId, until.Format("2006-01-02 15:04:05 MST"))
	if hint := loginAgentHint(); hint != "" {
		_, _ = io.WriteString(l.stdout, hint)
	}
	return nil
}

// plan checks the server's options and selects what to ask for: the
// --role subset (each must be among the options) or every role, the
// sorted union of their principals and extensions, and a TTL of at most
// the smallest of their caps and the root-verified user CA cap.
func (l *loginRun) plan(opts *loginOptions, roles []string, ttl time.Duration) (*loginPlan, error) {
	caCap := uint64(0)
	for _, p := range l.policy.CAProfiles {
		if p.Role == trust.RoleUser {
			caCap = p.MaxTTLSeconds
		}
	}
	if opts.User != l.cfg.User || opts.ServerTime <= 0 || caCap == 0 || opts.CAMaxTTLSeconds != caCap || len(opts.Roles) > wire.MaxLoginRoles*4 {
		return nil, errBadLoginOptions
	}
	byName := map[string]loginOptionsRole{}
	for _, r := range opts.Roles {
		if !directory.ValidRoleName(r.Name) || r.MaxTTLSeconds == 0 || len(r.Principals) == 0 || cert.ValidatePrincipals(r.Principals) != nil {
			return nil, errBadLoginOptions
		}
		for _, e := range r.Extensions {
			if !extensionPattern.MatchString(e) {
				return nil, errBadLoginOptions
			}
		}
		if _, dup := byName[r.Name]; dup {
			return nil, errBadLoginOptions
		}
		byName[r.Name] = r
	}
	skew := time.Unix(opts.ServerTime, 0).Sub(loginNow()).Truncate(time.Second)
	if skew > maxLoginSkew || skew < -maxLoginSkew {
		return nil, fmt.Errorf("your clock differs from the server by %ds; fix it before logging in", int64(skew/time.Second))
	}
	if len(byName) == 0 {
		return nil, fmt.Errorf("%s holds no role on this server; ask an admin to grant one", l.cfg.User)
	}
	p := &loginPlan{skew: skew}
	selected := make([]string, 0, len(byName))
	if len(roles) > 0 {
		for _, r := range roles {
			if _, ok := byName[r]; !ok {
				if directory.ValidRoleName(r) {
					return nil, fmt.Errorf("--role %s: you do not hold that role on this server", r)
				}
				return nil, errors.New("--role: not a valid role name")
			}
			if !slices.Contains(selected, r) {
				selected = append(selected, r)
			}
		}
		slices.Sort(selected)
		if len(selected) > wire.MaxLoginRoles {
			return nil, fmt.Errorf("--role: at most %d roles", wire.MaxLoginRoles)
		}
		p.roles = selected
	} else {
		for name := range byName {
			selected = append(selected, name)
		}
		slices.Sort(selected)
	}
	capSecs := caCap
	principals, extensions := map[string]bool{}, map[string]bool{}
	for _, name := range selected {
		r := byName[name]
		capSecs = min(capSecs, r.MaxTTLSeconds)
		for _, pr := range r.Principals {
			principals[pr] = true
		}
		for _, e := range r.Extensions {
			extensions[e] = true
		}
	}
	p.principals = sortedSet(principals)
	p.extensions = sortedSet(extensions)
	if len(p.principals) > wire.MaxPrincipals {
		return nil, errBadLoginOptions
	}
	capTTL := time.Duration(capSecs) * time.Second //nolint:gosec // G115: a policy TTL in seconds
	switch {
	case ttl == 0:
		p.ttl = capTTL
	case ttl > capTTL:
		return nil, fmt.Errorf("--ttl %s is longer than %s, the most the selected roles allow", ttl, capTTL)
	default:
		p.ttl = ttl.Truncate(time.Second)
	}
	if p.ttl < minLoginTTL {
		return nil, fmt.Errorf("a login certificate must be valid for at least %s, so that it has %d s left when it arrives (requested %s)", minLoginTTL, minLoginRemaining, p.ttl)
	}
	return p, nil
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// checkBegin checks the server's begin answer and returns the approval URL
// rebuilt from checked parts: a 32-hex login ID, an expiry a few minutes
// after the server's time, and an https URL with no user, query or
// fragment, whose origin is the configured server or a root-signed policy
// origin and whose path is exactly /login/<login ID>. Only that URL is
// printed or handed to the browser opener.
func (l *loginRun) checkBegin(b *loginBeginAnswer, serverTime int64) (string, error) {
	bad := errors.New("the server's login begin answer does not check out, so no approval URL was opened")
	if !loginIDPattern.MatchString(b.LoginID) || b.ExpiresAt <= serverTime || b.ExpiresAt-serverTime > 600 {
		return "", bad
	}
	u, err := url.Parse(b.ApprovalURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" ||
		u.Opaque != "" || u.Path != "/login/"+b.LoginID {
		return "", bad
	}
	origin := "https://" + u.Host
	allowed := origin == l.client.Server()
	if l.policy.WebAuthn != nil && slices.Contains(l.policy.WebAuthn.Origins, origin) {
		allowed = true
	}
	if !allowed {
		return "", bad
	}
	return origin + "/login/" + b.LoginID, nil
}

// callbackDeadline is when the CLI stops waiting for the loopback
// callback, on its own clock: the server's approval deadline mapped
// through the measured skew, plus callbackGrace (02-12-F15).
func callbackDeadline(expiresAt int64, skew time.Duration) time.Time {
	return time.Unix(expiresAt, 0).Add(-skew).Add(callbackGrace)
}

// redeemFailure states a failed redeem. The CLI never retries: the code is
// single-use, and a certificate the signer issued for a lost answer is
// bound to this process's key, which is gone when it exits.
func redeemFailure(err error) error {
	var he *serverclient.HTTPError
	if errors.As(err, &he) && he.Code == http.StatusForbidden {
		for _, d := range signerLoginRefusals {
			if he.APIErrorIs(d) {
				return fmt.Errorf("login not completed: refused by the signer: %s; run keyroster login again", d)
			}
		}
		return fmt.Errorf("login not completed: refused by the signer: %w; run keyroster login again", err)
	}
	return fmt.Errorf("login not completed: %w; run keyroster login again", err)
}

// checkLoginCert parses and checks the certificate the server returned,
// against the CLI's own request and one reading of the clock, now. It must
// be a user certificate signed (signature verified) by ca, the root-pinned
// user CA, valid at now, for key, with exactly the requested principals, a
// kr2 key ID naming the user and the request ID, spanning at most the TTL
// plus cert.Build's backdate, and with at least minLoginRemaining seconds
// left. It returns the certificate and its remaining whole seconds,
// counted from now rounded up.
func checkLoginCert(raw []byte, ca, key ssh.PublicKey, req *wire.LoginIssueRequest, ttl time.Duration, now time.Time) (*ssh.Certificate, uint32, error) {
	pk, err := ssh.ParsePublicKey(raw)
	if err != nil {
		return nil, 0, errors.New("it does not parse")
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok || c.CertType != ssh.UserCert {
		return nil, 0, errors.New("it is not a user certificate")
	}
	if !bytes.Equal(c.SignatureKey.Marshal(), ca.Marshal()) {
		return nil, 0, errors.New("it is not signed by the user CA of your root-signed trust bundle")
	}
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool { return bytes.Equal(auth.Marshal(), ca.Marshal()) },
		Clock:           func() time.Time { return now },
	}
	principal := ""
	if len(c.ValidPrincipals) > 0 {
		principal = c.ValidPrincipals[0]
	}
	if err := checker.CheckCert(principal, c); err != nil {
		return nil, 0, errors.New("its CA signature or validity does not verify")
	}
	if !bytes.Equal(c.Key.Marshal(), key.Marshal()) {
		return nil, 0, errors.New("it is for another key")
	}
	if !slices.Equal(c.ValidPrincipals, req.Principals) {
		return nil, 0, errors.New("its principals are not the ones requested")
	}
	kid, err := cert.ParseKeyID(c.KeyId)
	if err != nil || kid.Roles == nil || kid.CA != wire.CARoleUser.String() || kid.Subject != req.Subject || kid.Request != hex.EncodeToString(req.RequestID[:]) {
		return nil, 0, errors.New("its key ID does not name this user and request")
	}
	if c.ValidBefore <= c.ValidAfter || c.ValidBefore-c.ValidAfter > uint64(ttl/time.Second)+certBackdate { //nolint:gosec // G115: a positive TTL
		return nil, 0, errors.New("it is valid for longer than requested")
	}
	nowSecs := now.Unix()
	if now.Nanosecond() > 0 {
		nowSecs++
	}
	if c.ValidBefore > uint64(1)<<62 || int64(c.ValidBefore)-nowSecs < minLoginRemaining { //nolint:gosec // G115: bounded above
		return nil, 0, fmt.Errorf("it has less than %d s left", minLoginRemaining)
	}
	return c, uint32(int64(c.ValidBefore) - nowSecs), nil //nolint:gosec // G115: at most the TTL plus the backdate
}

// addLoginToAgent adds key and its certificate c to the agent that
// connectLoginAgent reaches, with a lifetime of remaining seconds, then
// requires the agent's listing to hold the certificate. An agent that
// refuses the lifetime constraint fails the login: there is no retry
// without it.
func addLoginToAgent(ctx context.Context, key ed25519.PrivateKey, c *ssh.Certificate, remaining uint32) error {
	conn, err := connectLoginAgent(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ag := agent.NewClient(conn)
	if err := ag.Add(agent.AddedKey{PrivateKey: key, Certificate: c, LifetimeSecs: remaining, Comment: c.KeyId}); err != nil {
		return fmt.Errorf("the agent refused the key with a lifetime constraint; not retrying without it: %w", err)
	}
	keys, err := ag.List()
	if err != nil {
		return fmt.Errorf("list the agent's keys: %w", err)
	}
	want := c.Marshal()
	for _, k := range keys {
		if bytes.Equal(k.Blob, want) {
			return nil
		}
	}
	return errors.New("the agent dropped the certificate: it is not in the agent's listing after the add")
}

// randomB64 returns n random bytes as unpadded base64url.
func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

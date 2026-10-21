package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/webauthn"
)

// The registration routes, under the invite token they are for.
const (
	enrollBeginPath  = "/api/v1/enroll/{token}/begin"
	enrollFinishPath = "/api/v1/enroll/{token}/finish"
)

// registrationTTL is how long a begun registration ceremony may take: the
// lifetime of its session row and the timeout the browser is given.
const registrationTTL = 5 * time.Minute

// rpDisplayName is the relying party name the authenticator shows.
const rpDisplayName = "keyroster"

// maxCredentialIDLen is the longest credential ID kept (W3C WebAuthn: 1023
// bytes, the directory's limit too).
const maxCredentialIDLen = 1023

// The reason codes of the enroll refused log line: a closed list, one for
// every non-2xx answer of begin and finish (02-08-R2-F10).
const (
	reasonInviteNotValid        = "invite_not_valid"
	reasonTooManySessions       = "too_many_sessions"
	reasonBadRequest            = "bad_request"
	reasonSessionNotFound       = "session_not_found"
	reasonVerifyFailed          = "verify_failed"
	reasonUnsupportedCredential = "unsupported_credential"
	reasonDuplicateCredential   = "duplicate_credential"
	reasonSignerUnavailable     = "signer_unavailable"
	reasonInternalError         = "internal_error"
	// Added with the owner's hardening decisions of 2026-10-21 (H1, H3).
	reasonUnsupportedAttestation = "unsupported_attestation"
	reasonBodyTooLarge           = "body_too_large"
)

// The body limits of the registration routes (owner hardening H3). Begin
// takes no input beyond the URL's token, so 1 KiB only leaves room for a
// client that sends an empty JSON object. A finish with attestation none
// is a few KiB even at the largest credential ID (1023 bytes) and an
// RSA-4096 key, base64url-encoded; 64 KiB leaves room for the extra
// members browsers add, and bounds what the parser ever sees.
const (
	maxEnrollBeginBody  = 1 << 10
	maxEnrollFinishBody = 64 << 10
)

// The client answers of the registration routes. They are fixed texts: no
// value from the request or from go-webauthn's error ever reaches them.
var (
	errEnrollInviteNotValid = serverclient.APIError{Error: "invite not valid"}
	errEnrollTooMany        = serverclient.APIError{Error: "too many registrations in progress for this invite; wait a few minutes and try again"}
	errEnrollBadRequest     = serverclient.APIError{Error: "malformed registration"}
	errEnrollSession        = serverclient.APIError{Error: "this registration has expired or was already used; reload the page and try again"}
	errEnrollVerify         = serverclient.APIError{Error: "the passkey registration could not be verified"}
	errEnrollUnsupported    = serverclient.APIError{Error: "unsupported credential"}
	errEnrollDuplicate      = serverclient.APIError{Error: "this passkey is already registered"}
	errEnrollInternal       = serverclient.APIError{Error: "internal error"}
	// H1 and H3 (owner hardening, 2026-10-21).
	errEnrollAttestation = serverclient.APIError{Error: "unsupported attestation"}
	errEnrollTooLarge    = serverclient.APIError{Error: "request body too large"}
)

// errNotNone is the logged cause of an unsupported_attestation refusal.
// It is a fixed text: the format the client sent is request data and is
// never logged.
var errNotNone = errors.New("attestation format is not none")

// EnrollFinishResponse is the 200 answer of the registration finish: what
// the page shows the user to read to the admin.
type EnrollFinishResponse struct {
	// Fingerprint is webauthn.Fingerprint of the stored SPKI.
	Fingerprint string `json:"fingerprint"`
	// Algorithm is EdDSA, ES256 or RS256.
	Algorithm string `json:"algorithm"`
	// Synced is the authenticator's backup state (BS) flag.
	Synced bool `json:"synced"`
}

// enrollUser is a pending account as go-webauthn sees it: the user handle
// stored with the account and its name. It owns no credential that
// go-webauthn would need; excludeCredentials is set explicitly.
type enrollUser struct {
	handle []byte
	name   string
}

func (u enrollUser) WebAuthnID() []byte                           { return u.handle }
func (u enrollUser) WebAuthnName() string                         { return u.name }
func (u enrollUser) WebAuthnDisplayName() string                  { return u.name }
func (u enrollUser) WebAuthnCredentials() []gowebauthn.Credential { return nil }

// webauthnConfig is the go-webauthn relying party for one request, built
// from the signer's current Status only: the policy's RP ID and origins,
// attestation none, user verification required, resident key preferred.
// No FIDO metadata service is configured, and the browser timeout equals
// the session lifetime. go-webauthn's own session expiry is not enforced:
// it reads time.Now, and the session row's expiry under the server's clock
// is the authority.
func webauthnConfig(v *statusView) *gowebauthn.Config {
	return &gowebauthn.Config{
		RPID:                  v.rp.RPID,
		RPDisplayName:         rpDisplayName,
		RPOrigins:             append([]string(nil), v.rp.Origins...),
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
		},
		Timeouts: gowebauthn.TimeoutsConfig{
			Registration: gowebauthn.TimeoutConfig{Timeout: registrationTTL, TimeoutUVD: registrationTTL},
		},
	}
}

// logEnrollRefusal writes the one log line of a begin or finish answer
// that is not a 2xx: message "enroll refused" with exactly route, reason,
// user and err (02-08-R2-F10). err is only ever the error's Error() text;
// for a go-webauthn *protocol.Error that is its Details field alone, never
// its debug field, which quotes the expected and received challenge on a
// mismatch. No token, token hash, challenge, session data, credential ID,
// SPKI or request byte is ever passed in. The level is error for the two
// server-side failures and info for every refusal.
func logEnrollRefusal(log *slog.Logger, route, reason, user string, err error) {
	level := slog.LevelInfo
	if reason == reasonSignerUnavailable || reason == reasonInternalError {
		level = slog.LevelError
	}
	text := ""
	if err != nil {
		text = err.Error()
	}
	log.Log(context.Background(), level, "enroll refused", "route", route, "reason", reason, "user", user, "err", text)
}

// enrollRefuse logs the refusal and answers it with code and the fixed
// body msg (the custody header of v when there is one).
func (s *Server) enrollRefuse(w http.ResponseWriter, v *statusView, code int, msg serverclient.APIError, route, reason, user string, err error) {
	logEnrollRefusal(s.log, route, reason, user, err)
	s.writeJSON(w, v, code, msg)
}

// handleEnrollBegin serves POST /api/v1/enroll/{token}/begin. It needs a
// current, unused, unexpired invite, found with the same lookup as the
// invite page (PendingUserByInvite), so a used invite gets the same 404 as
// an unknown one. It starts a registration ceremony for the pending user's
// handle and name, with excludeCredentials the user's credentials in the
// installed directory and the credential parameters restricted to EdDSA,
// ES256 and RS256, stores the session data the server produced under the
// invite hash and the session's challenge for 5 minutes, and returns the
// creation options. An invite with 16 open sessions is refused 429.
func (s *Server) handleEnrollBegin(w http.ResponseWriter, r *http.Request) {
	const route = "begin"
	if _, ok := s.readEnrollBody(w, r, route, maxEnrollBeginBody); !ok {
		return
	}
	ctx := r.Context()
	v, err := s.currentStatus(ctx)
	if err != nil {
		s.enrollRefuse(w, nil, http.StatusServiceUnavailable, serverclient.APIError{Error: "signer unavailable"}, route, reasonSignerUnavailable, "", err)
		return
	}
	hash, ok := inviteHash(r)
	if !ok {
		s.enrollRefuse(w, v, http.StatusNotFound, errEnrollInviteNotValid, route, reasonInviteNotValid, "", nil)
		return
	}
	now := s.clock()
	u, err := s.db.PendingUserByInvite(ctx, hash, now)
	if errors.Is(err, serverdb.ErrNotFound) {
		s.enrollRefuse(w, v, http.StatusNotFound, errEnrollInviteNotValid, route, reasonInviteNotValid, "", nil)
		return
	}
	if err != nil {
		s.enrollRefuse(w, v, http.StatusInternalServerError, errEnrollInternal, route, reasonInternalError, "", err)
		return
	}
	dir, err := s.installedDirectory(ctx, v)
	if err != nil {
		s.enrollRefuse(w, nil, http.StatusServiceUnavailable, serverclient.APIError{Error: "signer unavailable"}, route, reasonSignerUnavailable, u.Name, err)
		return
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(dir.creds[u.Name]))
	for _, id := range dir.creds[u.Name] {
		exclude = append(exclude, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: id})
	}
	wa, err := gowebauthn.New(webauthnConfig(v))
	if err != nil {
		s.enrollRefuse(w, v, http.StatusInternalServerError, errEnrollInternal, route, reasonInternalError, u.Name, err)
		return
	}
	creation, session, err := wa.BeginRegistration(enrollUser{handle: u.UserHandle, name: u.Name},
		gowebauthn.WithCredentialParameters(gowebauthn.CredentialParametersRecommendedL3()),
		gowebauthn.WithExclusions(exclude))
	if err != nil {
		s.enrollRefuse(w, v, http.StatusInternalServerError, errEnrollInternal, route, reasonInternalError, u.Name, err)
		return
	}
	// The session stays on the server: stored as JSON the server wrote,
	// read back only from this table, never from the client.
	data, err := json.Marshal(session)
	if err != nil {
		s.enrollRefuse(w, v, http.StatusInternalServerError, errEnrollInternal, route, reasonInternalError, u.Name, err)
		return
	}
	err = s.db.CreateRegistrationSession(ctx, hash, session.Challenge, data, now.Add(registrationTTL).UnixMicro(), now.UnixMicro())
	if errors.Is(err, serverdb.ErrTooManySessions) {
		s.enrollRefuse(w, v, http.StatusTooManyRequests, errEnrollTooMany, route, reasonTooManySessions, u.Name, err)
		return
	}
	if err != nil {
		s.enrollRefuse(w, v, http.StatusInternalServerError, errEnrollInternal, route, reasonInternalError, u.Name, err)
		return
	}
	s.writeJSON(w, v, http.StatusOK, creation)
}

// handleEnrollFinish serves POST /api/v1/enroll/{token}/finish. The order
// makes consuming an invite atomic (02-08-F1):
//
//  1. at most maxEnrollFinishBody bytes are read (H3);
//  2. the pending user of the invite is looked up with the invite page's
//     lookup, so a used, expired, replaced or unknown invite gets the
//     uniform 404 before any third-party parser sees the body: only a
//     live invite's holder reaches go-webauthn's JSON and CBOR parsing;
//  3. the body is parsed with go-webauthn's creation-response parser; the
//     challenge in its clientDataJSON is untrusted and used only as the
//     key of the session lookup (go-webauthn compares it in step 5). An
//     attestation format other than "none" is refused here, before any
//     session is consumed and before go-webauthn could run that format's
//     verifier (H1): packed, tpm (go-tpm), android-key, android-safetynet
//     (JWT and mapstructure), fido-u2f, apple and compound, with their
//     x509 chain building, never see client input;
//  4. the session under the invite hash and that challenge is consumed,
//     once, atomically;
//  5. go-webauthn verifies the registration (UV required, the offered
//     algorithms, the policy's RP ID and origins);
//  6. the COSE key becomes SPKI DER and must pass webauthn.ParsePublicKey;
//  7. the canonical credential ID, the unpadded base64url of the ID bytes
//     go-webauthn verified, must be neither pending nor in the installed
//     directory (409);
//  8. BindPendingCredential sets invite_used_us only while the invite is
//     still current and stores the pending credential, in one transaction.
//
// It answers the fingerprint, the algorithm and the backup state.
func (s *Server) handleEnrollFinish(w http.ResponseWriter, r *http.Request) {
	const route = "finish"
	body, ok := s.readEnrollBody(w, r, route, maxEnrollFinishBody)
	if !ok {
		return
	}
	ctx := r.Context()
	v, err := s.currentStatus(ctx)
	if err != nil {
		s.enrollRefuse(w, nil, http.StatusServiceUnavailable, serverclient.APIError{Error: "signer unavailable"}, route, reasonSignerUnavailable, "", err)
		return
	}
	hash, ok := inviteHash(r)
	if !ok {
		s.enrollRefuse(w, v, http.StatusNotFound, errEnrollInviteNotValid, route, reasonInviteNotValid, "", nil)
		return
	}
	now := s.clock()
	u, err := s.db.PendingUserByInvite(ctx, hash, now)
	if errors.Is(err, serverdb.ErrNotFound) {
		s.enrollRefuse(w, v, http.StatusNotFound, errEnrollInviteNotValid, route, reasonInviteNotValid, "", nil)
		return
	}
	if err != nil {
		s.enrollRefuse(w, v, http.StatusInternalServerError, errEnrollInternal, route, reasonInternalError, "", err)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		s.enrollRefuse(w, v, http.StatusBadRequest, errEnrollBadRequest, route, reasonBadRequest, u.Name, err)
		return
	}
	if parsed.Response.AttestationObject.Format != string(protocol.AttestationFormatNone) {
		s.enrollRefuse(w, v, http.StatusBadRequest, errEnrollAttestation, route, reasonUnsupportedAttestation, u.Name, errNotNone)
		return
	}
	data, err := s.db.ConsumeRegistrationSession(ctx, hash, parsed.Response.CollectedClientData.Challenge, now.UnixMicro())
	if errors.Is(err, serverdb.ErrNotFound) || errors.Is(err, serverdb.ErrExpired) {
		s.enrollRefuse(w, v, http.StatusBadRequest, errEnrollSession, route, reasonSessionNotFound, u.Name, err)
		return
	}
	if err != nil {
		s.enrollRefuse(w, v, http.StatusInternalServerError, errEnrollInternal, route, reasonInternalError, u.Name, err)
		return
	}
	var session gowebauthn.SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		s.enrollRefuse(w, v, http.StatusInternalServerError, errEnrollInternal, route, reasonInternalError, u.Name, err)
		return
	}
	wa, err := gowebauthn.New(webauthnConfig(v))
	if err != nil {
		s.enrollRefuse(w, v, http.StatusInternalServerError, errEnrollInternal, route, reasonInternalError, u.Name, err)
		return
	}
	cred, err := wa.CreateCredential(enrollUser{handle: u.UserHandle, name: u.Name}, session, parsed)
	if err != nil {
		s.enrollRefuse(w, v, http.StatusBadRequest, errEnrollVerify, route, reasonVerifyFailed, u.Name, err)
		return
	}
	alg, spki, err := spkiFromCOSE(cred.PublicKey)
	if err != nil {
		s.enrollRefuse(w, v, http.StatusBadRequest, errEnrollUnsupported, route, reasonUnsupportedCredential, u.Name, err)
		return
	}
	if len(cred.ID) == 0 || len(cred.ID) > maxCredentialIDLen {
		s.enrollRefuse(w, v, http.StatusBadRequest, errEnrollUnsupported, route, reasonUnsupportedCredential, u.Name, errors.New("credential ID length out of range"))
		return
	}
	id := base64.RawURLEncoding.EncodeToString(cred.ID)
	pending, err := s.db.PendingCredentialExists(ctx, id)
	if err != nil {
		s.enrollRefuse(w, v, http.StatusInternalServerError, errEnrollInternal, route, reasonInternalError, u.Name, err)
		return
	}
	if pending {
		s.enrollRefuse(w, v, http.StatusConflict, errEnrollDuplicate, route, reasonDuplicateCredential, u.Name, errors.New("credential ID already pending"))
		return
	}
	dir, err := s.installedDirectory(ctx, v)
	if err != nil {
		s.enrollRefuse(w, nil, http.StatusServiceUnavailable, serverclient.APIError{Error: "signer unavailable"}, route, reasonSignerUnavailable, u.Name, err)
		return
	}
	if dir.credIDs[string(cred.ID)] {
		s.enrollRefuse(w, v, http.StatusConflict, errEnrollDuplicate, route, reasonDuplicateCredential, u.Name, errors.New("credential ID in the installed directory"))
		return
	}
	err = s.db.BindPendingCredential(ctx, hash, now.UnixMicro(), serverdb.PendingCredential{
		ID: id, UserName: u.Name, Alg: alg, SPKI: spki,
		BackupEligible: cred.Flags.BackupEligible, BackedUp: cred.Flags.BackupState,
	})
	switch {
	case errors.Is(err, serverdb.ErrInviteNotValid):
		s.enrollRefuse(w, v, http.StatusNotFound, errEnrollInviteNotValid, route, reasonInviteNotValid, u.Name, err)
		return
	case errors.Is(err, serverdb.ErrDuplicateCredential):
		s.enrollRefuse(w, v, http.StatusConflict, errEnrollDuplicate, route, reasonDuplicateCredential, u.Name, err)
		return
	case err != nil:
		s.enrollRefuse(w, v, http.StatusInternalServerError, errEnrollInternal, route, reasonInternalError, u.Name, err)
		return
	}
	fp := webauthn.Fingerprint(spki)
	s.log.Info("passkey registered", "user", u.Name, "algorithm", algName(alg), "fingerprint", fp,
		"backup_eligible", cred.Flags.BackupEligible, "backed_up", cred.Flags.BackupState)
	s.writeJSON(w, v, http.StatusOK, EnrollFinishResponse{Fingerprint: fp, Algorithm: algName(alg), Synced: cred.Flags.BackupState})
}

// readEnrollBody reads the body of a registration request, at most limit
// bytes, before anything else looks at the request (owner hardening H3).
// A declared Content-Length over limit is refused at once; a body without
// one is read through http.MaxBytesReader and refused as soon as it passes
// limit. Both get 413 with nothing written and no session touched.
func (s *Server) readEnrollBody(w http.ResponseWriter, r *http.Request, route string, limit int64) ([]byte, bool) {
	if r.ContentLength > limit {
		s.enrollRefuse(w, nil, http.StatusRequestEntityTooLarge, errEnrollTooLarge, route, reasonBodyTooLarge, "", errors.New("declared body length over the limit"))
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			s.enrollRefuse(w, nil, http.StatusRequestEntityTooLarge, errEnrollTooLarge, route, reasonBodyTooLarge, "", errors.New("body over the limit"))
			return nil, false
		}
		s.enrollRefuse(w, nil, http.StatusBadRequest, errEnrollBadRequest, route, reasonBadRequest, "", err)
		return nil, false
	}
	return body, true
}

// inviteHash returns the SHA-256 of the request's invite token when the
// token has the form of one, so nothing else is hashed and looked up. The
// token itself is never logged.
func inviteHash(r *http.Request) ([]byte, bool) {
	token := r.PathValue("token")
	if !validInviteToken(token) {
		return nil, false
	}
	sum := sha256.Sum256([]byte(token))
	return sum[:], true
}

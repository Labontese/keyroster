package server

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/wire"
)

// The machine renew route's per-client rate (03-11b, b-C2). Its global
// backstop is globalFactor times both.
const (
	machinePerMinute = 30
	machineBurst     = 10
)

// machinePassThrough is every refusal detail of the signer's MachineIssue
// that the route passes to an anonymous caller as is (03-11b, PD2). Each
// reveals nothing about a directory entry, or the signer gives it only
// after the proof of possession has verified:
//   - request_time_skew: the caller's own clock;
//   - machine_issue_no_installation_id, machine_issue_installation_mismatch:
//     installation facts (the trust bundle is public);
//   - machine_pop_not_enabled: the policy, which is public;
//   - directory_not_installed, directory_not_authorized: installation
//     state, nothing per entry;
//   - machine_name_reserved: the request's own text;
//   - after the proof of possession: machine_key_revoked, cert_revoked,
//     machine_disabled, machine_key_unusable,
//     machine_issue_valid_for_not_zero, ca_not_configured, bad_principal,
//     duplicate_request, machine_renew_too_often.
//
// Every other refused detail, the identity details unknown_machine,
// machine_key_mismatch and machine_pop_invalid among them, answers
// machine_not_authenticated (default 1 of 03-11, T-03-397), so a detail the
// signer adds later is hidden until it is listed here with the same
// reasoning (fail closed).
var machinePassThrough = map[string]bool{
	"request_time_skew":                   true,
	"machine_issue_no_installation_id":    true,
	"machine_issue_installation_mismatch": true,
	"machine_pop_not_enabled":             true,
	"directory_not_installed":             true,
	"directory_not_authorized":            true,
	"machine_name_reserved":               true,
	"machine_key_revoked":                 true,
	"cert_revoked":                        true,
	"machine_disabled":                    true,
	"machine_key_unusable":                true,
	"machine_issue_valid_for_not_zero":    true,
	"ca_not_configured":                   true,
	"bad_principal":                       true,
	"duplicate_request":                   true,
	"machine_renew_too_often":             true,
}

// popMachinesEnabled reports whether the installed policy lets machines
// renew by proof of possession (pop.machines, 03-11b).
func popMachinesEnabled(v *statusView) bool {
	return v.policy.PoP != nil && v.policy.PoP.Machines
}

// handleMachineRenew serves POST MachineRenewPath (03-11b, D-15, T-03-73,
// T-03-397): an anonymous machine's renewal of its machine certificate, by
// proof of possession of its key. It is the first anonymous route that
// reaches a signing path. In order:
//  1. the route's own per-client limiter (machineLimit, in newServer's mux);
//  2. the body, at most MaxMachineRenewBody (413), decoded strictly (400
//     malformed_request);
//  3. the cached signer status (503 when it cannot be read, with no
//     MachineIssue call);
//  4. pop.machines in the installed policy, else 403
//     machine_pop_not_enabled and no signer call (a server that lies here
//     can only deny, which it always can; the cache is up to statusTTL
//     old);
//  5. the request parses (400 malformed_request);
//  6. the signer's answer under signerCallTimeout, through the machine
//     share of the budget; a failure is mapped by machineSignerFailed.
//
// Success is 200 with the certificate. The route decides nothing from the
// directory, logs neither the request bytes nor the evidence, and never
// calls dropKRL: a failed signer call says nothing about the KRL.
func (s *Server) handleMachineRenew(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, serverclient.MaxMachineRenewBody))
	if err != nil {
		s.writeJSON(w, nil, http.StatusRequestEntityTooLarge, serverclient.APIError{Error: "request too large"})
		return
	}
	var in serverclient.MachineRenewRequest
	if err := decodeAgentJSON(body, &in); err != nil {
		s.writeJSON(w, nil, http.StatusBadRequest, serverclient.APIError{Error: serverclient.MachineErrMalformed})
		return
	}
	v, err := s.currentStatus(r.Context())
	if err != nil {
		s.signerUnavailable(w, false)
		return
	}
	if !popMachinesEnabled(v) {
		s.writeJSON(w, v, http.StatusForbidden, serverclient.APIError{Error: serverclient.MachineErrPoPNotEnabled})
		return
	}
	req, err := wire.ParseMachineIssueRequest(in.Request)
	if err != nil {
		s.writeJSON(w, v, http.StatusBadRequest, serverclient.APIError{Error: serverclient.MachineErrMalformed})
		return
	}
	client := clientKey(r)
	cctx, cancel := context.WithTimeout(r.Context(), signerCallTimeout)
	resp, err := s.signer.MachineIssue(cctx, req)
	cancel()
	if err != nil {
		s.machineSignerFailed(w, v, req.MachineName, client, err)
		return
	}
	s.log.Info("machine certificate relayed", "machine", req.MachineName, "serial", resp.Serial, "client", client)
	s.writeJSON(w, v, http.StatusOK, serverclient.MachineRenewAnswer{Certificate: resp.Cert})
}

// machineSignerFailed answers a failed MachineIssue call (03-11b, PD2,
// PD4): a refusal whose detail is in machinePassThrough is 403 with that
// detail, every other refusal is 403 machine_not_authenticated; malformed
// unknown_message_type is 403 signer_too_old (a signer older than this
// server); malformed malformed_request and malformed_frame are 400 with
// their own detail, and every other malformed detail is 400
// malformed_request; anything else is 503. The log keeps the specific
// detail. It never calls dropKRL.
func (s *Server) machineSignerFailed(w http.ResponseWriter, v *statusView, name, client string, err error) {
	var refused *wire.ErrorResponse
	if !errors.As(err, &refused) {
		s.log.Warn("machine renew: signer call failed", "machine", name, "client", client, "err", err)
		s.signerUnavailable(w, false)
		return
	}
	s.log.Warn("machine renew refused by the signer", "machine", name, "reason", refused.Message, "client", client)
	switch {
	case refused.Code == wire.CodeRefused && machinePassThrough[refused.Message]:
		s.writeJSON(w, v, http.StatusForbidden, serverclient.APIError{Error: refused.Message})
	case refused.Code == wire.CodeRefused:
		s.writeJSON(w, v, http.StatusForbidden, serverclient.APIError{Error: serverclient.MachineErrNotAuthenticated})
	case refused.Code == wire.CodeMalformed && refused.Message == "unknown_message_type":
		s.writeJSON(w, v, http.StatusForbidden, serverclient.APIError{Error: serverclient.MachineErrSignerTooOld})
	case refused.Code == wire.CodeMalformed && (refused.Message == "malformed_request" || refused.Message == "malformed_frame"):
		s.writeJSON(w, v, http.StatusBadRequest, serverclient.APIError{Error: refused.Message})
	case refused.Code == wire.CodeMalformed:
		s.writeJSON(w, v, http.StatusBadRequest, serverclient.APIError{Error: serverclient.MachineErrMalformed})
	default:
		s.signerUnavailable(w, false)
	}
}

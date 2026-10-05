package signer

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// Default refusal-logging rate (D-14): individual refusal leaves per minute
// and the burst allowed at once.
const (
	DefaultRefusalLogPerMinute = 10
	DefaultRefusalLogBurst     = 10
)

// summaryInterval is how often pending refusal counts become a
// refusal_summary leaf.
const summaryInterval = time.Minute

// refusalLimiter is a token bucket on the signer's clock. Refusals within
// the rate become individual refusal leaves; the rest are counted per
// reason and written as one refusal_summary leaf per window, so that
// logged plus summarized refusals always equal all refusals. Guarded by
// Signer.mu.
type refusalLimiter struct {
	perMinute   int
	burst       int
	tokens      float64
	last        time.Time
	counts      map[uint8]uint64
	windowStart time.Time
}

func newRefusalLimiter(perMinute, burst int, now time.Time) *refusalLimiter {
	return &refusalLimiter{
		perMinute: perMinute, burst: burst, tokens: float64(burst), last: now,
		counts: map[uint8]uint64{}, windowStart: now,
	}
}

// allow takes one token if one is available at now.
func (l *refusalLimiter) allow(now time.Time) bool {
	if elapsed := now.Sub(l.last); elapsed > 0 {
		l.tokens = min(float64(l.burst), l.tokens+elapsed.Minutes()*float64(l.perMinute))
		l.last = now
	}
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// refuse records one refusal and returns the response for the peer. Every
// refusal is logged through slog. Within the rate it is appended to the
// Merkle log as a refusal leaf (in its own transaction); above the rate, or
// if that append fails, it is counted toward the next refusal_summary leaf
// instead, so no refusal is dropped from the audit trail (D-14). digest is
// zero when the request was never decoded.
func (s *Signer) refuse(ctx context.Context, peer Peer, digest [32]byte, reason uint8, detail string) *wire.ErrorResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log.Warn("refused", "uid", peer.UID, "pid", peer.PID, "reason", detail,
		"class", tlog.ReasonName(reason), "code", codeFor(reason).String())
	resp := &wire.ErrorResponse{Code: codeFor(reason), Message: detail}
	now := s.clock()
	if !s.limiter.allow(now) {
		s.limiter.counts[reason]++
		return resp
	}
	body, err := (&tlog.RefusalBody{RequestDigest: digest, PeerUID: peer.UID, Reason: reason, Detail: detail}).Encode()
	if err == nil {
		err = s.logTx(ctx, func(tx *sql.Tx) error {
			_, err := s.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindRefusal, Body: body})
			return err
		})
	}
	if err != nil {
		s.limiter.counts[reason]++
		s.log.Error("refusal not logged individually; counted for the next summary", "error", err.Error())
	}
	return resp
}

// flushSummaries appends one refusal_summary leaf for the refusals counted
// since the window started, if any, and starts a new window. On failure
// the counts are kept for the next flush.
func (s *Signer) flushSummaries(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	l := s.limiter
	if len(l.counts) == 0 {
		l.windowStart = now
		return
	}
	reasons := make([]uint8, 0, len(l.counts))
	for r := range l.counts {
		reasons = append(reasons, r)
	}
	slices.Sort(reasons)
	sum := &tlog.RefusalSummaryBody{WindowStartMicros: micros(l.windowStart), WindowEndMicros: micros(now)}
	sum.WindowEndMicros = max(sum.WindowEndMicros, sum.WindowStartMicros)
	for _, r := range reasons {
		sum.Counts = append(sum.Counts, tlog.ReasonCount{Reason: r, Count: l.counts[r]})
	}
	body, err := sum.Encode()
	if err == nil {
		err = s.logTx(ctx, func(tx *sql.Tx) error {
			_, err := s.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindRefusalSummary, Body: body})
			return err
		})
	}
	if err != nil {
		s.log.Error("refusal summary not logged; counts kept for the next flush", "error", err.Error())
		return
	}
	s.log.Info("refusal summary logged", "refusals", sum.Total())
	clear(l.counts)
	l.windowStart = now
}

// flushLoop flushes the refusal counts every summaryInterval until ctx is
// done.
func (s *Signer) flushLoop(ctx context.Context) {
	t := time.NewTicker(summaryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.flushSummaries(ctx)
		}
	}
}

// issueOrRefuse runs Issue and records a refusal through refuse.
func (s *Signer) issueOrRefuse(ctx context.Context, peer Peer, req *wire.IssueRequest) (*wire.IssueResponse, *wire.ErrorResponse) {
	resp, err := s.Issue(ctx, peer, req)
	if err == nil {
		return resp, nil
	}
	var digest [32]byte
	if req != nil {
		digest = req.Digest()
	}
	return nil, s.refuseErr(ctx, peer, digest, err)
}

// refuseErr records err (a *refusal, or any other error as internal_error)
// through refuse.
func (s *Signer) refuseErr(ctx context.Context, peer Peer, digest [32]byte, err error) *wire.ErrorResponse {
	var r *refusal
	if !errors.As(err, &r) {
		r = &refusal{code: wire.CodeInternal, reason: "internal_error", cause: err}
	}
	return s.refuse(ctx, peer, digest, classify(r.reason), r.reason)
}

// classify maps a signer reason string to its refusal reason class.
func classify(detail string) uint8 {
	switch detail {
	case "peer_not_allowed", "peer_credentials_unavailable":
		return tlog.ReasonPeerNotAllowed
	case "malformed_frame", "unknown_message_type", "malformed_request":
		return tlog.ReasonMalformed
	case "ca_not_configured":
		return tlog.ReasonCANotConfigured
	case "bad_principal", "empty_principals":
		return tlog.ReasonBadPrincipal
	case "bad_subject_key":
		return tlog.ReasonBadSubjectKey
	case "bad_validity":
		return tlog.ReasonTTLExceeded
	case "request_time_skew":
		return tlog.ReasonStaleRequest
	case "duplicate_request":
		return tlog.ReasonDuplicateRequest
	case "clock_regression":
		return tlog.ReasonClockRegression
	case "bad_subject":
		return tlog.ReasonBadSubject
	case "extension_not_allowed":
		return tlog.ReasonExtensionNotAllowed
	case "state_unavailable", "serial_unavailable":
		return tlog.ReasonUnavailable
	case "too_many_connections":
		return tlog.ReasonOverloaded
	default:
		return tlog.ReasonInternal
	}
}

// codeFor returns the wire error code sent for a reason class.
func codeFor(reason uint8) wire.ErrorCode {
	switch reason {
	case tlog.ReasonMalformed:
		return wire.CodeMalformed
	case tlog.ReasonClockRegression, tlog.ReasonUnavailable, tlog.ReasonOverloaded:
		return wire.CodeUnavailable
	case tlog.ReasonInternal:
		return wire.CodeInternal
	default:
		return wire.CodeRefused
	}
}

// micros returns t in microseconds since the epoch, 0 before it.
func micros(t time.Time) uint64 {
	us := t.UnixMicro()
	if us < 0 {
		return 0
	}
	return uint64(us) //nolint:gosec // G115: us >= 0, checked above
}

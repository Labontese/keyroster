//go:build linux

package fetch

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/hostcert"
	"github.com/Labontese/keyroster/internal/agent/probe"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// outboxProbeCert is one probe certificate request in the outbox
// (03-10b): its polarity, request ID and ProbeIssueRequest bytes.
type outboxProbeCert struct {
	polarity  probe.Polarity
	requestID string
	body      []byte
}

// readOutboxProbeCerts reads the outbox's probecert-<polarity>.req files,
// sorted by name, each at most hostcert.MaxOutboxRequest bytes; one that
// does not parse is skipped.
func readOutboxProbeCerts(dir string) ([]outboxProbeCert, error) {
	fd, err := spool.OpenDir(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	names, err := spool.ListDir(fd)
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	var out []outboxProbeCert
	for _, n := range names {
		m := probe.RequestFileRE.FindStringSubmatch(n)
		if m == nil {
			continue
		}
		b, err := spool.ReadFileAt(fd, n, hostcert.MaxOutboxRequest)
		if err != nil {
			continue
		}
		r, err := hostcert.ParseOutboxRequest(b)
		if err != nil {
			continue
		}
		req, err := wire.ParseProbeIssueRequest(r.Request)
		if err != nil {
			continue
		}
		out = append(out, outboxProbeCert{polarity: probe.Polarity(m[1]), requestID: hex.EncodeToString(req.RequestID[:]), body: r.Request})
	}
	return out, nil
}

// pruneProbeCertAnswers removes every probe answer whose request ID the
// outbox no longer holds for its polarity (the applier consumed or
// abandoned it); the applier never deletes in the spool.
func pruneProbeCertAnswers(spoolDir string, reqs []outboxProbeCert) []string {
	fd, err := spool.OpenDir(spoolDir)
	if err != nil {
		return nil
	}
	defer func() { _ = unix.Close(fd) }()
	names, err := spool.ListDir(fd)
	if err != nil {
		return nil
	}
	held := map[string]string{}
	for _, r := range reqs {
		held[string(r.polarity)] = r.requestID
	}
	var removed []string
	for _, n := range names {
		m := probe.AnswerFileRE.FindStringSubmatch(n)
		if m == nil {
			continue
		}
		if id, ok := held[m[1]]; ok && answerID(fd, n) == id {
			continue
		}
		if err := unix.Unlinkat(fd, n, 0); err == nil {
			removed = append(removed, n)
		}
	}
	return removed
}

// postProbeCerts posts each outbox probe certificate request (03-10b), one
// at a time, that has no answer in the spool yet, and writes what the
// server answers as probecert-<polarity>.answer (mode 0644), with
// postHostCerts's mapping: 200 the certificate; 403 with a detail in the
// refusal grammar that refusal; any 429 ends this poll's probe posts and
// writes nothing; a 5xx or a transport error writes nothing (the applier
// abandons the request as no_answer); any other 4xx, or a 403 without such
// a detail, http_<status>.
func (f *Fetcher) postProbeCerts(ctx context.Context) error {
	reqs, err := readOutboxProbeCerts(f.cfg.Outbox)
	if err != nil {
		return nil
	}
	if pruned := pruneProbeCertAnswers(f.cfg.Spool, reqs); len(pruned) > 0 {
		f.logf("removed %d probe certificate answers the applier no longer waits for", len(pruned))
	}
	for _, r := range reqs {
		if f.probeAnswered(r) {
			continue
		}
		ans, err := f.client.AgentProbeCert(ctx, &serverclient.AgentProbeCertRequest{Request: r.body})
		out := hostcert.Answer{RequestID: r.requestID}
		var he *serverclient.HTTPError
		switch {
		case err == nil:
			out.Certificate = ans.Certificate
		case errors.As(err, &he) && he.Code == http.StatusTooManyRequests:
			f.logf("the server is rate limiting probe certificate requests; continuing at the next poll")
			return nil
		case errors.As(err, &he) && he.Code >= 500:
			f.logf("WARNING %s probe certificate request: %v; it goes again at the next poll", r.polarity, err)
			continue
		case errors.As(err, &he) && he.Code == http.StatusForbidden && hostcert.DetailRE.MatchString(he.Detail()):
			out.Refused = he.Detail()
		case errors.As(err, &he) && he.Code >= 400 && he.Code < 500:
			out.Refused = "http_" + strconv.Itoa(he.Code)
		default:
			f.logf("WARNING %s probe certificate request: %v; it goes again at the next poll", r.polarity, err)
			continue
		}
		if err := writeProbeCertAnswer(f.cfg.Spool, r.polarity, out); err != nil {
			return fmt.Errorf("probe certificate answer: %w", err)
		}
	}
	return nil
}

// probeAnswered reports whether the spool already holds an answer for r.
func (f *Fetcher) probeAnswered(r outboxProbeCert) bool {
	fd, err := spool.OpenDir(f.cfg.Spool)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(fd) }()
	return answerID(fd, probe.AnswerFileName(r.polarity)) == r.requestID
}

// writeProbeCertAnswer writes polarity pol's answer into the spool, mode
// 0644; a certificate the applier would not read (above
// hostcert.MaxAnswer) is answered as the refusal answer_too_large.
func writeProbeCertAnswer(dir string, pol probe.Polarity, a hostcert.Answer) error {
	b, err := trust.CanonicalJSON(a)
	if err != nil {
		return err
	}
	if len(b) > hostcert.MaxAnswer {
		if b, err = trust.CanonicalJSON(hostcert.Answer{RequestID: a.RequestID, Refused: "answer_too_large"}); err != nil {
			return err
		}
	}
	fd, err := spool.OpenDir(dir)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return spool.WriteFileAt(fd, probe.AnswerFileName(pol), b, 0o644)
}

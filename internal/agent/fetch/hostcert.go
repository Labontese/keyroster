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
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// outboxHostCert is one host certificate request in the outbox (03-09):
// its key, request ID and HostIssueRequest bytes.
type outboxHostCert struct {
	key       string
	requestID string
	body      []byte
}

// readOutboxHostCerts reads the outbox's hostcert-<k>.req files, sorted by
// name, each at most hostcert.MaxOutboxRequest bytes; one that does not
// parse is skipped.
func readOutboxHostCerts(dir string) ([]outboxHostCert, error) {
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
	var out []outboxHostCert
	for _, n := range names {
		m := hostcert.RequestFileRE.FindStringSubmatch(n)
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
		req, err := wire.ParseHostIssueRequest(r.Request)
		if err != nil {
			continue
		}
		out = append(out, outboxHostCert{key: m[1], requestID: hex.EncodeToString(req.RequestID[:]), body: r.Request})
	}
	return out, nil
}

// pruneHostCertAnswers removes every spool answer whose request ID the
// outbox no longer holds for its key: the applier consumed it (it removes
// the outbox request then) or abandoned it. The applier never deletes in
// the spool (03-09).
func pruneHostCertAnswers(spoolDir string, reqs []outboxHostCert) []string {
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
		held[r.key] = r.requestID
	}
	var removed []string
	for _, n := range names {
		m := hostcert.AnswerFileRE.FindStringSubmatch(n)
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

// answerID is the request ID of the spool answer name, "" when it does
// not parse.
func answerID(fd int, name string) string {
	b, err := spool.ReadFileAt(fd, name, hostcert.MaxAnswer)
	if err != nil {
		return ""
	}
	a, err := hostcert.ParseAnswer(b)
	if err != nil {
		return ""
	}
	return a.RequestID
}

// postHostCerts posts each outbox host certificate request (03-09), one at
// a time, that has no answer in the spool yet, and writes what the server
// answers as hostcert-<k>.answer (mode 0644):
//   - 200: the certificate;
//   - 403 with a detail in the refusal grammar: that refusal;
//   - any 429, any 5xx or a transport error: nothing (the same request goes
//     again at the next poll; the applier abandons it after 330 s as a
//     transient failure, Q-09-7); a 429 also ends this poll's posts;
//   - any other 4xx, or a 403 without such a detail: http_<status>, which
//     the applier holds as a sticky refusal.
//
// Answers whose request the outbox no longer holds are removed first.
func (f *Fetcher) postHostCerts(ctx context.Context) error {
	reqs, err := readOutboxHostCerts(f.cfg.Outbox)
	if err != nil {
		return nil
	}
	if pruned := pruneHostCertAnswers(f.cfg.Spool, reqs); len(pruned) > 0 {
		f.logf("removed %d host certificate answers the applier no longer waits for", len(pruned))
	}
	for _, r := range reqs {
		if f.answered(r) {
			continue
		}
		ans, err := f.client.AgentHostCert(ctx, &serverclient.AgentHostCertRequest{Request: r.body})
		out := hostcert.Answer{RequestID: r.requestID}
		var he *serverclient.HTTPError
		switch {
		case err == nil:
			out.Certificate = ans.Certificate
		case errors.As(err, &he) && he.Code == http.StatusTooManyRequests:
			f.logf("the server is rate limiting host certificate requests; continuing at the next poll")
			return nil
		case errors.As(err, &he) && he.Code >= 500:
			f.logf("WARNING host certificate request for key %s: %v; it goes again at the next poll", r.key[:16], err)
			continue
		case errors.As(err, &he) && he.Code == http.StatusForbidden && hostcert.DetailRE.MatchString(he.Detail()):
			out.Refused = he.Detail()
		case errors.As(err, &he) && he.Code >= 400 && he.Code < 500:
			out.Refused = "http_" + strconv.Itoa(he.Code)
		default:
			f.logf("WARNING host certificate request for key %s: %v; it goes again at the next poll", r.key[:16], err)
			continue
		}
		if err := writeHostCertAnswer(f.cfg.Spool, r.key, out); err != nil {
			return fmt.Errorf("host certificate answer: %w", err)
		}
	}
	return nil
}

// answered reports whether the spool already holds an answer for r.
func (f *Fetcher) answered(r outboxHostCert) bool {
	fd, err := spool.OpenDir(f.cfg.Spool)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(fd) }()
	return answerID(fd, hostcert.AnswerFileName(r.key)) == r.requestID
}

// writeHostCertAnswer writes key k's answer into the spool, mode 0644, so
// the applier (root, no capabilities) reads it (agent-10).
func writeHostCertAnswer(dir, k string, a hostcert.Answer) error {
	b, err := trust.CanonicalJSON(a)
	if err != nil {
		return err
	}
	fd, err := spool.OpenDir(dir)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return spool.WriteFileAt(fd, hostcert.AnswerFileName(k), b, 0o644)
}

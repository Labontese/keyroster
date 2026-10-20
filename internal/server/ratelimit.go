package server

import (
	"container/list"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/Labontese/keyroster/internal/serverclient"
)

// Limits are the per-client rate limits of the admin and invite routes.
// A zero field takes its default. Each route class also has one global
// limiter at globalFactor times its per-client rate and burst.
//
// The limits are best-effort damping of floods only. Authenticity rests
// on SSHSIG with single-use nonces (admin routes) and on 256-bit hashed
// invite tokens (T-02-36).
type Limits struct {
	AdminPerMinute  int // default 60
	AdminBurst      int // default 20
	InvitePerMinute int // default 30
	InviteBurst     int // default 10
}

// Default limits.
const (
	defaultAdminPerMinute  = 60
	defaultAdminBurst      = 20
	defaultInvitePerMinute = 30
	defaultInviteBurst     = 10
)

const (
	// globalFactor is the global limiter's rate and burst over the
	// per-client ones.
	globalFactor = 10
	// maxLimiterEntries bounds the per-client limiter map; the least
	// recently used client is evicted first.
	maxLimiterEntries = 10000
	// limiterIdle is how long a client's limiter is kept unused. It is
	// far above the time a bucket needs to refill, so an evicted client
	// comes back to the same full bucket it would have had.
	limiterIdle = 10 * time.Minute
)

func (l Limits) withDefaults() Limits {
	if l.AdminPerMinute <= 0 {
		l.AdminPerMinute = defaultAdminPerMinute
	}
	if l.AdminBurst <= 0 {
		l.AdminBurst = defaultAdminBurst
	}
	if l.InvitePerMinute <= 0 {
		l.InvitePerMinute = defaultInvitePerMinute
	}
	if l.InviteBurst <= 0 {
		l.InviteBurst = defaultInviteBurst
	}
	return l
}

// limiter is the rate limit of one route class: a token bucket per client
// key, kept in an LRU-bounded map, and one global bucket as a coarse
// backstop. It is safe for concurrent use.
type limiter struct {
	perMinute int
	burst     int
	max       int

	mu      sync.Mutex
	global  *rate.Limiter
	entries map[string]*list.Element // of *limiterEntry
	lru     *list.List               // most recently used at the front
}

type limiterEntry struct {
	key  string
	lim  *rate.Limiter
	last time.Time
}

func newLimiter(perMinute, burst, globalPerMinute, globalBurst int) *limiter {
	return &limiter{
		perMinute: perMinute,
		burst:     burst,
		max:       maxLimiterEntries,
		global:    rate.NewLimiter(perMinuteRate(globalPerMinute), globalBurst),
		entries:   map[string]*list.Element{},
		lru:       list.New(),
	}
}

func perMinuteRate(n int) rate.Limit { return rate.Limit(float64(n) / 60) }

// allow reports whether one request from client key at now passes both
// the client's bucket and the global one.
func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Idle entries first, oldest at the back.
	for e := l.lru.Back(); e != nil; e = l.lru.Back() {
		le := e.Value.(*limiterEntry)
		if now.Sub(le.last) < limiterIdle {
			break
		}
		l.remove(e)
	}
	e, ok := l.entries[key]
	if !ok {
		for l.lru.Len() >= l.max {
			l.remove(l.lru.Back())
		}
		e = l.lru.PushFront(&limiterEntry{key: key, lim: rate.NewLimiter(perMinuteRate(l.perMinute), l.burst)})
		l.entries[key] = e
	} else {
		l.lru.MoveToFront(e)
	}
	le := e.Value.(*limiterEntry)
	le.last = now
	if !le.lim.AllowN(now, 1) {
		return false
	}
	return l.global.AllowN(now, 1)
}

func (l *limiter) remove(e *list.Element) {
	le := e.Value.(*limiterEntry)
	delete(l.entries, le.key)
	l.lru.Remove(e)
}

// size returns the number of per-client entries.
func (l *limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// retryAfter is the Retry-After value of a refused request: the seconds
// one token takes to come back, rounded up.
func (l *limiter) retryAfter() int { return (60 + l.perMinute - 1) / l.perMinute }

// clientKey is the rate-limit key of r: the host of r.RemoteAddr only.
// X-Forwarded-For and Forwarded are never read: no proxy stands in front
// of keyroster-server, so those headers are whatever the client wrote. An
// IPv4 address (or an IPv4-mapped IPv6 one) is its own key; any other IPv6
// address is keyed by its /64, so one host rotating addresses inside its
// /64 shares one bucket.
func clientKey(r *http.Request) string {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	a := ap.Addr().Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	p, err := a.Prefix(64)
	if err != nil {
		return a.String()
	}
	return p.String()
}

// rateLimited applies l to next. A refused request gets 429 with
// Retry-After, as JSON or, for a page (html), the error page.
func (s *Server) rateLimited(l *limiter, html bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := clientKey(r)
		if l.allow(key, s.clock()) {
			next.ServeHTTP(w, r)
			return
		}
		// The route pattern, never the request URL: an invite URL holds
		// its token.
		s.log.Warn("rate limited", "route", r.Pattern, "client", key)
		w.Header().Set("Retry-After", strconv.Itoa(l.retryAfter()))
		if html {
			s.renderPage(w, nil, http.StatusTooManyRequests, "error", pageData{
				Title:   "Too many requests",
				Message: "Too many requests from your address. Wait a moment and try again.",
			})
			return
		}
		s.writeJSON(w, nil, http.StatusTooManyRequests, serverclient.APIError{Error: "rate limited"})
	})
}

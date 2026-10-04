// Package serial allocates certificate serial numbers from a clock floor
// (CA-03): serial = max(last+1, now in microseconds), never ahead of the
// clock. After a restore of an older database the stale high-water mark is
// overtaken by the clock, so a serial is never issued twice; a clock that
// runs behind the high-water mark fails closed.
package serial

import (
	"errors"
	"math"
	"time"
)

// Clock returns the current time.
type Clock func() time.Time

// ErrClockRegression means the clock is behind the last issued serial: the
// clock went backwards, or the state was restored together with an older
// clock. Issuance must stop until an admin resolves it.
var ErrClockRegression = errors.New("serial: clock is behind the last issued serial")

// ErrClockStalled means the clock did not reach the allocated serial within
// the wait budget.
var ErrClockStalled = errors.New("serial: clock did not advance")

// maxWaits bounds how often Next sleeps for the clock to catch up. A healthy
// clock needs at most one or two microsecond waits.
const maxWaits = 1000

// maxStepMicros caps a single wait.
const maxStepMicros = 1000

// Next returns the serial after last. It fails with ErrClockRegression when
// now is below last, and otherwise waits (through sleep) until the clock has
// reached the returned serial, so that serial <= issuance time in
// microseconds always holds.
func Next(last uint64, now Clock, sleep func(time.Duration)) (uint64, error) {
	if last == math.MaxUint64 {
		return 0, errors.New("serial: serial space exhausted")
	}
	n, err := micros(now())
	if err != nil {
		return 0, err
	}
	if n < last {
		return 0, ErrClockRegression
	}
	next := max(last+1, n)
	for range maxWaits {
		cur, err := micros(now())
		if err != nil {
			return 0, err
		}
		if cur < last {
			return 0, ErrClockRegression
		}
		if cur >= next {
			return next, nil
		}
		// Normally next-cur is 1 (two issuances in one microsecond). A
		// larger gap means the wall clock stepped back between the two
		// reads; wait in bounded steps and let maxWaits end it.
		sleep(time.Duration(min(next-cur, maxStepMicros)) * time.Microsecond) //nolint:gosec // G115: bounded by maxStepMicros
	}
	return 0, ErrClockStalled
}

func micros(t time.Time) (uint64, error) {
	us := t.UnixMicro()
	if us <= 0 {
		return 0, ErrClockRegression
	}
	return uint64(us), nil //nolint:gosec // G115: us > 0, checked above
}

package serial

import (
	"errors"
	"testing"
	"time"
)

// fakeClock is a manual clock whose sleep advances it.
type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
	frozen bool // sleep does not advance the clock
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Sleep(d time.Duration) {
	c.sleeps = append(c.sleeps, d)
	if !c.frozen {
		c.now = c.now.Add(d)
	}
}

func us(t time.Time) uint64 { return uint64(t.UnixMicro()) } //nolint:gosec // G115: test times are after 1970

func TestNext(t *testing.T) {
	base := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		last       uint64
		now        time.Time
		frozen     bool
		want       uint64
		wantErr    error
		wantSleeps int
	}{
		{name: "fresh_db_now_micros", last: 0, now: base, want: us(base)},
		{name: "clock_ahead_of_last", last: us(base) - 1000, now: base, want: us(base)},
		{name: "same_microsecond", last: us(base), now: base, want: us(base) + 1, wantSleeps: 1},
		{name: "clock_regression", last: us(base) + 1, now: base, wantErr: ErrClockRegression},
		{name: "clock_regression_far", last: us(base.Add(time.Hour)), now: base, wantErr: ErrClockRegression},
		{name: "epoch_zero_clock", last: 0, now: time.Unix(0, 0), wantErr: ErrClockRegression},
		{name: "pre_epoch_clock", last: 0, now: time.Unix(-5, 0), wantErr: ErrClockRegression},
		{name: "clock_stalled", last: us(base), now: base, frozen: true, wantErr: ErrClockStalled, wantSleeps: maxWaits},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk := &fakeClock{now: tc.now, frozen: tc.frozen}
			got, err := Next(tc.last, clk.Now, clk.Sleep)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Next = %d, %v; want %v", got, err, tc.wantErr)
				}
				if got != 0 {
					t.Fatalf("Next returned serial %d with an error", got)
				}
			} else {
				if err != nil {
					t.Fatalf("Next: %v", err)
				}
				if got != tc.want {
					t.Fatalf("Next = %d, want %d", got, tc.want)
				}
				if got == 0 || got <= tc.last {
					t.Fatalf("serial %d is 0 or not above last %d", got, tc.last)
				}
				if cur := us(clk.now); got > cur {
					t.Fatalf("serial %d is ahead of the clock %d", got, cur)
				}
			}
			if len(clk.sleeps) != tc.wantSleeps {
				t.Fatalf("slept %d times (%v), want %d", len(clk.sleeps), clk.sleeps, tc.wantSleeps)
			}
		})
	}
}

// Successive issuances in one fake microsecond get last+1, last+2, ...,
// each after the clock has reached it.
func TestNextAdjacentSerials(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	last := uint64(0)
	first := uint64(0)
	for i := range 5 {
		got, err := Next(last, clk.Now, clk.Sleep)
		if err != nil {
			t.Fatalf("issuance %d: %v", i, err)
		}
		if i == 0 {
			first = got
		}
		if want := first + uint64(i); got != want { //nolint:gosec // G115: i is small and non-negative
			t.Fatalf("issuance %d: serial %d, want %d", i, got, want)
		}
		if got > us(clk.now) {
			t.Fatalf("serial %d ahead of the clock %d", got, us(clk.now))
		}
		last = got
	}
}

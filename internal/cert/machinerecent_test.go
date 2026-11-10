package cert

import (
	"slices"
	"testing"
	"time"
)

// TestMachineLifetime: the lifetime is the smaller of the grant's TTL and
// the profile's cap, in whole seconds (03-11, PD6).
func TestMachineLifetime(t *testing.T) {
	prof := func(d time.Duration) Profile { return Profile{MaxTTL: d} }
	for name, tc := range map[string]struct {
		grant uint64
		cap   time.Duration
		want  uint64
	}{
		"entry_smallest":       {grant: 3600, cap: 24 * time.Hour, want: 3600},
		"role_smallest":        {grant: 1800, cap: 2 * time.Hour, want: 1800},
		"profile_cap_smallest": {grant: 86400, cap: 2 * time.Hour, want: 7200},
		"equal_values":         {grant: 7200, cap: 2*time.Hour + 500*time.Millisecond, want: 7200},
	} {
		t.Run(name, func(t *testing.T) {
			if got := MachineLifetime(tc.grant, prof(tc.cap)); got != tc.want {
				t.Fatalf("MachineLifetime(%d, %s) = %d, want %d", tc.grant, tc.cap, got, tc.want)
			}
		})
	}
}

// TestMachineRecentAdd: the one list rule of the bound (03-11, PD4).
func TestMachineRecentAdd(t *testing.T) {
	t.Run("prunes_seconds_an_hour_below_the_largest", func(t *testing.T) {
		got := MachineRecentAdd([]uint64{1000, 1001, 2000}, 4601)
		if !slices.Equal(got, []uint64{2000, 4601}) {
			t.Fatalf("got %v, want [2000 4601] (1001 is exactly 3600 below 4601)", got)
		}
	})
	t.Run("keeps_the_twelve_largest_by_value", func(t *testing.T) {
		var recent []uint64
		// Fifteen seconds in, in a scrambled order, all within the hour.
		for _, s := range []uint64{105, 101, 114, 103, 110, 102, 113, 104, 111, 100, 112, 106, 109, 107, 108} {
			recent = MachineRecentAdd(recent, s)
		}
		want := []uint64{103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114}
		if !slices.Equal(recent, want) {
			t.Fatalf("got %v, want %v", recent, want)
		}
	})
	t.Run("clock_step_back_keeps_values", func(t *testing.T) {
		a := MachineRecentAdd(MachineRecentAdd(nil, 10000), 10500)
		got := MachineRecentAdd(a, 9000) // 1500 s below the largest: kept
		if !slices.Equal(got, []uint64{9000, 10000, 10500}) {
			t.Fatalf("got %v", got)
		}
		if old := MachineRecentAdd(a, 6900); !slices.Equal(old, []uint64{10000, 10500}) { // 3600 below: dropped
			t.Fatalf("a second an hour below the largest is kept: %v", old)
		}
		b := MachineRecentAdd(MachineRecentAdd(MachineRecentAdd(nil, 10000), 10500), 9000)
		if !slices.Equal(got, b) {
			t.Fatal("the result depends on the caller")
		}
	})
	t.Run("does_not_alias_the_input", func(t *testing.T) {
		backing := [16]uint64{5, 6, 7}
		out := MachineRecentAdd(backing[:3], 8)
		out[0] = 99
		if backing[0] != 5 || backing[3] != 0 || !slices.Equal(out, []uint64{99, 6, 7, 8}) {
			t.Fatalf("the input was written: %v (out %v)", backing[:4], out)
		}
	})
}

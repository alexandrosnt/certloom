package window

import (
	"testing"
	"time"
)

func at(t *testing.T, zone, s string) time.Time {
	t.Helper()
	loc, err := time.LoadLocation(zone)
	if err != nil {
		t.Fatal(err)
	}
	v, err := time.ParseInLocation("2006-01-02 15:04", s, loc)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestParseErrors(t *testing.T) {
	for _, s := range []string{"", "Mon-Fri 02:00-05:00", "Funday 02:00-05:00 UTC", "Mon 2-5 UTC", "Mon 02:00-02:00 UTC",
		"Mon 25:00-02:00 UTC", "Mon 02:00-05:00 Mars/Olympus", "Mon,,Tue 02:00-03:00 UTC"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) should fail", s)
		}
	}
}

func TestContainsAndNext(t *testing.T) {
	cases := []struct {
		spec, zone, now string
		in              bool
		next            string // in the window's zone; empty when in
	}{
		// Plain weekday window.
		{"Mon-Fri 02:00-05:00 Europe/Athens", "Europe/Athens", "2026-11-23 03:00", true, ""}, // Monday
		{"Mon-Fri 02:00-05:00 Europe/Athens", "Europe/Athens", "2026-11-23 05:00", false, "2026-11-24 02:00"},
		{"Mon-Fri 02:00-05:00 Europe/Athens", "Europe/Athens", "2026-11-21 12:00", false, "2026-11-23 02:00"}, // Saturday
		// Crossing midnight belongs to the start day.
		{"Sat 22:00-02:00 UTC", "UTC", "2026-11-22 01:30", true, ""}, // Sunday early morning
		{"Sat 22:00-02:00 UTC", "UTC", "2026-11-22 02:00", false, "2026-11-28 22:00"},
		// Wrapping day range.
		{"Fri-Mon 01:00-02:00 UTC", "UTC", "2026-11-24 01:30", false, "2026-11-27 01:00"}, // Tuesday
		{"daily 23:00-24:00 UTC", "UTC", "2026-11-24 23:59", true, ""},
		// Athens spring forward: 03:00 -> 04:00 on 2026-03-29. A 03:30 start
		// does not exist and moves forward by the gap.
		{"Sun 03:30-05:00 Europe/Athens", "Europe/Athens", "2026-03-29 02:00", false, "2026-03-29 04:30"},
		// Athens fall back: 04:00 -> 03:00 on 2026-10-25; the window is
		// 03:00-05:00 wall clock, i.e. three real hours that night.
		{"Sun 03:00-05:00 Europe/Athens", "Europe/Athens", "2026-10-25 04:30", true, ""},
		// New York spring forward: 02:00 -> 03:00 on 2026-03-08.
		{"Sun 01:00-04:00 America/New_York", "America/New_York", "2026-03-08 03:30", true, ""},
		{"Sun 02:15-02:45 America/New_York", "America/New_York", "2026-03-08 00:00", false, "2026-03-08 03:15"},
		// New York fall back: 02:00 -> 01:00 on 2026-11-01.
		{"Sun 01:00-02:00 America/New_York", "America/New_York", "2026-11-01 00:30", false, "2026-11-01 01:00"},
	}
	for _, c := range cases {
		w, err := Parse(c.spec)
		if err != nil {
			t.Fatal(err)
		}
		now := at(t, c.zone, c.now)
		if got := w.Contains(now); got != c.in {
			t.Errorf("%s at %s: Contains = %v, want %v", c.spec, c.now, got, c.in)
		}
		next := w.Next(now)
		if c.in {
			if !next.Equal(now) {
				t.Errorf("%s at %s: Next = %s, want now", c.spec, c.now, next)
			}
			continue
		}
		if want := at(t, c.zone, c.next); !next.Equal(want) {
			t.Errorf("%s at %s: Next = %s, want %s", c.spec, c.now, next.In(want.Location()), want)
		}
	}
}

func TestFallBackHourIsCoveredOnce(t *testing.T) {
	// 01:00-02:00 New York on the fall-back night spans two real hours
	// (01:00 EDT .. 02:00 EST); both 01:30s are inside.
	w, _ := Parse("Sun 01:00-02:00 America/New_York")
	first := time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC)  // 01:30 EDT
	second := time.Date(2026, 11, 1, 6, 30, 0, 0, time.UTC) // 01:30 EST
	if !w.Contains(first) || !w.Contains(second) {
		t.Fatalf("both 01:30s should be inside: %v %v", w.Contains(first), w.Contains(second))
	}
	if w.Contains(time.Date(2026, 11, 1, 7, 0, 0, 0, time.UTC)) { // 02:00 EST
		t.Fatal("02:00 EST is the end")
	}
}

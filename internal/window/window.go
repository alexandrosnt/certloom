// Package window evaluates weekly maintenance windows such as
// "Mon-Fri 02:00-05:00 Europe/Athens".
//
// A window belongs to the day it starts on; "Sat 22:00-02:00 UTC" runs from
// Saturday 22:00 to Sunday 02:00. Wall-clock times are interpreted in the
// window's IANA zone using the tz database embedded in the binary, so the
// result does not depend on the host's zone files. Across DST changes a
// window keeps its wall-clock times: a start inside a skipped hour moves
// forward by the gap.
package window

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // embedded zone database
)

// Window is a parsed weekly window.
type Window struct {
	days       [7]bool // indexed by time.Weekday
	start, end int     // minutes after midnight; end <= start means it ends the next day
	loc        *time.Location
	spec       string
}

var dayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// Parse reads "<days> <HH:MM>-<HH:MM> <zone>". Days are a comma-separated
// list of names or ranges (Mon-Fri, Sat,Sun, Fri-Mon) or "daily".
func Parse(spec string) (*Window, error) {
	f := strings.Fields(spec)
	if len(f) != 3 {
		return nil, fmt.Errorf("maintenance window %q: want \"<days> <HH:MM>-<HH:MM> <IANA zone>\", e.g. \"Mon-Fri 02:00-05:00 Europe/Athens\"", spec)
	}
	w := &Window{spec: strings.Join(f, " ")}
	if err := w.parseDays(f[0]); err != nil {
		return nil, fmt.Errorf("maintenance window %q: %w", spec, err)
	}
	from, to, ok := strings.Cut(f[1], "-")
	if !ok {
		return nil, fmt.Errorf("maintenance window %q: time range must look like 02:00-05:00", spec)
	}
	var err error
	if w.start, err = clock(from); err != nil {
		return nil, fmt.Errorf("maintenance window %q: %w", spec, err)
	}
	if w.end, err = clock(to); err != nil {
		return nil, fmt.Errorf("maintenance window %q: %w", spec, err)
	}
	if w.start == w.end {
		return nil, fmt.Errorf("maintenance window %q: start and end are equal", spec)
	}
	if w.loc, err = time.LoadLocation(f[2]); err != nil {
		return nil, fmt.Errorf("maintenance window %q: unknown time zone %q", spec, f[2])
	}
	return w, nil
}

func (w *Window) parseDays(s string) error {
	s = strings.ToLower(s)
	if s == "daily" || s == "*" {
		for i := range w.days {
			w.days[i] = true
		}
		return nil
	}
	for part := range strings.SplitSeq(s, ",") {
		a, b, isRange := strings.Cut(part, "-")
		da, ok := dayNames[a]
		if !ok {
			return fmt.Errorf("unknown day %q (use Mon, Tue, ... or daily)", a)
		}
		if !isRange {
			w.days[da] = true
			continue
		}
		db, ok := dayNames[b]
		if !ok {
			return fmt.Errorf("unknown day %q (use Mon, Tue, ... or daily)", b)
		}
		for d := da; ; d = (d + 1) % 7 {
			w.days[d] = true
			if d == db {
				break
			}
		}
	}
	return nil
}

func clock(s string) (int, error) {
	h, m, ok := strings.Cut(s, ":")
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if !ok || err1 != nil || err2 != nil || hh < 0 || hh > 24 || mm < 0 || mm > 59 || (hh == 24 && mm != 0) {
		return 0, errors.New("time " + strconv.Quote(s) + " must be HH:MM")
	}
	return hh*60 + mm, nil
}

// String returns the normalised spec.
func (w *Window) String() string { return w.spec }

// occurrence returns the window that starts on the calendar day of t's date
// (in the window's zone) shifted by offset days.
func (w *Window) occurrence(day time.Time, offset int) (start, end time.Time, ok bool) {
	y, m, d := day.Date()
	base := time.Date(y, m, d+offset, 0, 0, 0, 0, w.loc)
	if !w.days[base.Weekday()] {
		return time.Time{}, time.Time{}, false
	}
	start = wall(y, m, d+offset, w.start, w.loc)
	endDay := d + offset
	if w.end <= w.start {
		endDay++
	}
	end = wall(y, m, endDay, w.end, w.loc)
	return start, end, end.After(start)
}

// wall returns the instant of a wall-clock time. A time that does not exist
// (inside a DST gap) is moved forward by the gap, by reading it with the
// offset in force before the transition; time.Date alone does not promise
// which side it picks.
func wall(y int, m time.Month, d, minutes int, loc *time.Location) time.Time {
	t := time.Date(y, m, d, minutes/60, minutes%60, 0, 0, loc)
	if t.Hour()*60+t.Minute() == minutes%(24*60) {
		return t
	}
	_, before := t.Add(-6 * time.Hour).Zone()
	return time.Date(y, m, d, minutes/60, minutes%60, 0, 0, time.UTC).Add(-time.Duration(before) * time.Second).In(loc)
}

// Contains reports whether t is inside an occurrence of the window.
func (w *Window) Contains(t time.Time) bool {
	day := t.In(w.loc)
	for off := -1; off <= 0; off++ {
		if s, e, ok := w.occurrence(day, off); ok && !t.Before(s) && t.Before(e) {
			return true
		}
	}
	return false
}

// Next returns t if t is inside the window, otherwise the start of the next
// occurrence after t.
func (w *Window) Next(t time.Time) time.Time {
	if w.Contains(t) {
		return t
	}
	day := t.In(w.loc)
	for off := 0; off <= 8; off++ {
		if s, _, ok := w.occurrence(day, off); ok && s.After(t) {
			return s
		}
	}
	return time.Time{} // unreachable: Parse guarantees at least one day
}

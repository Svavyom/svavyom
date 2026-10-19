package schedule

import (
	"strconv"
	"time"
)

// MissedWindow is how late a daily run may start. A host that was down at 02:30 and comes back at 15:00 must not take the machines down in the
// middle of the working day for a backup that was meant for the night: such a run is skipped and the next day's runs as normal. An every-N-hours
// schedule has no such window: it runs once, late.
const MissedWindow = 6 * time.Hour

// NextAfter returns the first run strictly after t. An hours schedule counts from t; a daily one is the next HH:MM in loc. A wall-clock time that does
// not exist (the hour skipped when clocks go forward) runs at the normalised time, an ambiguous one (clocks going back) at its first occurrence, and
// never twice on one date.
func NextAfter(sp Spec, t time.Time, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	if sp.EveryHours > 0 {
		return t.Add(time.Duration(sp.EveryHours) * time.Hour)
	}
	h, _ := strconv.Atoi(sp.At[:2])
	m, _ := strconv.Atoi(sp.At[3:])
	lt := t.In(loc)
	for d := 0; d < 3; d++ {
		c := time.Date(lt.Year(), lt.Month(), lt.Day()+d, h, m, 0, 0, loc)
		if c.After(t) {
			return c.UTC()
		}
	}
	return t.Add(24 * time.Hour) // unreachable in practice
}

// Due decides what to do with a schedule whose NextRun has passed. run is true when the window should open now; the new NextRun is returned either way.
// A daily schedule that is more than MissedWindow late is skipped (run false).
func Due(sp Spec, scheduled, now time.Time, loc *time.Location) (run bool, next time.Time) {
	if now.Before(scheduled) {
		return false, scheduled
	}
	late := now.Sub(scheduled)
	next = NextAfter(sp, now, loc)
	if sp.EveryHours > 0 {
		return true, next
	}
	return late <= MissedWindow, next
}

package blackout

import (
	"testing"
	"time"
)

func mustLoad(t *testing.T, tz string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(tz)
	if err != nil {
		t.Skipf("tzdata %s unavailable: %v", tz, err)
	}
	return loc
}

func TestDailyHourRange(t *testing.T) {
	loc := mustLoad(t, "Europe/Paris")
	windows := []Window{{RRULE: "FREQ=DAILY;BYHOUR=0-5", TZ: "Europe/Paris"}}
	inside := time.Date(2026, 7, 30, 3, 0, 0, 0, loc)
	if !Active(inside, windows) {
		t.Error("03:00 Paris must be inside BYHOUR=0-5")
	}
	outside := time.Date(2026, 7, 30, 12, 0, 0, 0, loc)
	if Active(outside, windows) {
		t.Error("12:00 Paris must be outside BYHOUR=0-5")
	}
	// UTC is not Paris: 03:00 UTC = 05:00 CEST → still inside; 04:30 UTC = 06:30 CEST → outside.
	if Active(time.Date(2026, 7, 30, 4, 30, 0, 0, time.UTC), windows) {
		t.Error("evaluation must happen in the declared tz")
	}
}

func TestWeeklyByDay(t *testing.T) {
	windows := []Window{{RRULE: "FREQ=WEEKLY;BYDAY=SA,SU", TZ: "UTC"}}
	saturday := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC) // a Saturday
	if !Active(saturday, windows) {
		t.Error("Saturday must be inside BYDAY=SA,SU")
	}
	monday := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	if Active(monday, windows) {
		t.Error("Monday must be outside BYDAY=SA,SU")
	}
}

func TestFailClosedOnGarbage(t *testing.T) {
	if !Active(time.Now(), []Window{{RRULE: "FREQ=HOURLY", TZ: "UTC"}}) {
		t.Error("unsupported FREQ must fail closed (active)")
	}
	if !Active(time.Now(), []Window{{RRULE: "FREQ=DAILY;BYHOUR=banana", TZ: "UTC"}}) {
		t.Error("unparsable BYHOUR must fail closed")
	}
	if !Active(time.Now(), []Window{{RRULE: "FREQ=DAILY", TZ: "Not/AZone"}}) {
		t.Error("unknown tz must fail closed")
	}
}

func TestWrapAroundRange(t *testing.T) {
	windows := []Window{{RRULE: "FREQ=DAILY;BYHOUR=22-2", TZ: "UTC"}}
	if !Active(time.Date(2026, 1, 1, 23, 0, 0, 0, time.UTC), windows) {
		t.Error("23:00 must be inside 22-2")
	}
	if !Active(time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC), windows) {
		t.Error("01:00 must be inside 22-2")
	}
	if Active(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), windows) {
		t.Error("12:00 must be outside 22-2")
	}
}

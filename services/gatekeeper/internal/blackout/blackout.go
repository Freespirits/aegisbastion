// Package blackout evaluates RoE blackout windows (pipeline step 8 WINDOW,
// doc 11 §3.3) in the window's declared IANA timezone. MVP supports the
// RRULE subset the design docs actually use:
//
//	FREQ=DAILY;BYHOUR=0-5          (hour ranges or lists, e.g. BYHOUR=0,12,22)
//	FREQ=WEEKLY;BYDAY=MO,TU;BYHOUR=…
//
// Unsupported RRULE features fail closed: the window is treated as ACTIVE
// (blackout) so unknown rules never silently permit work.
package blackout

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

var byday = map[string]time.Weekday{
	"SU": time.Sunday, "MO": time.Monday, "TU": time.Tuesday, "WE": time.Wednesday,
	"TH": time.Thursday, "FR": time.Friday, "SA": time.Saturday,
}

// Window is one parsed blackout window.
type Window struct {
	RRULE string
	TZ    string
}

// Active reports whether t falls inside any of the given windows, evaluated
// in each window's declared tz. A parse failure fails closed (true).
func Active(t time.Time, windows []Window) bool {
	for _, w := range windows {
		if windowActive(t, w) {
			return true
		}
	}
	return false
}

func windowActive(t time.Time, w Window) bool {
	loc, err := time.LoadLocation(w.TZ)
	if err != nil {
		return true // unknown tz: fail closed
	}
	local := t.In(loc)

	parts := map[string]string{}
	for _, p := range strings.Split(w.RRULE, ";") {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 {
			parts[strings.ToUpper(kv[0])] = strings.ToUpper(kv[1])
		}
	}
	freq := parts["FREQ"]
	if freq != "DAILY" && freq != "WEEKLY" {
		return true // unsupported FREQ: fail closed
	}
	if freq == "WEEKLY" {
		days, ok := parts["BYDAY"]
		if !ok {
			return true // WEEKLY without BYDAY is ambiguous: fail closed
		}
		dayMatch := false
		for _, d := range strings.Split(days, ",") {
			wd, ok := byday[strings.TrimSpace(d)]
			if !ok {
				return true // unknown day token: fail closed
			}
			if local.Weekday() == wd {
				dayMatch = true
				break
			}
		}
		if !dayMatch {
			return false
		}
	}
	if hours, ok := parts["BYHOUR"]; ok {
		return hourIn(local.Hour(), hours)
	}
	// DAILY without BYHOUR = all day.
	return true
}

// hourIn parses BYHOUR values: "0-5" ranges and "0,12,22" lists (mixed ok).
func hourIn(hour int, spec string) bool {
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if lo, hi, ok := strings.Cut(tok, "-"); ok {
			loN, err1 := strconv.Atoi(lo)
			hiN, err2 := strconv.Atoi(hi)
			if err1 != nil || err2 != nil {
				return true // unparsable: fail closed
			}
			if loN <= hiN {
				if hour >= loN && hour <= hiN {
					return true
				}
			} else { // wrap-around range, e.g. 22-2
				if hour >= loN || hour <= hiN {
					return true
				}
			}
			continue
		}
		n, err := strconv.Atoi(tok)
		if err != nil {
			return true // unparsable: fail closed
		}
		if hour == n {
			return true
		}
	}
	return false
}

// ParseWindows converts proto blackout windows. Kept here so policy stays lean.
func ParseWindows(rrules, tzs []string) ([]Window, error) {
	if len(rrules) != len(tzs) {
		return nil, fmt.Errorf("blackout: rrule/tz count mismatch")
	}
	out := make([]Window, len(rrules))
	for i := range rrules {
		out[i] = Window{RRULE: rrules[i], TZ: tzs[i]}
	}
	return out, nil
}

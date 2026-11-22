package abuse

import (
	"fmt"
	"testing"
	"time"

	"github.com/wh3r3ar3you/uptimeforge/internal/checks"
)

var t0 = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func TestNormalize(t *testing.T) {
	nodes := map[string]bool{"194.26.229.27": true}
	for in, want := range map[string]string{
		"83.149.47.17":                 "83.149.47.17",
		"::ffff:83.149.47.17":          "83.149.47.17",
		"2a00:1fa0:4a2:1c3e:9d1:5:6:7": "2a00:1fa0:4a2:1c3e::/64",
		"2a00:1fa0:4a2:1c3e:aaaa::1":   "2a00:1fa0:4a2:1c3e::/64",
		"194.26.229.27":                "", // a node or bridge, not a client
		"10.2.0.254":                   "",
		"192.168.1.5":                  "",
		"127.0.0.1":                    "",
		"::1":                          "",
		"fe80::1":                      "",
		"not an ip":                    "",
		"":                             "",
	} {
		got, ok := Normalize(in, nodes)
		if got != want || ok != (want != "") {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestRuleDefaultsAndValidate(t *testing.T) {
	var nilRule *Rule
	r := nilRule.Effective()
	if r.Mode != ModeNotify || r.Window.D() != 5*time.Minute || r.Notify.K != 3 || r.Notify.N != 5 || r.Notify.Hold.D() != 15*time.Minute ||
		r.Ban.K != 5 || r.Ban.N != 10 || r.Ban.Hold.D() != 30*time.Minute || r.Cooldown.D() != 24*time.Hour || r.Retention.D() != 72*time.Hour {
		t.Fatalf("defaults %+v", r)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]Rule{
		"mode":       {Mode: "kill"},
		"k below 2":  {Notify: &Threshold{K: 1}},
		"ban below":  {Notify: &Threshold{K: 5, N: 10}, Ban: &Threshold{K: 3, N: 5}},
		"window":     {Window: checks.Duration(30 * time.Second)},
		"hold":       {Notify: &Threshold{Hold: checks.Duration(time.Minute)}},
		"retention":  {Retention: checks.Duration(time.Hour)},
		"negative n": {Notify: &Threshold{N: -1}},
	} {
		if err := (&bad).Effective().Validate(); err == nil {
			t.Errorf("%s: no error for %+v", name, bad)
		}
	}
	if (Threshold{K: 3, N: 5}).For(1) != 6 || (Threshold{K: 3, N: 5}).For(3) != 9 || (Threshold{K: 3, N: 5}).For(5) != 15 {
		t.Fatal("threshold math")
	}
}

// ips makes n client addresses for one user.
func ips(n int, base int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("83.%d.0.%d", base, i+1)
	}
	return out
}

// run feeds the same picture every minute for d and returns every verdict.
type sim struct {
	t      *testing.T
	rule   Rule
	tr     *Tracker
	users  map[int64]User
	states map[int64]State
	at     time.Time
}

func newSim(t *testing.T, r *Rule, users ...User) *sim {
	s := &sim{t: t, rule: r.Effective(), tr: NewTracker(), users: map[int64]User{}, states: map[int64]State{}, at: t0}
	for _, u := range users {
		s.users[u.ID] = u
	}
	return s
}

func (s *sim) step(polled bool, conns map[int64][]string) []Verdict {
	s.at = s.at.Add(time.Minute)
	if polled {
		s.tr.Observe(s.at, "node-a", conns)
	}
	var v []Verdict
	v, s.states = Evaluate(s.at, s.rule, s.tr, s.users, 5, polled, s.states)
	return v
}

func (s *sim) run(minutes int, conns map[int64][]string) (acts []Action) {
	for range minutes {
		for _, v := range s.step(true, conns) {
			if v.Action != ActNone {
				acts = append(acts, v.Action)
			}
		}
	}
	return acts
}

func TestMobileClientIsNotFlagged(t *testing.T) {
	s := newSim(t, nil, User{ID: 1, Limit: 1, Status: "ACTIVE"})
	// Wi-Fi, LTE and a CGNAT hop: three addresses inside the window, all day.
	for i := range 120 {
		s.step(true, map[int64][]string{1: {ips(3, 1)[i%3]}})
	}
	for _, st := range s.states {
		if st.Level != LevelOK {
			t.Fatalf("a phone hopping networks got %+v", st)
		}
	}
}

func TestNotifyAfterHoldOnceThenCooldown(t *testing.T) {
	s := newSim(t, nil, User{ID: 7, Username: "saveoleshki", Limit: 1, Status: "ACTIVE"})
	share := map[int64][]string{7: ips(8, 1)} // limit 1: notify at 6, ban at 11
	if acts := s.run(14, share); len(acts) != 0 {
		t.Fatalf("acted before the 15 min hold: %v", acts)
	}
	acts := s.run(2, share)
	if len(acts) != 1 || acts[0] != ActNotify {
		t.Fatalf("after the hold: %v", acts)
	}
	if acts := s.run(60, share); len(acts) != 0 {
		t.Fatalf("repeated inside the cooldown: %v", acts)
	}
	// Twice as many addresses as last told: say it again at once.
	if acts := s.run(1, map[int64][]string{7: ips(16, 1)}); len(acts) != 1 {
		t.Fatalf("growth to 16 not reported: %v", acts)
	}
	v := s.step(true, map[int64][]string{7: ips(16, 1)})
	if len(v) != 1 || v[0].Now != 16 || v[0].User.Username != "saveoleshki" || v[0].Limit != 1 || len(v[0].Nodes) != 1 {
		t.Fatalf("verdict %+v", v)
	}
}

func TestBelowThresholdResetsHold(t *testing.T) {
	s := newSim(t, nil, User{ID: 7, Limit: 1, Status: "ACTIVE"})
	share := map[int64][]string{7: ips(8, 1)}
	s.run(10, share)
	// The window is 5 minutes: six quiet polls let every address age out.
	s.run(6, map[int64][]string{7: {"83.1.0.1"}})
	if acts := s.run(14, share); len(acts) != 0 {
		t.Fatalf("the hold did not restart: %v", acts)
	}
}

func TestNoDataNeitherResetsNorAdvances(t *testing.T) {
	s := newSim(t, nil, User{ID: 7, Limit: 1, Status: "ACTIVE"})
	share := map[int64][]string{7: ips(8, 1)}
	s.run(10, share) // 9 minutes held
	for range 30 {
		if v := s.step(false, nil); len(v) != 0 {
			t.Fatalf("acted with the panel down: %+v", v)
		}
	}
	if s.states[7].NotifySince.IsZero() {
		t.Fatal("the hold was reset while blind")
	}
	// Half an hour blind counts for nothing: 6 more seen minutes to go.
	if acts := s.run(5, share); len(acts) != 0 {
		t.Fatalf("blind time counted towards the hold: %v", acts)
	}
	if acts := s.run(1, share); len(acts) != 1 {
		t.Fatalf("the hold did not resume: %v", acts)
	}
}

func TestBanOnlyInBanMode(t *testing.T) {
	share := map[int64][]string{7: ips(12, 1)} // limit 1: ban at 11

	s := newSim(t, nil, User{ID: 7, Limit: 1, Status: "ACTIVE"})
	acts := s.run(40, share)
	if len(acts) != 2 || acts[0] != ActNotify || acts[1] != ActWouldBan {
		t.Fatalf("notify mode: %v", acts)
	}

	s = newSim(t, &Rule{Mode: ModeBan}, User{ID: 7, Limit: 1, Status: "ACTIVE"})
	acts = s.run(40, share)
	if len(acts) != 2 || acts[0] != ActNotify || acts[1] != ActBan {
		t.Fatalf("ban mode: %v", acts)
	}
	if acts := s.run(60, share); len(acts) != 0 {
		t.Fatalf("banned twice: %v", acts)
	}
}

func TestNeverBanned(t *testing.T) {
	share := map[int64][]string{1: ips(12, 1), 2: ips(12, 2), 3: ips(12, 3), 4: ips(30, 4)}
	s := newSim(t, &Rule{Mode: ModeBan, AllowUsers: []int64{1}, AllowTags: []string{"WHITELIST"}},
		User{ID: 1, Limit: 1, Status: "ACTIVE"},
		User{ID: 2, Limit: 1, Status: "ACTIVE", Tag: "WHITELIST"},
		User{ID: 3, Limit: 1, Status: "DISABLED"},
		User{ID: 4, Limit: 0, Status: "ACTIVE"}, // no device limit
	)
	for range 60 {
		for _, v := range s.step(true, share) {
			if v.Action == ActBan || ((v.User.ID == 1 || v.User.ID == 2 || v.User.ID == 4) && v.Action != ActNone) {
				t.Fatalf("user %d: %s", v.User.ID, v.Action)
			}
		}
	}
}

func TestUnknownUserTakesFallbackLimit(t *testing.T) {
	s := newSim(t, nil) // the directory has not caught up with a new user
	acts := s.run(16, map[int64][]string{9: ips(15, 1)})
	if len(acts) != 1 {
		t.Fatalf("fallback 5 (notify at 15) never notified: %v", acts)
	}
	s = newSim(t, nil)
	if acts := s.run(16, map[int64][]string{9: ips(14, 1)}); len(acts) != 0 {
		t.Fatalf("14 addresses at fallback 5 notified: %v", acts)
	}
}

func TestTrackerRestoreAndPrune(t *testing.T) {
	tr := NewTracker()
	tr.Observe(t0, "a", map[int64][]string{1: {"83.1.0.1", "10.0.0.1"}})
	tr.Observe(t0.Add(time.Minute), "b", map[int64][]string{1: {"83.1.0.1", "83.1.0.2"}})
	seen := tr.Seen()
	if len(seen) != 2 {
		t.Fatalf("seen %+v", seen)
	}
	back := NewTracker()
	back.Restore(seen)
	if n, nodes := back.Count(1, t0); n != 2 || len(nodes) != 2 {
		t.Fatalf("restored count %d nodes %v", n, nodes)
	}
	back.Prune(t0.Add(30 * time.Second))
	if n, _ := back.Count(1, t0.Add(-time.Hour)); n != 2 {
		t.Fatalf("pruned a fresh address: %d", n)
	}
	back.Prune(t0.Add(2 * time.Minute))
	if n, _ := back.Count(1, t0.Add(-time.Hour)); n != 0 {
		t.Fatalf("kept stale addresses: %d", n)
	}
}

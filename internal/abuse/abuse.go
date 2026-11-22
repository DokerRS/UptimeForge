// Package abuse tells a shared subscription from an honest one by how many
// client addresses connect under it at once, across every Remnawave node.
//
// It is pure logic: the panel is polled and the results stored elsewhere
// (internal/app). An address counts while it is in a node's list of open
// connections; the panel's lastSeen is when the last new connection opened,
// so a long-lived one can carry a lastSeen of days ago and is still there.
package abuse

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/wh3r3ar3you/uptimeforge/internal/checks"
)

const (
	ModeOff    = "off"
	ModeNotify = "notify"
	ModeBan    = "ban"
)

// Threshold is "at least max(limit×K, limit+N) addresses for Hold".
type Threshold struct {
	K    int             `yaml:"k" json:"k,omitempty"`
	N    int             `yaml:"n" json:"n,omitempty"`
	Hold checks.Duration `yaml:"hold" json:"hold,omitempty"`
}

// For is the number of addresses that crosses the threshold at a device limit.
func (t Threshold) For(limit int) int { return max(limit*t.K, limit+t.N) }

// Rule is the remnawave.abuse setting. Zero values take the defaults.
type Rule struct {
	Mode      string          `yaml:"mode" json:"mode,omitempty"`           // off, notify (default) or ban
	Window    checks.Duration `yaml:"window" json:"window,omitempty"`       // what "at once" spans, default 5m
	Notify    *Threshold      `yaml:"notify" json:"notify,omitempty"`       // default 3, 5, 15m
	Ban       *Threshold      `yaml:"ban" json:"ban,omitempty"`             // default 5, 10, 30m
	Cooldown  checks.Duration `yaml:"cooldown" json:"cooldown,omitempty"`   // between messages about one user, default 24h
	Retention checks.Duration `yaml:"retention" json:"retention,omitempty"` // how long addresses are kept, default 72h
	// AllowUsers and AllowTags are never reported nor banned: service
	// accounts (a bridge's own user) and people known to be fine.
	AllowUsers []int64  `yaml:"allow_users" json:"allow_users,omitempty"`
	AllowTags  []string `yaml:"allow_tags" json:"allow_tags,omitempty"`
}

// Effective is the rule with defaults filled in; r may be nil.
func (r *Rule) Effective() Rule {
	var o Rule
	if r != nil {
		o = *r
	}
	if o.Mode == "" {
		o.Mode = ModeNotify
	}
	def := func(d *checks.Duration, v time.Duration) {
		if *d == 0 {
			*d = checks.Duration(v)
		}
	}
	def(&o.Window, 5*time.Minute)
	def(&o.Cooldown, 24*time.Hour)
	def(&o.Retention, 72*time.Hour)
	fill := func(t *Threshold, k, n int, hold time.Duration) *Threshold {
		var x Threshold
		if t != nil {
			x = *t
		}
		if x.K == 0 {
			x.K = k
		}
		if x.N == 0 {
			x.N = n
		}
		def(&x.Hold, hold)
		return &x
	}
	o.Notify = fill(o.Notify, 3, 5, 15*time.Minute)
	o.Ban = fill(o.Ban, 5, 10, 30*time.Minute)
	return o
}

// Validate checks an effective rule.
func (r Rule) Validate() error {
	if r.Mode != ModeOff && r.Mode != ModeNotify && r.Mode != ModeBan {
		return fmt.Errorf("remnawave.abuse.mode must be off, notify or ban")
	}
	if w := r.Window.D(); w < 2*time.Minute || w > time.Hour {
		return errors.New("remnawave.abuse.window must be between 2m and 1h")
	}
	if c := r.Cooldown.D(); c < time.Hour || c > 7*24*time.Hour {
		return errors.New("remnawave.abuse.cooldown must be between 1h and 7d")
	}
	if k := r.Retention.D(); k < 24*time.Hour || k > 14*24*time.Hour {
		return errors.New("remnawave.abuse.retention must be between 24h and 14d")
	}
	for name, t := range map[string]*Threshold{"notify": r.Notify, "ban": r.Ban} {
		if t.K < 2 || t.N < 0 {
			return fmt.Errorf("remnawave.abuse.%s: k must be at least 2 and n not negative", name)
		}
		if h := t.Hold.D(); h < 5*time.Minute || h > 6*time.Hour {
			return fmt.Errorf("remnawave.abuse.%s.hold must be between 5m and 6h", name)
		}
	}
	for _, limit := range []int{1, 2, 3, 5, 10} {
		if r.Ban.For(limit) < r.Notify.For(limit) {
			return errors.New("remnawave.abuse: the ban threshold must not be below the notify one")
		}
	}
	return nil
}

// Normalize turns a client address into what is counted: an IPv4 address as
// is, an IPv6 one as its /64 (a phone rotates addresses inside it). Node and
// bridge addresses, private and local ones are not clients and give false.
func Normalize(ip string, nodes map[string]bool) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	a = a.Unmap().WithZone("")
	if nodes[a.String()] || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() || !a.IsGlobalUnicast() {
		return "", false
	}
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String(), true
	}
	return a.String(), true
}

// Seen is one address of one user: when it was first and last in a node's
// list of open connections, and on which nodes.
type Seen struct {
	User   int64     `json:"user"`
	Prefix string    `json:"prefix"`
	First  time.Time `json:"first"`
	Last   time.Time `json:"last"`
	Nodes  []string  `json:"nodes"`
}

// Tracker holds the addresses seen per user.
type Tracker struct {
	nodes map[string]bool
	seen  map[int64]map[string]*Seen
}

func NewTracker() *Tracker { return &Tracker{seen: map[int64]map[string]*Seen{}} }

// SetNodeIPs names the addresses of the panel's own nodes: a client never
// connects from one, a bridge or cascade does.
func (t *Tracker) SetNodeIPs(ips map[string]bool) { t.nodes = ips }

// Observe adds one node's open connections, polled at at.
func (t *Tracker) Observe(at time.Time, node string, users map[int64][]string) {
	for id, list := range users {
		for _, ip := range list {
			p, ok := Normalize(ip, t.nodes)
			if !ok {
				continue
			}
			m := t.seen[id]
			if m == nil {
				m = map[string]*Seen{}
				t.seen[id] = m
			}
			s := m[p]
			if s == nil {
				s = &Seen{User: id, Prefix: p, First: at}
				m[p] = s
			}
			if at.After(s.Last) {
				s.Last = at
			}
			if !slices.Contains(s.Nodes, node) {
				s.Nodes = append(s.Nodes, node)
			}
		}
	}
}

// Restore loads what was stored before a restart.
func (t *Tracker) Restore(list []Seen) {
	for _, s := range list {
		m := t.seen[s.User]
		if m == nil {
			m = map[string]*Seen{}
			t.seen[s.User] = m
		}
		c := s
		c.Nodes = slices.Clone(s.Nodes)
		m[s.Prefix] = &c
	}
}

// Prune forgets addresses not seen since before.
func (t *Tracker) Prune(before time.Time) {
	for id, m := range t.seen {
		for p, s := range m {
			if s.Last.Before(before) {
				delete(m, p)
			}
		}
		if len(m) == 0 {
			delete(t.seen, id)
		}
	}
}

// Seen lists every address held, for storing.
func (t *Tracker) Seen() []Seen {
	var out []Seen
	for _, m := range t.seen {
		for _, s := range m {
			c := *s
			c.Nodes = slices.Clone(s.Nodes)
			out = append(out, c)
		}
	}
	return out
}

// Count is how many addresses of the user were seen after since, and on
// which nodes.
func (t *Tracker) Count(user int64, since time.Time) (int, []string) {
	n, nodes := 0, []string{}
	for _, s := range t.seen[user] {
		if s.Last.After(since) {
			n++
			for _, x := range s.Nodes {
				if !slices.Contains(nodes, x) {
					nodes = append(nodes, x)
				}
			}
		}
	}
	sort.Strings(nodes)
	return n, nodes
}

// Addresses lists the user's addresses, newest first.
func (t *Tracker) Addresses(user int64) []Seen {
	var out []Seen
	for _, s := range t.seen[user] {
		c := *s
		c.Nodes = slices.Clone(s.Nodes)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Last.After(out[j].Last) || (out[i].Last.Equal(out[j].Last) && out[i].Prefix < out[j].Prefix)
	})
	return out
}

// User is what the panel says about a subscriber. Limit is the device limit
// already resolved against the panel's fallback; 0 means no limit.
type User struct {
	ID         int64  `json:"id"`
	Username   string `json:"username,omitempty"`
	TelegramID int64  `json:"telegram_id,omitempty"`
	Limit      int    `json:"limit"`
	Status     string `json:"status,omitempty"`
	Tag        string `json:"tag,omitempty"`
}

type Level string

const (
	LevelOK     Level = "ok"
	LevelNotify Level = "notify"
	LevelBan    Level = "ban"
)

type Action string

const (
	ActNone     Action = ""
	ActNotify   Action = "notify"
	ActWouldBan Action = "would_ban" // the ban threshold held in notify mode
	ActBan      Action = "ban"
)

// State is what is remembered per user between polls, and across restarts.
type State struct {
	User        int64     `json:"user"`
	Level       Level     `json:"level"`
	NotifySince time.Time `json:"notify_since,omitzero"` // above the notify threshold since
	BanSince    time.Time `json:"ban_since,omitzero"`
	LastEval    time.Time `json:"last_eval,omitzero"`
	NotifiedAt  time.Time `json:"notified_at,omitzero"`
	NotifiedNow int       `json:"notified_now,omitempty"`
	NotifiedBan bool      `json:"notified_ban,omitempty"`
	BannedAt    time.Time `json:"banned_at,omitzero"`
	BanFailed   bool      `json:"ban_failed,omitempty"` // the panel refused the ban
}

// Verdict is one user above a threshold, and what to do now.
type Verdict struct {
	User   User
	Limit  int
	Now    int      // addresses at once (inside the window)
	Day    int      // addresses over 24 hours
	Nodes  []string `json:"nodes"`
	Level  Level
	Since  time.Time
	Action Action
}

func (r Rule) allowed(u User) bool {
	return slices.Contains(r.AllowUsers, u.ID) || (u.Tag != "" && slices.Contains(r.AllowTags, u.Tag))
}

// Poll is what one round got from the panel. Answered: at least one node
// answered. Partial: some node did not, or the window is still refilling
// after a gap; a user under the threshold then keeps its hold, since the
// missing addresses may simply not have been read.
type Poll struct {
	Answered bool
	Partial  bool
}

// ShiftHolds moves every running hold forward by gap: time the hub was down,
// or the antifraud off, does not count towards one.
func ShiftHolds(states map[int64]State, gap time.Duration) {
	for id, st := range states {
		if !st.NotifySince.IsZero() {
			st.NotifySince = st.NotifySince.Add(gap)
		}
		if !st.BanSince.IsZero() {
			st.BanSince = st.BanSince.Add(gap)
		}
		states[id] = st
	}
}

// Evaluate judges every user the tracker holds at at. A round that got
// nothing from the panel, or has no user directory to judge by, moves
// nothing, and the time spent blind does not count towards a hold. fallback
// is the device limit for a user the directory does not know yet; such a
// user may be reported but never banned.
func Evaluate(at time.Time, r Rule, tr *Tracker, users map[int64]User, fallback int, poll Poll, states map[int64]State) ([]Verdict, map[int64]State) {
	next := make(map[int64]State, len(states))
	if !poll.Answered || users == nil {
		for id, st := range states {
			if !st.LastEval.IsZero() {
				gap := at.Sub(st.LastEval)
				if !st.NotifySince.IsZero() {
					st.NotifySince = st.NotifySince.Add(gap)
				}
				if !st.BanSince.IsZero() {
					st.BanSince = st.BanSince.Add(gap)
				}
			}
			st.LastEval = at
			next[id] = st
		}
		return nil, next
	}

	ids := map[int64]bool{}
	for id := range tr.seen {
		ids[id] = true
	}
	for id := range states {
		ids[id] = true
	}
	var out []Verdict
	for id := range ids {
		u, known := users[id]
		if !known {
			u = User{ID: id, Limit: fallback}
		}
		st := states[id]
		st.User, st.LastEval = id, at
		if r.allowed(u) || u.Limit <= 0 {
			continue // dropped from the states as well
		}
		now, nodes := tr.Count(id, at.Add(-r.Window.D()))
		level := LevelOK
		if now >= r.Notify.For(u.Limit) {
			level = LevelNotify
			if st.NotifySince.IsZero() {
				st.NotifySince = at
			}
		} else if !poll.Partial {
			st.NotifySince = time.Time{}
		}
		if now >= r.Ban.For(u.Limit) {
			level = LevelBan
			if st.BanSince.IsZero() {
				st.BanSince = at
			}
		} else if !poll.Partial {
			st.BanSince = time.Time{}
		}
		st.Level = level
		// Re-enabled in the panel by hand: after the cooldown it may be banned again.
		if !st.BannedAt.IsZero() && u.Status == "ACTIVE" && at.Sub(st.BannedAt) >= r.Cooldown.D() {
			st.BannedAt, st.BanFailed = time.Time{}, false
		}

		heldNotify := !st.NotifySince.IsZero() && at.Sub(st.NotifySince) >= r.Notify.Hold.D()
		heldBan := !st.BanSince.IsZero() && at.Sub(st.BanSince) >= r.Ban.Hold.D()
		act := ActNone
		switch {
		case heldBan && r.Mode == ModeBan && known && u.Status != "DISABLED" && st.BannedAt.IsZero():
			act = ActBan
			st.BannedAt = at
		case heldNotify || heldBan:
			due := st.NotifiedAt.IsZero() || at.Sub(st.NotifiedAt) >= r.Cooldown.D() || now >= 2*st.NotifiedNow || (heldBan && !st.NotifiedBan)
			if due && st.BannedAt.IsZero() {
				act = ActNotify
				// In ban mode a ban that cannot happen (unknown user, already
				// disabled) is a plain notice, not "would be banned".
				if heldBan && r.Mode != ModeBan {
					act = ActWouldBan
				}
			}
		}
		if act != ActNone {
			if at.Sub(st.NotifiedAt) >= r.Cooldown.D() {
				st.NotifiedBan = false
			}
			st.NotifiedAt, st.NotifiedNow = at, now
			st.NotifiedBan = st.NotifiedBan || act == ActWouldBan || act == ActBan
		}

		keep := level != LevelOK || !st.NotifySince.IsZero() || !st.BanSince.IsZero() || !st.BannedAt.IsZero() || (!st.NotifiedAt.IsZero() && at.Sub(st.NotifiedAt) < r.Cooldown.D())
		if keep {
			next[id] = st
		}
		if level != LevelOK || act != ActNone {
			day, _ := tr.Count(id, at.Add(-24*time.Hour))
			since := st.NotifySince
			out = append(out, Verdict{User: u, Limit: u.Limit, Now: now, Day: day, Nodes: nodes, Level: level, Since: since, Action: act})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Now > out[j].Now || (out[i].Now == out[j].Now && out[i].User.ID < out[j].User.ID)
	})
	return out, next
}

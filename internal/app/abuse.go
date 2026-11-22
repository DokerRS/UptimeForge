package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wh3r3ar3you/uptimeforge/internal/abuse"
	"github.com/wh3r3ar3you/uptimeforge/internal/notify"
	"github.com/wh3r3ar3you/uptimeforge/internal/remnawave"
	"github.com/wh3r3ar3you/uptimeforge/internal/store"
)

const (
	abusePoll       = time.Minute
	abuseUsersEvery = 10 * time.Minute
	abuseNodeWait   = 15 * time.Second
	abuseParallel   = 8
	abuseEventsKeep = 90 * 24 * time.Hour
)

// abuseRun is the antifraud's memory: the addresses seen per user, what was
// decided per user, and the panel's user directory.
type abuseRun struct {
	mu       sync.Mutex
	loaded   bool
	tr       *abuse.Tracker
	states   map[int64]abuse.State
	users    map[int64]abuse.User
	fallback int
	usersAt  time.Time
	prunedAt time.Time
	verdicts []abuse.Verdict
	cover    AbuseCoverage
	savedKey string // the states as last written
	// lastRound is when the previous round ran (stored, so a restart knows
	// how long the hub was down); refillUntil ends the stretch after a gap
	// in which the window is still filling up again.
	lastRound   time.Time
	refillUntil time.Time
	saveMu      sync.Mutex // one writer of the states at a time
	// notify sends a message (the Telegram notifier; tests replace it).
	notify func(context.Context, notify.AbuseNotice) error
}

// AbuseCoverage says how complete the last poll was.
type AbuseCoverage struct {
	Mode     string    `json:"mode"`
	At       time.Time `json:"at,omitzero"`
	Nodes    int       `json:"nodes"`
	Answered int       `json:"answered"`
	Error    string    `json:"error,omitempty"`
	Users    int       `json:"users"`
}

func (a *App) pollAbuse(ctx context.Context) {
	// The first round waits for the panel's node list (pollRemnawave starts at once).
	select {
	case <-ctx.Done():
		return
	case <-time.After(20 * time.Second):
		a.abuseRound(ctx, time.Now().UTC())
	}
	t := time.NewTicker(abusePoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.abuseRound(ctx, time.Now().UTC())
		}
	}
}

func (a *App) abuseClient() (*remnawave.Client, bool) {
	cfg := a.Hub.Config()
	if cfg.Remnawave == nil {
		return nil, false
	}
	c := remnawave.New(cfg.Remnawave.URL, cfg.Remnawave.Token)
	c.Headers, c.TZ = cfg.Remnawave.Headers, cfg.Timezone
	return c, true
}

// abuseRound polls the open connections of every node once and acts on what
// the rule decides.
func (a *App) abuseRound(ctx context.Context, at time.Time) {
	cfg := a.Hub.Config()
	if cfg.Remnawave == nil {
		return
	}
	rule := cfg.Remnawave.Abuse.Effective()
	r := &a.abuse
	if rule.Mode == abuse.ModeOff {
		r.mu.Lock()
		r.cover = AbuseCoverage{Mode: rule.Mode}
		r.mu.Unlock()
		return
	}
	c, _ := a.abuseClient()
	a.abuseLoad(ctx, at, rule)
	a.wantGeo() // the operators of the addresses come from the hub's offline GeoIP database

	// The user directory and the fallback limit change slowly.
	r.mu.Lock()
	needUsers := r.users == nil || at.Sub(r.usersAt) >= abuseUsersEvery
	r.mu.Unlock()
	if needUsers {
		uctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		list, err := c.AbuseUsers(uctx)
		fallback, ferr := c.FallbackDeviceLimit(uctx)
		cancel()
		if err == nil && ferr == nil {
			users := make(map[int64]abuse.User, len(list))
			for _, u := range list {
				limit := fallback
				if u.DeviceLimit != nil {
					limit = *u.DeviceLimit
				}
				users[u.ID] = abuse.User{ID: u.ID, Username: u.Username, TelegramID: u.TelegramID, Limit: limit, Status: u.Status, Tag: u.Tag}
			}
			r.mu.Lock()
			r.users, r.fallback, r.usersAt = users, fallback, at
			r.mu.Unlock()
		} else {
			a.Log.Warn("antifraud: read the panel's users", "err", errors.Join(err, ferr))
		}
	}

	// Every node connected to the panel, at most abuseParallel at once.
	var nodes []remnawave.Node
	if p := a.nodes.Load(); p != nil {
		nodes = *p
	}
	nodeIPs := map[string]bool{}
	var live []remnawave.Node
	for _, n := range nodes {
		for _, ip := range nodeIPsOf(n) {
			if a, err := netip.ParseAddr(ip); err == nil {
				nodeIPs[a.Unmap().WithZone("").String()] = true // the form Normalize compares
			}
		}
		if n.IsConnected && !n.IsDisabled {
			live = append(live, n)
		}
	}
	type answer struct {
		node  string
		conns map[int64][]remnawave.Conn
		err   error
	}
	answers := make([]answer, len(live))
	sem := make(chan struct{}, abuseParallel)
	var wg sync.WaitGroup
	for i, n := range live {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			nctx, cancel := context.WithTimeout(ctx, abuseNodeWait)
			defer cancel()
			conns, err := c.NodeConnections(nctx, n.UUID)
			answers[i] = answer{node: n.Name, conns: conns, err: err}
		}()
	}
	wg.Wait()
	cover := AbuseCoverage{Mode: rule.Mode, At: at, Nodes: len(live)}
	var errs []string
	for _, x := range answers {
		if x.err != nil {
			errs = append(errs, x.node+": "+x.err.Error())
			continue
		}
		cover.Answered++
	}
	if len(errs) > 0 {
		cover.Error = strings.Join(errs[:min(len(errs), 3)], "; ")
	}

	r.mu.Lock()
	r.tr.SetNodeIPs(nodeIPs)
	// A node lists an address for days after the client left: only one used
	// inside the window (plus a minute for clocks apart) is a live client.
	freshSince := at.Add(-rule.Window.D() - time.Minute)
	for _, x := range answers {
		if x.err != nil {
			continue
		}
		live := make(map[int64][]string, len(x.conns))
		for id, conns := range x.conns {
			for _, c := range conns {
				if c.LastSeen.After(freshSince) {
					live[id] = append(live[id], c.IP)
				}
			}
		}
		r.tr.Observe(at, x.node, live)
	}
	// A gap since the last round (the hub down, the antifraud off) counts for
	// nothing: running holds move on by it, and until the window has filled
	// again a user under the threshold keeps its hold.
	if !r.lastRound.IsZero() && at.Sub(r.lastRound) > 2*abusePoll && cover.Answered > 0 && r.users != nil {
		abuse.ShiftHolds(r.states, at.Sub(r.lastRound)-abusePoll)
		r.refillUntil = at.Add(rule.Window.D())
	}
	poll := abuse.Poll{Answered: cover.Answered > 0, Partial: cover.Answered < len(live) || at.Before(r.refillUntil)}
	verdicts, states := abuse.Evaluate(at, rule, r.tr, r.users, r.fallback, poll, r.states)
	r.lastRound = at
	r.states = states
	if cover.Answered > 0 {
		r.verdicts = verdicts
	}
	cover.Users = len(r.users)
	r.cover = cover
	var fresh []abuse.Seen
	for _, s := range r.tr.Seen() {
		if s.Last.Equal(at) {
			fresh = append(fresh, s)
		}
	}
	prune := at.Sub(r.prunedAt) >= time.Hour
	if prune {
		r.tr.Prune(at.Add(-rule.Retention.D()))
		r.prunedAt = at
	}
	r.mu.Unlock()

	if err := a.Store.WriteAbuseSeen(ctx, fresh); err != nil {
		a.Log.Warn("antifraud: store addresses", "err", err)
	}
	if prune {
		if err := a.Store.PruneAbuse(ctx, at.Add(-rule.Retention.D()), at.Add(-abuseEventsKeep)); err != nil {
			a.Log.Warn("antifraud: prune", "err", err)
		}
	}
	for _, v := range verdicts {
		if v.Action != abuse.ActNone {
			a.abuseAct(ctx, c, at, v)
		}
	}
	if err := a.Store.PutSetting(ctx, abuseLastRoundKey, at); err != nil {
		a.Log.Warn("antifraud: store the round time", "err", err)
	}
	a.abuseSaveStates(ctx)
}

const abuseLastRoundKey = "abuse_last_round"

// abuseSaveStates writes the states when they changed; LastEval alone moving
// does not count (the round time is stored apart).
func (a *App) abuseSaveStates(ctx context.Context) {
	r := &a.abuse
	r.saveMu.Lock()
	defer r.saveMu.Unlock()
	r.mu.Lock()
	save := maps.Clone(r.states)
	r.mu.Unlock()
	key := statesKey(save)
	if key == r.savedKey {
		return
	}
	if err := a.Store.SaveAbuseStates(ctx, save); err != nil {
		a.Log.Warn("antifraud: store states", "err", err)
		return
	}
	r.savedKey = key
}

func statesKey(m map[int64]abuse.State) string {
	ids := slices.Sorted(maps.Keys(m))
	var b strings.Builder
	for _, id := range ids {
		st := m[id]
		st.LastEval = time.Time{}
		j, _ := json.Marshal(st)
		b.Write(j)
	}
	return b.String()
}

// abuseLoad reads what was stored before a restart, once.
func (a *App) abuseLoad(ctx context.Context, at time.Time, rule abuse.Rule) {
	r := &a.abuse
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loaded {
		return
	}
	r.tr = abuse.NewTracker()
	r.states = map[int64]abuse.State{}
	if seen, err := a.Store.LoadAbuseSeen(ctx, at.Add(-rule.Retention.D())); err == nil {
		r.tr.Restore(seen)
	} else {
		a.Log.Warn("antifraud: load addresses", "err", err)
	}
	if st, err := a.Store.LoadAbuseStates(ctx); err == nil {
		r.states = st
	} else {
		a.Log.Warn("antifraud: load states", "err", err)
	}
	var last time.Time
	if found, err := a.Store.GetSetting(ctx, abuseLastRoundKey, &last); err == nil && found {
		r.lastRound = last
		// LastEval is not stored on every round: the round time is.
		for id, st := range r.states {
			st.LastEval = last
			r.states[id] = st
		}
	}
	r.loaded = true
}

// abuseAct sends the message, and in ban mode disables the subscription and
// then closes its connections. A refused disable closes nothing.
func (a *App) abuseAct(ctx context.Context, c *remnawave.Client, at time.Time, v abuse.Verdict) {
	n := notify.AbuseNotice{Action: string(v.Action), UserID: v.User.ID, Username: v.User.Username, TelegramID: v.User.TelegramID,
		Limit: v.Limit, Now: v.Now, Day: v.Day, Nodes: v.Nodes}
	if v.Action == abuse.ActBan {
		actx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := c.DisableUser(actx, v.User.ID)
		a.abuseMark(v.User.ID, err == nil)
		if err == nil {
			if derr := c.DropUserConnections(actx, []int64{v.User.ID}); derr != nil {
				a.Log.Warn("antifraud: close the connections of a disabled user", "user", v.User.ID, "err", derr)
				n.DropError = derr.Error()
			}
		} else {
			n.Error = err.Error()
		}
		cancel()
	}
	n.Addresses, n.Operators = a.abuseAddresses(ctx, v.User.ID, at)
	if err := a.Store.AddAbuseEvent(ctx, store.AbuseEvent{At: at, User: v.User.ID, Username: v.User.Username, Action: string(v.Action),
		Now: v.Now, Day: v.Day, Limit: v.Limit, Nodes: v.Nodes, Error: n.Error}); err != nil {
		a.Log.Warn("antifraud: store an event", "err", err)
	}
	send := a.abuse.notify
	if send == nil {
		a.mu.Lock()
		tg := a.tg
		a.mu.Unlock()
		if tg == nil {
			return
		}
		send = tg.NotifyAbuse
	}
	if err := send(ctx, n); err != nil {
		a.Log.Warn("antifraud: send a message", "user", v.User.ID, "err", err)
	}
}

// abuseAddresses lists the user's addresses inside the window with the
// operator of each, from the hub's offline GeoIP database (nothing is sent
// anywhere), and the operators with how many addresses each, most first.
func (a *App) abuseAddresses(ctx context.Context, user int64, at time.Time) ([]notify.AbuseAddress, []notify.AbuseOperator) {
	a.abuse.mu.Lock()
	window := a.Hub.Config().Remnawave.Abuse.Effective().Window.D()
	seen := a.abuse.tr.Addresses(user)
	a.abuse.mu.Unlock()
	var out []notify.AbuseAddress
	count := map[string]int{}
	for _, s := range seen {
		if !s.Last.After(at.Add(-window)) {
			continue
		}
		x := notify.AbuseAddress{IP: s.Prefix}
		if len(out) < abuseMaxLookups {
			x.ASN, x.Org = a.abuseNetwork(ctx, s.Prefix)
		}
		if x.Org != "" {
			count[x.Org]++
		}
		out = append(out, x)
	}
	names := slices.Collect(maps.Keys(count))
	sort.Slice(names, func(i, j int) bool {
		return count[names[i]] > count[names[j]] || (count[names[i]] == count[names[j]] && names[i] < names[j])
	})
	ops := make([]notify.AbuseOperator, 0, min(len(names), 5))
	for _, n := range names[:min(len(names), 5)] {
		ops = append(ops, notify.AbuseOperator{Name: n, Count: count[n]})
	}
	return out, ops
}

// abuseMaxLookups bounds the GeoIP lookups of one message.
const abuseMaxLookups = 50

// abuseNetwork is the operator of an address or an IPv6 /64.
func (a *App) abuseNetwork(ctx context.Context, prefix string) (asn, org string) {
	if a.geo == nil {
		return "", ""
	}
	ip, err := netip.ParseAddr(strings.TrimSuffix(prefix, "/64"))
	if err != nil {
		return "", ""
	}
	lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	n, err := a.geo.Network(lctx, ip)
	if err != nil {
		return "", ""
	}
	return n.ASN, n.Org
}

// nodeIPsOf is every address a node is known by: the panel's list and its
// address when that is an IP.
func nodeIPsOf(n remnawave.Node) []string {
	ips := nodeIPs(n)
	if isAddr(n.Address) && !slices.Contains(ips, n.Address) {
		ips = append(ips, n.Address)
	}
	return ips
}

// AbuseRow is one subscriber on the Antifraud page.
type AbuseRow struct {
	User      abuse.User        `json:"user"`
	Limit     int               `json:"limit"`
	Now       int               `json:"now"`
	Day       int               `json:"day"`
	Nodes     []string          `json:"nodes"`
	Level     abuse.Level       `json:"level"`
	Since     time.Time         `json:"since,omitzero"`
	BannedAt  time.Time         `json:"banned_at,omitzero"`
	BanFailed bool              `json:"ban_failed,omitempty"` // the panel refused the ban
	LastEvent *store.AbuseEvent `json:"last_event,omitempty"`
}

type AbuseView struct {
	Coverage AbuseCoverage `json:"coverage"`
	Rows     []AbuseRow    `json:"rows"`
}

// Abuse is the Antifraud page: everyone over a threshold now, and everyone
// with an event in the last week.
func (a *App) Abuse(ctx context.Context) AbuseView {
	r := &a.abuse
	r.mu.Lock()
	view := AbuseView{Coverage: r.cover, Rows: []AbuseRow{}}
	if cfg := a.Hub.Config(); cfg.Remnawave != nil {
		view.Coverage.Mode = cfg.Remnawave.Abuse.Effective().Mode
	}
	byID := map[int64]int{}
	for _, v := range r.verdicts {
		row := AbuseRow{User: v.User, Limit: v.Limit, Now: v.Now, Day: v.Day, Nodes: v.Nodes, Level: v.Level, Since: v.Since}
		if st := r.states[v.User.ID]; st.BanFailed {
			row.BanFailed = true
		} else {
			row.BannedAt = st.BannedAt
		}
		byID[v.User.ID] = len(view.Rows)
		view.Rows = append(view.Rows, row)
	}
	users, states := r.users, maps.Clone(r.states)
	r.mu.Unlock()
	evs, err := a.Store.AbuseEvents(ctx, 0, time.Now().Add(-7*24*time.Hour), 500)
	if err != nil {
		return view
	}
	for i := range evs {
		e := evs[i]
		if at, ok := byID[e.User]; ok {
			if view.Rows[at].LastEvent == nil {
				view.Rows[at].LastEvent = &e
			}
			continue
		}
		u, ok := users[e.User]
		if !ok {
			u = abuse.User{ID: e.User, Username: e.Username, Limit: e.Limit}
		}
		byID[e.User] = len(view.Rows)
		row := AbuseRow{User: u, Limit: e.Limit, Nodes: e.Nodes, Level: abuse.LevelOK, LastEvent: &e}
		if st := states[e.User]; st.BanFailed {
			row.BanFailed = true
		} else {
			row.BannedAt = st.BannedAt
		}
		view.Rows = append(view.Rows, row)
	}
	return view
}

// AbuseAddress is one address of a subscriber with its operator.
type AbuseAddress struct {
	abuse.Seen
	ASN string `json:"asn,omitempty"`
	Org string `json:"org,omitempty"`
}

// AbuseUserView is one subscriber's addresses and history, for admins only.
type AbuseUserView struct {
	User      abuse.User         `json:"user"`
	State     abuse.State        `json:"state"`
	Addresses []AbuseAddress     `json:"addresses"`
	Events    []store.AbuseEvent `json:"events"`
}

func (a *App) AbuseUser(ctx context.Context, id int64) (AbuseUserView, error) {
	r := &a.abuse
	r.mu.Lock()
	v := AbuseUserView{User: abuse.User{ID: id}, Addresses: []AbuseAddress{}}
	if u, ok := r.users[id]; ok {
		v.User = u
	}
	v.State = r.states[id]
	var seen []abuse.Seen
	if r.tr != nil {
		seen = r.tr.Addresses(id)
	}
	r.mu.Unlock()
	for i, s := range seen {
		x := AbuseAddress{Seen: s}
		if i < abuseMaxLookups {
			x.ASN, x.Org = a.abuseNetwork(ctx, s.Prefix)
		}
		v.Addresses = append(v.Addresses, x)
	}
	evs, err := a.Store.AbuseEvents(ctx, id, time.Time{}, 100)
	if err != nil {
		return v, err
	}
	v.Events = evs
	if v.Events == nil {
		v.Events = []store.AbuseEvent{}
	}
	return v, nil
}

// AbuseEnable turns a subscription back on in the panel and starts the
// user's count over.
func (a *App) AbuseEnable(ctx context.Context, id int64) error {
	c, ok := a.abuseClient()
	if !ok {
		return errors.New("Remnawave is not configured")
	}
	if err := c.EnableUser(ctx, id); err != nil {
		return err
	}
	// What was stored must be in memory first, or saving would wipe it.
	a.abuseLoad(ctx, time.Now().UTC(), a.Hub.Config().Remnawave.Abuse.Effective())
	r := &a.abuse
	r.mu.Lock()
	delete(r.states, id)
	if u, ok := r.users[id]; ok {
		users := maps.Clone(r.users)
		u.Status = "ACTIVE"
		users[id] = u
		r.users = users
	}
	username := r.users[id].Username
	r.mu.Unlock()
	a.abuseSaveStates(ctx)
	return a.Store.AddAbuseEvent(ctx, store.AbuseEvent{At: time.Now().UTC(), User: id, Username: username, Action: "enable"})
}

// AbuseAllow puts a user on the antifraud's allowlist.
func (a *App) AbuseAllow(ctx context.Context, id int64) error {
	a.mu.Lock()
	pinned := a.managed.sections[SectionRemnawave]
	a.mu.Unlock()
	if pinned {
		return invalid(errors.New("the Remnawave section is set in the config file: add the user to remnawave.abuse.allow_users there"))
	}
	cfg := a.Settings().Config
	if cfg.Remnawave == nil {
		return invalid(errors.New("Remnawave is not configured"))
	}
	rw := *cfg.Remnawave
	var rule abuse.Rule
	if rw.Abuse != nil {
		rule = *rw.Abuse
	}
	if !slices.Contains(rule.AllowUsers, id) {
		rule.AllowUsers = append(slices.Clone(rule.AllowUsers), id)
	}
	rw.Abuse = &rule
	cfg.Remnawave = &rw
	if err := a.SaveSettings(ctx, cfg); err != nil {
		return fmt.Errorf("save the allowlist: %w", err)
	}
	return nil
}

// abuseMark records how a ban went: disabled, the user directory says so
// (a fresh map: readers hold the old one without the lock); refused, the
// state says the ban failed so the page does not show the user as banned.
func (a *App) abuseMark(id int64, disabled bool) {
	r := &a.abuse
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.states[id]
	st.BanFailed = !disabled
	r.states[id] = st
	if u, ok := r.users[id]; ok && disabled {
		users := maps.Clone(r.users)
		u.Status = "DISABLED"
		users[id] = u
		r.users = users
	}
}

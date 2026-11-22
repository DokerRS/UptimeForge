package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wh3r3ar3you/uptimeforge/internal/abuse"
	"github.com/wh3r3ar3you/uptimeforge/internal/geoip"
	"github.com/wh3r3ar3you/uptimeforge/internal/hub"
	"github.com/wh3r3ar3you/uptimeforge/internal/notify"
	"github.com/wh3r3ar3you/uptimeforge/internal/store/pgtest"
)

// abusePanel is a Remnawave panel with two nodes and one subscriber (7,
// device limit 1) connected from n addresses; node b also carries the
// bridge address of node a, which is no client.
type abusePanel struct {
	ips       atomic.Int32
	down      atomic.Bool  // connections fail
	failDis   atomic.Bool  // disable answers 500
	usersDown atomic.Bool  // the user directory fails
	stale     atomic.Int32 // addresses user 7 left days ago, still listed by node a
	mu        sync.Mutex
	actions   []string
	*httptest.Server
}

func newAbusePanel(t *testing.T) *abusePanel {
	p := &abusePanel{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case path == "/api/nodes/":
			io.WriteString(w, `{"response":[
				{"uuid":"na","name":"DE-1","address":"194.26.229.27","isConnected":true,"usersOnline":10,"ips":[{"ip":"194.26.229.27"}]},
				{"uuid":"nb","name":"NL-1","address":"5.5.5.5","isConnected":true,"usersOnline":10}]}`)
		case path == "/api/system/stats" || path == "/api/system/stats/bandwidth":
			io.WriteString(w, `{"response":{}}`)
		case r.Method == "POST" && strings.HasPrefix(path, "/api/connections/by-node/"):
			if p.down.Load() {
				w.WriteHeader(502)
				io.WriteString(w, `{"message":"bad gateway"}`)
				return
			}
			fmt.Fprintf(w, `{"response":{"jobId":"job-%s"}}`, strings.TrimPrefix(path, "/api/connections/by-node/"))
		case r.Method == "GET" && path == "/api/connections/by-node/job-na":
			var ips []string
			// Live addresses were seen this minute; stale ones are what a node
			// keeps for days after the client left.
			fresh := time.Unix(0, abuseClock.Load()).UTC().Format(time.RFC3339)
			for i := range int(p.ips.Load()) {
				ips = append(ips, fmt.Sprintf(`{"ip":"83.1.0.%d","lastSeen":"%s"}`, i+1, fresh))
			}
			for i := range int(p.stale.Load()) {
				ips = append(ips, fmt.Sprintf(`{"ip":"83.2.%d.%d","lastSeen":"2026-11-20T00:00:00Z"}`, i/200, i%200+1))
			}
			fmt.Fprintf(w, `{"response":{"isCompleted":true,"isFailed":false,"result":{"users":[{"userId":7,"ips":[%s]},{"userId":8,"ips":[{"ip":"83.9.9.9","lastSeen":"%s"}]}]}}}`, strings.Join(ips, ","), fresh)
		case r.Method == "GET" && path == "/api/connections/by-node/job-nb":
			// The bridge (node a) carries its clients' traffic as user 7 too.
			fmt.Fprintf(w, `{"response":{"isCompleted":true,"isFailed":false,"result":{"users":[{"userId":7,"ips":[{"ip":"194.26.229.27","lastSeen":"%s"}]}]}}}`, time.Unix(0, abuseClock.Load()).UTC().Format(time.RFC3339))
		case path == "/api/users" && p.usersDown.Load():
			w.WriteHeader(500)
			io.WriteString(w, `{"message":"boom"}`)
		case path == "/api/users":
			io.WriteString(w, `{"response":{"total":2,"users":[
				{"id":7,"username":"saveoleshki","telegramId":8620400077,"status":"ACTIVE","tag":null,"hwidDeviceLimit":1,"vlessUuid":"11111111-2222-3333-4444-555555555555","subscriptionUrl":"https://sub/s3cr3t"},
				{"id":8,"username":"honest","telegramId":null,"status":"ACTIVE","tag":null,"hwidDeviceLimit":null}]}}`)
		case path == "/api/subscription-settings":
			io.WriteString(w, `{"response":{"hwidSettings":{"enabled":true,"fallbackDeviceLimit":5,"maxDevicesAnnounce":null}}}`)
		case r.Method == "POST" && (strings.HasSuffix(path, "/actions/disable") || strings.HasSuffix(path, "/actions/enable") || path == "/api/connections/drop"):
			body, _ := io.ReadAll(r.Body)
			p.mu.Lock()
			p.actions = append(p.actions, strings.TrimSpace(path+" "+string(body)))
			p.mu.Unlock()
			if strings.HasSuffix(path, "/disable") && p.failDis.Load() {
				w.WriteHeader(500)
				io.WriteString(w, `{"message":"boom"}`)
				return
			}
			io.WriteString(w, `{"response":{}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *abusePanel) acts() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.actions...)
}

var abuseT0 = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// abuseApp is an app on the panel with the antifraud's messages captured.
func abuseApp(t *testing.T, dbURL string, p *abusePanel, rule *abuse.Rule) (*App, func() []notify.AbuseNotice) {
	t.Helper()
	a := newApp(t, Options{DatabaseURL: dbURL, DataDir: t.TempDir()})
	t.Cleanup(func() { a.Store.Close() })
	ctx := context.Background()
	if err := a.SaveSettings(ctx, hub.Config{Remnawave: &hub.Remnawave{URL: p.URL, Token: "t", Abuse: rule}}); err != nil {
		t.Fatal(err)
	}
	a.refreshRemnawave(ctx)
	var mu sync.Mutex
	var sent []notify.AbuseNotice
	a.abuse.notify = func(_ context.Context, n notify.AbuseNotice) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, n)
		return nil
	}
	return a, func() []notify.AbuseNotice {
		mu.Lock()
		defer mu.Unlock()
		return append([]notify.AbuseNotice(nil), sent...)
	}
}

// abuseClock is the time of the round being run: the fake panel dates its
// live addresses with it.
var abuseClock atomic.Int64

func rounds(a *App, from, to int) {
	for i := from; i <= to; i++ {
		abuseClock.Store(abuseT0.Add(time.Duration(i) * time.Minute).UnixNano())
		a.abuseRound(context.Background(), abuseT0.Add(time.Duration(i)*time.Minute))
	}
}

func TestAbuseNotifiesOnceAfterTheHold(t *testing.T) {
	p := newAbusePanel(t)
	p.ips.Store(8) // limit 1: notify at 6
	a, sent := abuseApp(t, pgtest.URL(t), p, nil)
	rounds(a, 0, 14)
	if s := sent(); len(s) != 0 {
		t.Fatalf("before the hold: %+v", s)
	}
	rounds(a, 15, 40)
	s := sent()
	if len(s) != 1 {
		t.Fatalf("notices %+v", s)
	}
	n := s[0]
	// The bridge address on node b is no client: 8 addresses, not 9.
	if n.Action != "notify" || n.UserID != 7 || n.Username != "saveoleshki" || n.TelegramID != 8620400077 || n.Limit != 1 || n.Now != 8 || strings.Join(n.Nodes, ",") != "DE-1" {
		t.Fatalf("notice %+v", n)
	}
	if acts := p.acts(); len(acts) != 0 {
		t.Fatalf("notify mode touched the panel: %v", acts)
	}
	evs, _ := a.Store.AbuseEvents(context.Background(), 7, time.Time{}, 10)
	if len(evs) != 1 || evs[0].Action != "notify" {
		t.Fatalf("events %+v", evs)
	}
	view := a.Abuse(context.Background())
	if view.Coverage.Nodes != 2 || view.Coverage.Answered != 2 || len(view.Rows) != 1 || view.Rows[0].User.ID != 7 {
		t.Fatalf("view %+v", view)
	}
}

func TestAbuseBanDisablesThenDrops(t *testing.T) {
	p := newAbusePanel(t)
	p.ips.Store(12) // limit 1: ban at 11
	a, sent := abuseApp(t, pgtest.URL(t), p, &abuse.Rule{Mode: abuse.ModeBan})
	rounds(a, 0, 60)
	if acts := p.acts(); strings.Join(acts, "|") != `/api/users/7/actions/disable|/api/connections/drop {"dropBy":{"by":"userIds","userIds":[7]}}` {
		t.Fatalf("panel calls %v", acts)
	}
	s := sent()
	if len(s) != 2 || s[0].Action != "notify" || s[1].Action != "ban" || s[1].Error != "" {
		t.Fatalf("notices %+v", s)
	}

	// Unban by hand: the panel enables the user and the antifraud starts over.
	if err := a.AbuseEnable(context.Background(), 7); err != nil {
		t.Fatal(err)
	}
	if acts := p.acts(); acts[len(acts)-1] != "/api/users/7/actions/enable" {
		t.Fatalf("enable: %v", acts)
	}
}

func TestAbuseFailedBanDoesNotDrop(t *testing.T) {
	p := newAbusePanel(t)
	p.ips.Store(12)
	p.failDis.Store(true)
	a, sent := abuseApp(t, pgtest.URL(t), p, &abuse.Rule{Mode: abuse.ModeBan})
	rounds(a, 0, 60)
	if acts := p.acts(); len(acts) != 1 || !strings.HasSuffix(acts[0], "/disable") {
		t.Fatalf("panel calls %v", acts)
	}
	s := sent()
	if len(s) != 2 || s[1].Action != "ban" || !strings.Contains(s[1].Error, "HTTP 500") {
		t.Fatalf("notices %+v", s)
	}
	evs, _ := a.Store.AbuseEvents(context.Background(), 7, time.Time{}, 10)
	if len(evs) != 2 || evs[0].Action != "ban" || evs[0].Error == "" {
		t.Fatalf("events %+v", evs)
	}
	if v := a.Abuse(context.Background()); len(v.Rows) != 1 || !v.Rows[0].BanFailed || !v.Rows[0].BannedAt.IsZero() {
		t.Fatalf("a refused ban shows as %+v", v.Rows)
	}
}

func TestAbuseHoldSurvivesRestart(t *testing.T) {
	p := newAbusePanel(t)
	p.ips.Store(8)
	db := pgtest.URL(t)
	a, sentA := abuseApp(t, db, p, nil)
	rounds(a, 0, 9)
	b, sentB := abuseApp(t, db, p, nil) // the hub restarted
	rounds(b, 10, 14)
	if len(sentA())+len(sentB()) != 0 {
		t.Fatal("notified before the hold")
	}
	rounds(b, 15, 15)
	if s := sentB(); len(s) != 1 {
		t.Fatalf("the hold restarted from zero after a restart: %+v", s)
	}
	c, sentC := abuseApp(t, db, p, nil) // and again: the cooldown is remembered
	rounds(c, 16, 60)
	if s := sentC(); len(s) != 0 {
		t.Fatalf("told again after a restart: %+v", s)
	}
}

func TestAbusePanelDownDoesNothing(t *testing.T) {
	p := newAbusePanel(t)
	p.ips.Store(30)
	a, sent := abuseApp(t, pgtest.URL(t), p, &abuse.Rule{Mode: abuse.ModeBan})
	rounds(a, 0, 5)
	p.down.Store(true)
	rounds(a, 6, 90)
	if s := sent(); len(s) != 0 {
		t.Fatalf("acted blind: %+v", s)
	}
	if acts := p.acts(); len(acts) != 0 {
		t.Fatalf("panel actions while blind: %v", acts)
	}
	if v := a.Abuse(context.Background()); v.Coverage.Answered != 0 || v.Coverage.Error == "" {
		t.Fatalf("coverage %+v", v.Coverage)
	}
}

func TestAbuseOffDoesNotPoll(t *testing.T) {
	p := newAbusePanel(t)
	p.ips.Store(30)
	a, sent := abuseApp(t, pgtest.URL(t), p, &abuse.Rule{Mode: abuse.ModeOff})
	rounds(a, 0, 40)
	if len(sent()) != 0 || len(p.acts()) != 0 {
		t.Fatal("off mode acted")
	}
}

// The hub was down for 40 minutes: that time does not count towards a hold,
// so a restart is no shortcut to a ban.
func TestAbuseDowntimeDoesNotCount(t *testing.T) {
	p := newAbusePanel(t)
	p.ips.Store(8)
	db := pgtest.URL(t)
	a, _ := abuseApp(t, db, p, nil)
	rounds(a, 0, 9) // 9 minutes held
	b, sent := abuseApp(t, db, p, nil)
	rounds(b, 50, 54)
	if s := sent(); len(s) != 0 {
		t.Fatalf("downtime counted towards the hold: %+v", s)
	}
	rounds(b, 55, 55)
	if s := sent(); len(s) != 1 {
		t.Fatalf("the hold did not resume after downtime: %+v", s)
	}
}

// After a restart the user directory does not load: nobody is judged, and
// what was remembered (who was told, and when) is kept.
func TestAbuseNoDirectoryKeepsStates(t *testing.T) {
	p := newAbusePanel(t)
	p.ips.Store(8)
	db := pgtest.URL(t)
	a, _ := abuseApp(t, db, p, nil)
	rounds(a, 0, 16)
	p.usersDown.Store(true)
	b, sent := abuseApp(t, db, p, nil)
	rounds(b, 17, 40)
	if s := sent(); len(s) != 0 {
		t.Fatalf("judged without a directory: %+v", s)
	}
	st, _ := b.Store.LoadAbuseStates(context.Background())
	if st[7].NotifiedAt.IsZero() {
		t.Fatalf("states wiped: %+v", st)
	}
}

// The Antifraud page is read while a round bans someone (run with -race).
func TestAbusePageDuringBan(t *testing.T) {
	p := newAbusePanel(t)
	p.ips.Store(12)
	a, _ := abuseApp(t, pgtest.URL(t), p, &abuse.Rule{Mode: abuse.ModeBan})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			a.Abuse(context.Background())
			a.AbuseUser(context.Background(), 7)
		}
	}()
	rounds(a, 0, 35)
	<-done
}

// orgGeo puts every address in one operator.
type orgGeo struct{}

func (orgGeo) Country(context.Context, netip.Addr) (string, error) { return "ru", nil }
func (orgGeo) Network(_ context.Context, ip netip.Addr) (geoip.Network, error) {
	return geoip.Network{IP: ip, Country: "ru", ASN: "as8359", Org: "MTS PJSC"}, nil
}
func (orgGeo) Prepare(context.Context) error { return nil }

// The message carries every address of the window with its provider, from
// the hub's own database.
func TestAbuseNoticeHasAddressesAndProviders(t *testing.T) {
	p := newAbusePanel(t)
	p.ips.Store(8)
	a, sent := abuseApp(t, pgtest.URL(t), p, nil)
	a.geo = orgGeo{}
	rounds(a, 0, 15)
	s := sent()
	if len(s) != 1 {
		t.Fatalf("notices %+v", s)
	}
	n := s[0]
	if len(n.Addresses) != 8 || n.Addresses[0].IP == "" || n.Addresses[0].Org != "MTS PJSC" || n.Addresses[0].ASN != "as8359" {
		t.Fatalf("addresses %+v", n.Addresses)
	}
	if len(n.Operators) != 1 || n.Operators[0] != "MTS PJSC · 8" {
		t.Fatalf("operators %v", n.Operators)
	}
	v, _ := a.AbuseUser(context.Background(), 7)
	if len(v.Addresses) != 8 || v.Addresses[0].Org != "MTS PJSC" {
		t.Fatalf("page addresses %+v", v.Addresses)
	}
}

// A node keeps an address in its list for days after the client left (the
// panel's lastSeen says when it was last used): only addresses seen inside
// the window count, so a subscriber with 3 live addresses and 100 stale
// ones is no case at all.
func TestAbuseStaleEntriesDoNotCount(t *testing.T) {
	p := newAbusePanel(t)
	p.ips.Store(3)
	p.stale.Store(100)
	a, sent := abuseApp(t, pgtest.URL(t), p, nil)
	rounds(a, 0, 30)
	if s := sent(); len(s) != 0 {
		t.Fatalf("stale addresses counted: %+v", s)
	}
	if v, _ := a.AbuseUser(context.Background(), 7); len(v.Addresses) != 3 {
		t.Fatalf("addresses kept: %d, want the 3 live ones", len(v.Addresses))
	}
}

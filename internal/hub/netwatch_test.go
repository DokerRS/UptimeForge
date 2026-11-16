package hub

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/wh3r3ar3you/uptimeforge/internal/checks"
	"github.com/wh3r3ar3you/uptimeforge/internal/model"
)

// netHub is a hub that watches its own internet, with its local probe as the
// only one running "site" and an agent "de" running "node".
func netHub(t *testing.T) (*Hub, *recorder) {
	t.Helper()
	cfg := &Config{
		DataDir:  t.TempDir(),
		Baseline: []checks.Spec{{Type: "tcp", TCP: &checks.TCPParams{Address: "77.88.8.8:53"}}},
		Probes: []ProbeConfig{
			{ID: "hub", Name: "Hub", Local: true},
			{ID: "de", Token: "token-de-00123456789", Probing: true},
		},
		Checks: []CheckConfig{
			{Spec: checks.Spec{ID: "site", Type: "tcp", TCP: &checks.TCPParams{Address: "site.example:443"}}, Probes: []string{"id=hub"}},
			{Spec: checks.Spec{ID: "node", Type: "tcp", TCP: &checks.TCPParams{Address: "node.example:443"}}, Probes: []string{"id=de"}},
		},
	}
	if err := cfg.normalize(); err != nil {
		t.Fatal(err)
	}
	h, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	h.AddNotifier(rec)
	h.mu.Lock()
	for _, p := range h.probes {
		p.online, p.since = true, time.Now().Add(-time.Hour)
	}
	h.netWatch = true
	h.rebuild()
	h.mu.Unlock()
	return h, rec
}

func failSite(h *Hub) {
	for range 2 { // retries = 2
		h.Ingest("hub", []checks.Result{res("site", false)})
	}
}

// later is an answer of the watch that comes after what was just ingested.
func later() time.Time { return time.Now().Add(time.Millisecond) }

// earlier is an answer from before it.
func earlier() time.Time { return time.Now().Add(-time.Second) }

func woken(h *Hub) bool {
	select {
	case <-h.netWake:
		return true
	default:
		return false
	}
}

// The case behind a burst of alerts: the hub has no internet, so everything it
// checks itself fails. That is one fact about the hub, said once it lasts.
func TestHubWithoutInternetHoldsItsOwnFailures(t *testing.T) {
	h, rec := netHub(t)
	t0 := time.Now()
	h.hubNet(false, t0)
	failSite(h)
	h.tick()
	if ev := rec.find(model.EventOpen, "site"); ev != nil {
		t.Fatalf("a hub without internet alerted on its own check: %+v", ev.Incident)
	}
	if rec.find(model.EventOpen, "probe-net:hub") != nil {
		t.Fatal("a few seconds without internet are not news")
	}
	h.hubNet(false, t0.Add(netAlertAfter))
	ev := rec.find(model.EventOpen, "probe-net:hub")
	if ev == nil || ev.Incident.Kind != model.KindProbeNoNet {
		t.Fatalf("a hub offline for %s says so: %+v", netAlertAfter, ev)
	}
	if rec.find(model.EventOpen, "site") != nil {
		t.Fatal("still no alert on the hub's own check")
	}
	h.hubNet(true, t0.Add(time.Minute))
	if rec.find(model.EventResolve, "probe-net:hub") == nil {
		t.Fatal("the hub's internet is back: its incident resolves")
	}
}

// What the hub measured without internet is no news once it is back: the
// 20 "node down" alerts at the moment the line came up.
func TestHubBackOnlineForgetsItsBlindResults(t *testing.T) {
	h, rec := netHub(t)
	h.hubNet(false, earlier())
	failSite(h)
	h.hubNet(true, later())
	h.tick()
	if ev := rec.find(model.EventOpen, "site"); ev != nil {
		t.Fatalf("results from without internet counted after it came back: %+v", ev.Incident)
	}
	// A real failure after it is back still alerts.
	failSite(h)
	h.hubNet(true, later())
	if ev := rec.find(model.EventOpen, "site"); ev == nil || ev.Incident.Kind != model.KindDown {
		t.Fatalf("a failure seen with internet must alert: %+v", ev)
	}
}

// A failure the hub sees itself counts only once its internet is confirmed
// after it: the hub's line may have dropped a moment ago, unnoticed yet.
func TestHubFailureWaitsForItsInternetCheck(t *testing.T) {
	h, rec := netHub(t)
	h.hubNet(true, earlier())
	woken(h) // drain
	failSite(h)
	if rec.find(model.EventOpen, "site") != nil {
		t.Fatal("alerted before the hub's internet was confirmed")
	}
	if !woken(h) {
		t.Fatal("a failure on the hub asks for an internet check at once")
	}
	h.tick()
	if rec.find(model.EventOpen, "site") != nil {
		t.Fatal("a tick does not confirm the internet")
	}
	h.hubNet(true, later())
	if ev := rec.find(model.EventOpen, "site"); ev == nil || ev.Incident.Kind != model.KindDown {
		t.Fatalf("confirmed internet lets the failure through: %+v", ev)
	}
	// Further results of the same outage need no new confirmation.
	h.Ingest("hub", []checks.Result{res("site", false)})
	h.tick()
	if rec.find(model.EventResolve, "site") != nil {
		t.Fatal("the open incident must not flap while the hub keeps seeing it")
	}

	// The same failure with the line gone instead: no alert.
	h2, rec2 := netHub(t)
	h2.hubNet(true, earlier())
	failSite(h2)
	h2.hubNet(false, later())
	h2.tick()
	if rec2.find(model.EventOpen, "site") != nil {
		t.Fatal("the internet check said the hub is offline: no alert on its check")
	}
}

// A hub without internet sees no agent; that is not every agent going offline.
func TestAgentsNotOfflineWhileHubOffline(t *testing.T) {
	h, rec := netHub(t)
	h.MarkSeen([]string{"de"})
	h.mu.Lock()
	p := h.probes["de"]
	p.online, p.since = false, time.Now().Add(-time.Hour)
	h.mu.Unlock()

	h.hubNet(false, time.Now())
	h.tick()
	if rec.find(model.EventOpen, "probe:de") != nil {
		t.Fatal("agent called offline while the hub had no internet")
	}
	h.hubNet(true, later())
	h.tick()
	if rec.find(model.EventOpen, "probe:de") != nil {
		t.Fatal("agents get time to reconnect once the hub is back")
	}
	h.mu.Lock()
	h.net.back = time.Now().Add(-startupGrace - time.Second)
	h.mu.Unlock()
	h.tick()
	if rec.find(model.EventOpen, "probe:de") == nil {
		t.Fatal("an agent still away after the grace is offline")
	}
}

// A hub that boots before its line is up (the 13:51 reboot) has no answer
// yet: its own failures wait for one.
func TestHubFailureBeforeFirstAnswerWaits(t *testing.T) {
	h, rec := netHub(t)
	failSite(h)
	h.tick()
	if rec.find(model.EventOpen, "site") != nil {
		t.Fatal("alerted before the hub's internet was ever checked")
	}
	h.hubNet(true, later())
	if rec.find(model.EventOpen, "site") == nil {
		t.Fatal("the first answer with internet lets it through")
	}
}

// A baseline with no TCP target to dial turns the watch off: the baseline
// checks decide for the hub's probes again.
func TestNetOffHandsBackToBaseline(t *testing.T) {
	h, _ := netHub(t)
	h.hubNet(false, time.Now())
	h.netOff()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.netWatch || h.probes["hub"].noNet {
		t.Fatal("with the watch off the hub's probe is not held as offline")
	}
}

func TestNetAddrsAndReachable(t *testing.T) {
	addrs := netAddrs([]checks.Spec{
		{Type: "tcp", TCP: &checks.TCPParams{Address: "1.1.1.1:443"}},
		{Type: "http", HTTP: &checks.HTTPParams{URL: "https://example.com"}},
		{Type: "tcp", TCP: &checks.TCPParams{Address: "8.8.8.8:443"}},
	})
	if len(addrs) != 2 || addrs[0] != "1.1.1.1:443" || addrs[1] != "8.8.8.8:443" {
		t.Fatalf("netAddrs: %v", addrs)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := closed.Addr().String()
	closed.Close()

	ctx := context.Background()
	if !reachable(ctx, []string{dead, ln.Addr().String()}, time.Second) {
		t.Fatal("one answering address is internet")
	}
	if reachable(ctx, []string{dead}, time.Second) {
		t.Fatal("no answering address is no internet")
	}
}

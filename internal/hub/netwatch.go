package hub

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/wh3r3ar3you/uptimeforge/internal/checks"
	"github.com/wh3r3ar3you/uptimeforge/internal/model"
)

// The hub watches its own internet. Without it every check the hub runs
// itself fails and every agent drops at once: one fact about the hub, not
// thirty alerts that reach Telegram after the line is back.
//
// While the hub has no internet, its virtual probes (the local one and those
// behind a proxy) stay out of verdicts and no agent counts as offline; after
// netAlertAfter the local probe opens probe-net. A failure the hub sees
// itself counts only once the internet is confirmed after it, and what it
// measured blind is forgotten when the line comes back, which also gives
// agents startupGrace to reconnect.
//
// The watch dials the TCP targets of the baseline (any answer is internet)
// every netEvery and at once when the hub sees something fail. Without a TCP
// baseline it is off and the baseline checks decide, as for agents.

const (
	netEvery      = 10 * time.Second
	netTimeout    = 3 * time.Second
	netMinGap     = 2 * time.Second // between two rounds, however many wakes
	netAlertAfter = 30 * time.Second
)

type hubNet struct {
	known bool
	up    bool
	at    time.Time // the last answer
	since time.Time // the current state began
	back  time.Time // the internet came back after an outage
}

// netAddrs are the TCP targets of the baseline.
func netAddrs(base []checks.Spec) []string {
	var out []string
	for _, s := range base {
		if s.Type == "tcp" && s.TCP != nil && s.TCP.Address != "" {
			out = append(out, s.TCP.Address)
		}
	}
	return out
}

// reachable says whether any of addrs accepts a TCP connection within timeout.
func reachable(ctx context.Context, addrs []string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ok := make(chan bool, len(addrs))
	var d net.Dialer
	for _, a := range addrs {
		go func() {
			c, err := d.DialContext(ctx, "tcp", a)
			if err == nil {
				c.Close()
			}
			ok <- err == nil
		}()
	}
	for range addrs {
		if <-ok {
			return true
		}
	}
	return false
}

// watchNet runs the watch until ctx ends.
func (h *Hub) watchNet(ctx context.Context) {
	t := time.NewTicker(netEvery)
	defer t.Stop()
	var last time.Time
	for {
		if wait := netMinGap - time.Since(last); wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
		h.mu.Lock()
		addrs := netAddrs(h.cfg.Baseline)
		h.mu.Unlock()
		last = time.Now()
		if len(addrs) > 0 {
			up := reachable(ctx, addrs, netTimeout)
			if ctx.Err() != nil {
				return
			}
			h.hubNet(up, time.Now())
		} else {
			h.netOff()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-h.netWake:
		}
	}
}

// wakeNet asks for a round now. It never blocks; callers may hold h.mu.
func (h *Hub) wakeNet() {
	select {
	case h.netWake <- struct{}{}:
	default:
	}
}

// netOff hands the verdict back to the baseline checks: the baseline has no
// TCP target left to dial.
func (h *Hub) netOff() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.netWatch {
		return
	}
	h.netWatch, h.net = false, hubNet{}
	for _, p := range h.probes {
		if p.cfg.Virtual() {
			p.noNet = false
		}
	}
}

// netConfirmed says the hub had internet at an answer after t.
func (h *Hub) netConfirmed(t time.Time) bool {
	return h.net.known && h.net.up && h.net.at.After(t)
}

// hubNet takes one answer of the watch.
func (h *Hub) hubNet(up bool, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.netWatch = true
	prev := h.net
	h.net.known, h.net.up, h.net.at = true, up, now
	changed := !prev.known || prev.up != up
	if changed {
		h.net.since = now
	}
	cameBack := up && prev.known && !prev.up
	if cameBack {
		h.net.back = now
		h.log.Info("the hub has internet again", "after", now.Sub(prev.since).Round(time.Second))
	} else if changed && !up {
		h.log.Warn("the hub has no internet: its own checks wait and agents are not called offline")
	}
	for _, p := range h.probes {
		if !p.cfg.Virtual() {
			continue
		}
		p.noNet = !up
		if cameBack {
			// What it measured blind is no news: it starts over as if it had
			// just come up.
			p.since = now
			for _, ch := range h.checks {
				delete(ch.state, p.cfg.ID)
			}
		}
	}

	if local := h.localProbe(); local != nil {
		key := "probe-net:" + local.cfg.ID
		switch {
		case !up && now.Sub(h.net.since) >= netAlertAfter:
			h.transition(key, model.KindProbeNoNet, "",
				[]model.ProbeLine{h.probeLine(local, false, "baseline", "no answer from "+strings.Join(netAddrs(h.cfg.Baseline), ", "))},
				meta{name: local.cfg.Name, typ: "probe", severity: "warning"}, now)
		case up && h.incidents[key] != nil:
			h.transition(key, model.KindOK, "", []model.ProbeLine{h.probeLine(local, true, "", "")},
				meta{name: local.cfg.Name, typ: "probe", severity: "warning"}, now)
		}
	}
	if up || changed {
		// Up releases failures that waited for this answer; a change moves
		// the virtual probes in or out of every verdict.
		h.evaluateAll(now)
	}
}

// localProbe is the hub's own probe, if it has one. Callers hold h.mu.
func (h *Hub) localProbe() *probe {
	for _, id := range h.probeOrder {
		if p := h.probes[id]; p.cfg.Local {
			return p
		}
	}
	return nil
}

// offlineDue says agent p has been away long enough to count as offline. A
// hub without internet cannot tell, and once it is back every agent gets the
// time to reconnect it gets after a restart. Callers hold h.mu.
func (h *Hub) offlineDue(p *probe, now time.Time) bool {
	from := p.since
	if h.netWatch {
		if !h.net.known || !h.net.up {
			return false
		}
		if h.net.back.After(from) {
			from = h.net.back
		}
	}
	return now.Sub(from) > h.offlineAfter(p)
}

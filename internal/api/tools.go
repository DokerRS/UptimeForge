package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/wh3r3ar3you/uptimeforge/internal/checks"
	"github.com/wh3r3ar3you/uptimeforge/internal/hub"
	"github.com/wh3r3ar3you/uptimeforge/internal/xray"
)

type runRequest struct {
	Target    string   `json:"target"`
	Probes    []string `json:"probes"`
	Mode      string   `json:"mode"` // "auto" or "subscription"
	UserAgent string   `json:"user_agent"`
}

type runRow struct {
	Name     string           `json:"name"`
	Target   string           `json:"target"`
	Type     string           `json:"type"`
	Outcomes []hub.RunOutcome `json:"outcomes"`
	Error    string           `json:"error,omitempty"`
}

const maxSubscriptionRows = 100

// subscriptionRowTimeout bounds the check of one config of a subscription
// test; the configs go one at a time.
const subscriptionRowTimeout = 5 * time.Second

// SpecFor turns whatever the user pasted into a check: a share link, an
// http(s) URL, a tg:// MTProxy link or host:port.
func SpecFor(target string) (checks.Spec, error) {
	target = strings.TrimSpace(target)
	spec := checks.Spec{ID: "_run", Timeout: checks.Duration(25 * time.Second)}
	scheme, _, hasScheme := strings.Cut(target, "://")
	scheme = strings.ToLower(scheme)
	switch {
	case hasScheme && (scheme == "http" || scheme == "https"):
		if mt := mtprotoSpec(target); mt != nil {
			return *mt, nil
		}
		spec.Type, spec.HTTP = "http", &checks.HTTPParams{URL: target}
	case hasScheme && scheme == "tg":
		if mt := mtprotoSpec(target); mt != nil {
			return *mt, nil
		}
		return spec, errors.New("this tg:// link is not an MTProxy link")
	case hasScheme:
		if _, err := xray.ParseLink(target); err != nil {
			return spec, err
		}
		spec.Type, spec.Xray = "xray", &checks.XrayParams{Link: target}
	default:
		if _, _, err := net.SplitHostPort(target); err != nil {
			return spec, errors.New("paste a share link (vless://, vmess://, trojan://, ss://, hy2://), an http(s) URL, a tg://proxy link or host:port")
		}
		spec.Type, spec.TCP = "tcp", &checks.TCPParams{Address: target}
	}
	return spec, nil
}

func (s *Server) runTool(w http.ResponseWriter, r *http.Request) {
	var req runRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, err)
		return
	}
	if req.Mode == "subscription" {
		s.runSubscription(w, r, req)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	spec, err := SpecFor(req.Target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	row := runRow{Name: req.Target, Target: spec.Target(), Type: spec.Type}
	if spec.Xray != nil {
		if l, err := xray.ParseLink(req.Target); err == nil {
			row.Name, row.Target = pick(l.Name, l.Endpoint()), strings.ToUpper(l.Protocol)+" · "+l.Endpoint()
		}
	}
	row.Outcomes = s.app.Hub.RunOnce(ctx, spec, req.Probes)
	writeJSON(w, http.StatusOK, map[string]any{"rows": []runRow{row}})
}

// runSubscription checks every config of a subscription, one at a time, each
// on every picked probe at once within subscriptionRowTimeout. One at a time
// keeps an agent to one of them (an agent refuses checks on demand past a
// few), and a dead config costs its 5 s, not a slot others wait for.
//
// The answer is NDJSON, so a long subscription shows as it goes: first
// {"rows": [...]} with every config and no outcomes, then {"row": i,
// "outcomes": [...]} per config in order, then {"done": true}. Closing the
// request stops the run.
func (s *Server) runSubscription(w http.ResponseWriter, r *http.Request, req runRequest) {
	fctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	entries, err := xray.FetchSubscription(fctx, &http.Client{}, strings.TrimSpace(req.Target), req.UserAgent)
	cancel()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(entries) > maxSubscriptionRows {
		entries = entries[:maxSubscriptionRows]
	}
	rows := make([]runRow, len(entries))
	for i, e := range entries {
		proto, _ := e.Outbound["protocol"].(string)
		rows[i] = runRow{Name: e.Name, Target: strings.ToUpper(proto) + " · " + e.Endpoint, Type: "xray", Outcomes: []hub.RunOutcome{}}
	}

	// A run of 100 configs outlives any server-wide deadline (see liveStream).
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "application/x-ndjson")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	send := func(v any) bool { return enc.Encode(v) == nil && rc.Flush() == nil }

	if !send(map[string]any{"rows": rows}) {
		return
	}
	for i, e := range entries {
		if r.Context().Err() != nil {
			return
		}
		spec := checks.Spec{ID: "_run", Type: "xray", Timeout: checks.Duration(subscriptionRowTimeout), Xray: &checks.XrayParams{Outbound: e.Outbound}}
		if !send(map[string]any{"row": i, "outcomes": s.app.Hub.RunOnce(r.Context(), spec, req.Probes)}) {
			return
		}
	}
	send(map[string]any{"done": true})
}

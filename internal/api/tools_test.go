package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wh3r3ar3you/uptimeforge/internal/hub"
)

// runTyped posts a typed check to the Tools run endpoint.
func runTyped(t *testing.T, c *client, base string, check map[string]any) (*http.Response, map[string][]runRow) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"check": check, "probes": []string{"hub"}})
	req, _ := http.NewRequest("POST", base+"/api/v1/tools/run", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string][]runRow
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

// Tools runs any check a probe can run, typed with the same fields as the
// check form: a port, a ping, a DNS name, a site with a keyword.
func TestToolRunsTypedCheck(t *testing.T) {
	_, srv, _ := startHub(t)
	c := newClient(t, srv.URL)
	setupAdmin(c)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	open := ln.Addr().String()
	ln.Close()
	ln, _ = net.Listen("tcp", open)
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	resp, out := runTyped(t, c, srv.URL, map[string]any{"type": "tcp", "tcp": map[string]any{"address": open}})
	rows := out["rows"]
	if resp.StatusCode != 200 || len(rows) != 1 || rows[0].Type != "tcp" || rows[0].Target != open || len(rows[0].Outcomes) != 1 {
		t.Fatalf("status %d rows %+v", resp.StatusCode, rows)
	}
	if r := rows[0].Outcomes[0].Result; r == nil || r.Status != "up" {
		t.Fatalf("open port: %+v", rows[0].Outcomes[0])
	}

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("hello world")) }))
	defer site.Close()
	_, out = runTyped(t, c, srv.URL, map[string]any{"type": "http", "http": map[string]any{"url": site.URL, "keyword": "missing"}})
	if r := out["rows"][0].Outcomes[0].Result; r == nil || r.Status == "up" {
		t.Fatalf("keyword not on the page passed: %+v", out["rows"][0].Outcomes[0])
	}

	for name, bad := range map[string]map[string]any{
		"no address":   {"type": "tcp", "tcp": map[string]any{}},
		"hub only":     {"type": "push", "params": map[string]any{"token": "abc"}},
		"unknown type": {"type": "nope"},
		"subscription": {"type": "xray", "xray": map[string]any{"subscription": site.URL}},
	} {
		if resp, _ := runTyped(t, c, srv.URL, bad); resp.StatusCode != 400 {
			t.Errorf("%s: status %d, want 400", name, resp.StatusCode)
		}
	}
}

// A subscription test goes one config at a time, each on every picked probe
// at once and within subscriptionRowTimeout, and streams the rows as they are
// done: the table shows first, then fills. An agent never gets more than one
// config of it at a time, so none is refused for running too many.
func TestSubscriptionToolStreamsOneConfigAtATime(t *testing.T) {
	_, srv, _ := startHub(t)
	c := newClient(t, srv.URL)
	setupAdmin(c)

	var links strings.Builder
	const n = 6
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&links, "vless://11111111-2222-3333-4444-555555555555@127.0.0.1:1?security=none#cfg-%d\n", i)
	}
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(links.String())) }))
	defer sub.Close()

	body, _ := json.Marshal(map[string]any{"target": sub.URL + "/sub/abc", "mode": "subscription", "probes": []string{"hub"}})
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/tools/run", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/x-ndjson") {
		t.Fatalf("status %d, content type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	var lines []map[string]json.RawMessage
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		lines = append(lines, m)
	}
	if len(lines) != n+2 {
		t.Fatalf("%d lines, want the list, %d rows and done", len(lines), n)
	}
	var rows []runRow
	if err := json.Unmarshal(lines[0]["rows"], &rows); err != nil || len(rows) != n || rows[0].Name != "cfg-1" {
		t.Fatalf("first line lists %+v (%v)", rows, err)
	}
	for i := 0; i < n; i++ {
		var at int
		var outs []hub.RunOutcome
		if json.Unmarshal(lines[i+1]["row"], &at) != nil || at != i || json.Unmarshal(lines[i+1]["outcomes"], &outs) != nil {
			t.Fatalf("line %d: %s", i+1, lines[i+1])
		}
		if len(outs) != 1 || outs[0].Result == nil || outs[0].Result.Status != "down" || outs[0].Result.Reason == "unavailable" {
			t.Fatalf("row %d: %+v", i, outs)
		}
		if d := time.Duration(outs[0].Result.LatencyMS * float64(time.Millisecond)); d > subscriptionRowTimeout+2*time.Second {
			t.Fatalf("row %d took %s", i, d)
		}
	}
	if string(lines[n+1]["done"]) != "true" {
		t.Fatalf("last line %s", lines[n+1])
	}
}

package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wh3r3ar3you/uptimeforge/internal/hub"
)

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

package xray

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// An Xray JSON config with a balancer carries several proxy outbounds; every
// one of them is a server to check, not just the first. A server in several
// configs (its own and a balancer's) is checked once, under the first name.
func TestDecodeXrayJSONBalancerOutbounds(t *testing.T) {
	vless := func(tag, host string) string {
		return `{"tag":"` + tag + `","protocol":"vless","settings":{"vnext":[{"address":"` + host +
			`","port":443,"users":[{"id":"x","encryption":"none"}]}]},"mux":{"enabled":false}}`
	}
	js := `[
	 {"remarks":"🇩🇪 Germany","outbounds":[` + vless("proxy", "de.example") + `,{"tag":"direct","protocol":"freedom"}]},
	 {"remarks":"⚡ Auto","outbounds":[` +
		vless("proxy-1", "nl.example") + `,` + vless("proxy-2", "de.example") + `,` + vless("proxy-3", "fi.example") +
		`,{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],
	  "routing":{"balancers":[{"tag":"auto","selector":["proxy-"]}]}}
	]`
	got, err := DecodeSubscription([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	var names, ends []string
	for _, e := range got {
		names, ends = append(names, e.Name), append(ends, e.Endpoint)
		if _, ok := e.Outbound["tag"]; ok {
			t.Fatalf("%s keeps its tag: %v", e.Name, e.Outbound)
		}
	}
	want := []string{"de.example:443", "nl.example:443", "fi.example:443"}
	if strings.Join(ends, " ") != strings.Join(want, " ") {
		t.Fatalf("endpoints %v, want %v", ends, want)
	}
	if names[0] != "🇩🇪 Germany" || names[1] != "⚡ Auto · proxy-1" || names[2] != "⚡ Auto · proxy-3" {
		t.Fatalf("names %q", names)
	}
}

// A panel with a device limit (Remnawave HWID) answers a request without
// x-hwid with a single stub host. The hub sends one HWID per subscription,
// the same on every fetch so it takes one device slot, not one per run, and
// one that does not give the subscription URL away.
func TestFetchSubscriptionSendsStableHWID(t *testing.T) {
	var mu sync.Mutex
	seen := map[string][]http.Header{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = append(seen[r.URL.Path], r.Header.Clone())
		mu.Unlock()
		if r.Header.Get("x-hwid") == "" {
			_, _ = w.Write([]byte("vless://u@stub.example:443?security=none#HWID%20required\n"))
			return
		}
		_, _ = w.Write([]byte("vless://u@a.example:443?security=none#a\nvless://u@b.example:443?security=none#b\n"))
	}))
	defer srv.Close()

	ctx := context.Background()
	for i := 0; i < 2; i++ {
		got, err := FetchSubscription(ctx, srv.Client(), srv.URL+"/sub/token-one", "")
		if err != nil || len(got) != 2 {
			t.Fatalf("fetch %d: %d entries, %v (want the 2 real hosts, not the HWID stub)", i, len(got), err)
		}
	}
	if _, err := FetchSubscription(ctx, srv.Client(), srv.URL+"/sub/token-two", ""); err != nil {
		t.Fatal(err)
	}

	one, two := seen["/sub/token-one"], seen["/sub/token-two"]
	if len(one) != 2 || len(two) != 1 {
		t.Fatalf("requests: %d and %d", len(one), len(two))
	}
	h1, h2 := one[0].Get("x-hwid"), two[0].Get("x-hwid")
	if h1 != one[1].Get("x-hwid") {
		t.Fatalf("HWID changes between fetches: %q, %q", h1, one[1].Get("x-hwid"))
	}
	if h1 == h2 {
		t.Fatalf("two subscriptions share HWID %q", h1)
	}
	if strings.Contains(h1, "token-one") {
		t.Fatalf("HWID %q gives the subscription URL away", h1)
	}
	if one[0].Get("x-device-os") == "" || one[0].Get("x-device-model") == "" {
		t.Fatalf("no device description: %v", one[0])
	}
}

package remnawave

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePanel answers the antifraud endpoints the way Remnawave 3.4 does.
type fakePanel struct {
	mu      sync.Mutex
	calls   []string // "METHOD path body"
	polls   int      // GETs of a job before it completes
	failJob bool
}

func (f *fakePanel) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.calls = append(f.calls, strings.TrimSpace(r.Method+" "+r.URL.Path+" "+string(body)))
		f.mu.Unlock()
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/connections/by-node/node-1":
			w.WriteHeader(201)
			fmt.Fprint(w, `{"response":{"jobId":"job-1"}}`)
		case r.Method == "GET" && r.URL.Path == "/api/connections/by-node/job-1":
			f.mu.Lock()
			f.polls++
			done := f.polls >= 2
			f.mu.Unlock()
			if f.failJob {
				fmt.Fprint(w, `{"response":{"isCompleted":true,"isFailed":true,"result":null}}`)
				return
			}
			if !done {
				fmt.Fprint(w, `{"response":{"isCompleted":false,"isFailed":false,"result":null}}`)
				return
			}
			fmt.Fprint(w, `{"response":{"isCompleted":true,"isFailed":false,"result":{"success":true,"nodeUuid":"node-1","users":[
				{"userId":7,"ips":[{"ip":"83.149.47.17","lastSeen":"2026-11-20T09:56:11.000Z"},{"ip":"2a00:1fa0::1","lastSeen":"2026-11-22T09:56:11.000Z"}]},
				{"userId":9,"ips":[{"ip":"5.6.7.8","lastSeen":"2026-11-22T09:56:11.000Z"}]}]}}}`)
		case r.Method == "GET" && r.URL.Path == "/api/users":
			start := r.URL.Query().Get("start")
			if r.URL.Query().Get("size") != "1000" {
				t.Errorf("page size %q", r.URL.Query().Get("size"))
			}
			if start == "0" {
				fmt.Fprint(w, `{"response":{"total":2,"users":[{"id":7,"uuid":"u7","username":"saveoleshki","telegramId":8620400077,"status":"ACTIVE","tag":null,"hwidDeviceLimit":1,
					"vlessUuid":"11111111-2222-3333-4444-555555555555","trojanPassword":"trojan-secret","ssPassword":"ss-secret","subscriptionUrl":"https://sub.example/s3cr3t"}]}}`)
				return
			}
			fmt.Fprint(w, `{"response":{"total":2,"users":[{"id":9,"username":"bob","telegramId":null,"status":"DISABLED","tag":"WHITELIST","hwidDeviceLimit":null,"vlessUuid":"x"}]}}`)
		case r.Method == "GET" && r.URL.Path == "/api/subscription-settings":
			fmt.Fprint(w, `{"response":{"uuid":"s","hwidSettings":{"enabled":true,"fallbackDeviceLimit":5,"maxDevicesAnnounce":null}}}`)
		case r.Method == "POST" && (r.URL.Path == "/api/users/7/actions/disable" || r.URL.Path == "/api/users/7/actions/enable"):
			fmt.Fprint(w, `{"response":{"id":7,"status":"DISABLED","vlessUuid":"leak"}}`)
		case r.Method == "POST" && r.URL.Path == "/api/connections/drop":
			w.WriteHeader(202)
			fmt.Fprint(w, `{"response":{"eventSent":true}}`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, `{"message":"no route","errorCode":"X"}`)
		}
	})
}

func TestNodeConnectionsWaitsForTheJob(t *testing.T) {
	f := &fakePanel{}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	c := New(srv.URL, token)
	c.JobPoll = 0
	got, err := c.NodeConnections(context.Background(), "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(got[7]) != 2 || got[7][0].IP != "83.149.47.17" || got[7][1].IP != "2a00:1fa0::1" || got[9][0].IP != "5.6.7.8" ||
		!got[7][0].LastSeen.Equal(time.Date(2026, 11, 20, 9, 56, 11, 0, time.UTC)) {
		t.Fatalf("got %v", got)
	}
	if f.polls != 2 {
		t.Fatalf("polled %d times", f.polls)
	}

	f2 := &fakePanel{failJob: true}
	srv2 := httptest.NewServer(f2.handler(t))
	defer srv2.Close()
	c2 := New(srv2.URL, token)
	c2.JobPoll = 0
	if _, err := c2.NodeConnections(context.Background(), "node-1"); err == nil {
		t.Fatal("a failed job gave no error")
	}
}

func TestAbuseUsersReadsNoSecrets(t *testing.T) {
	f := &fakePanel{}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	c := New(srv.URL, token)
	users, err := c.AbuseUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("users %+v", users)
	}
	u := users[0]
	if u.ID != 7 || u.Username != "saveoleshki" || u.TelegramID != 8620400077 || u.Status != "ACTIVE" || u.DeviceLimit == nil || *u.DeviceLimit != 1 {
		t.Fatalf("user 7 %+v", u)
	}
	if b := users[1]; b.DeviceLimit != nil || b.Tag != "WHITELIST" || b.TelegramID != 0 {
		t.Fatalf("user 9 %+v", b)
	}
	dump, _ := json.Marshal(users)
	for _, secret := range []string{"11111111-2222", "trojan-secret", "ss-secret", "s3cr3t"} {
		if strings.Contains(fmt.Sprintf("%+v", users)+string(dump), secret) {
			t.Fatalf("a secret field was read: %s", secret)
		}
	}
	limit, err := c.FallbackDeviceLimit(context.Background())
	if err != nil || limit != 5 {
		t.Fatalf("fallback %d %v", limit, err)
	}
}

func TestUserActions(t *testing.T) {
	f := &fakePanel{}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	c := New(srv.URL, token)
	ctx := context.Background()
	if err := c.DisableUser(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if err := c.DropUserConnections(ctx, []int64{7}); err != nil {
		t.Fatal(err)
	}
	if err := c.EnableUser(ctx, 7); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /api/users/7/actions/disable",
		`POST /api/connections/drop {"dropBy":{"by":"userIds","userIds":[7]}}`,
		"POST /api/users/7/actions/enable",
	}
	if strings.Join(f.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(f.calls, "\n"))
	}
	err := c.DisableUser(ctx, 8)
	var ae *APIError
	if err == nil || !strings.Contains(err.Error(), "POST /api/users/8/actions/disable: HTTP 404") || !asAPIError(err, &ae) {
		t.Fatalf("error %v", err)
	}
}

func asAPIError(err error, out **APIError) bool {
	e, ok := err.(*APIError)
	*out = e
	return ok
}

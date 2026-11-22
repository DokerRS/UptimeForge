package api

import (
	"net/http"
	"testing"
)

// The antifraud shows client addresses: only admins may see it or act on it.
func TestAbuseIsAdminOnly(t *testing.T) {
	_, srv, _ := startHub(t)
	c := newClient(t, srv.URL)
	setupAdmin(c)

	var view struct {
		Coverage struct {
			Mode string `json:"mode"`
		} `json:"coverage"`
		Rows []any `json:"rows"`
	}
	if code := c.do("GET", "/api/v1/abuse", nil, &view); code != 200 || view.Rows == nil {
		t.Fatalf("admin list: %d %+v", code, view)
	}
	var user struct {
		User struct {
			ID int64 `json:"id"`
		} `json:"user"`
		Addresses []any `json:"addresses"`
		Events    []any `json:"events"`
	}
	if code := c.do("GET", "/api/v1/abuse/7", nil, &user); code != 200 || user.User.ID != 7 || user.Addresses == nil || user.Events == nil {
		t.Fatalf("admin user: %d %+v", code, user)
	}
	if code := c.do("GET", "/api/v1/abuse/x", nil, nil); code != http.StatusBadRequest {
		t.Fatalf("bad id: %d", code)
	}
	// No panel configured: nothing to enable, nothing to allow.
	if code := c.do("POST", "/api/v1/abuse/7/enable", nil, nil); code < 400 {
		t.Fatalf("enable without a panel: %d", code)
	}

	c.do("POST", "/api/v1/users", map[string]string{"username": "viewer", "password": "viewer-pass", "role": "viewer"}, nil)
	v := newClient(t, srv.URL)
	if code := v.do("POST", "/api/v1/auth/login", map[string]string{"username": "viewer", "password": "viewer-pass"}, nil); code != 200 {
		t.Fatalf("viewer login: %d", code)
	}
	for _, r := range [][2]string{{"GET", "/api/v1/abuse"}, {"GET", "/api/v1/abuse/7"}, {"POST", "/api/v1/abuse/7/enable"}, {"POST", "/api/v1/abuse/7/allow"}} {
		if code := v.do(r[0], r[1], nil, nil); code != http.StatusForbidden {
			t.Errorf("viewer %s %s: %d", r[0], r[1], code)
		}
	}
}

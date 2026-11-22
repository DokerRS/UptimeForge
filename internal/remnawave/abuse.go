package remnawave

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// Conn is one client address of a user on a node. LastSeen is when the
// address was last used: a node keeps an address listed for days after the
// client left, so only a recent one means a live client.
type Conn struct {
	IP       string
	LastSeen time.Time
}

// NodeConnections lists the client addresses of one node per user id. The panel answers through a job: start it, then poll until it
// is done (about a second on a node with a thousand users online).
func (c *Client) NodeConnections(ctx context.Context, nodeUUID string) (map[int64][]Conn, error) {
	var job struct {
		JobID string `json:"jobId"`
	}
	path := "/api/connections/by-node/" + url.PathEscape(nodeUUID)
	if err := c.do(ctx, "POST", path, nil, nil, &job); err != nil {
		return nil, err
	}
	if job.JobID == "" {
		return nil, fmt.Errorf("remnawave: POST %s: no job id", path)
	}
	var st struct {
		IsCompleted bool `json:"isCompleted"`
		IsFailed    bool `json:"isFailed"`
		Result      *struct {
			Users []struct {
				UserID int64 `json:"userId"`
				IPs    []struct {
					IP       string    `json:"ip"`
					LastSeen time.Time `json:"lastSeen"`
				} `json:"ips"`
			} `json:"users"`
		} `json:"result"`
	}
	jobPath := "/api/connections/by-node/" + url.PathEscape(job.JobID)
	for i := 0; ; i++ {
		if err := c.get(ctx, jobPath, nil, &st); err != nil {
			return nil, err
		}
		if st.IsFailed {
			return nil, fmt.Errorf("remnawave: the panel could not read the connections of node %s", nodeUUID)
		}
		if st.IsCompleted {
			break
		}
		if i >= 60 {
			return nil, fmt.Errorf("remnawave: the connections of node %s are not ready after %d polls", nodeUUID, i)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(c.JobPoll):
		}
	}
	if st.Result == nil {
		return nil, errors.New("remnawave: a completed connections job has no result")
	}
	out := make(map[int64][]Conn, len(st.Result.Users))
	for _, u := range st.Result.Users {
		for _, ip := range u.IPs {
			out[u.UserID] = append(out[u.UserID], Conn{IP: ip.IP, LastSeen: ip.LastSeen})
		}
	}
	return out, nil
}

// UserBrief is what antifraud needs of a panel user. Only these fields are
// decoded: the rest of the user object carries its credentials (vlessUuid,
// passwords, the subscription URL), which never leave the panel reply.
type UserBrief struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	TelegramID  int64  `json:"telegramId"`
	Status      string `json:"status"`
	Tag         string `json:"tag"`
	DeviceLimit *int   `json:"hwidDeviceLimit"` // nil: the panel's fallback applies
}

// AbuseUsers reads every user, a thousand per page.
func (c *Client) AbuseUsers(ctx context.Context) ([]UserBrief, error) {
	const size = 1000
	var all []UserBrief
	for start := 0; ; start += size {
		var page struct {
			Total int `json:"total"`
			Users []struct {
				ID          int64   `json:"id"`
				Username    string  `json:"username"`
				TelegramID  *int64  `json:"telegramId"`
				Status      string  `json:"status"`
				Tag         *string `json:"tag"`
				DeviceLimit *int    `json:"hwidDeviceLimit"`
			} `json:"users"`
		}
		q := url.Values{"start": {strconv.Itoa(start)}, "size": {strconv.Itoa(size)}}
		if err := c.get(ctx, "/api/users", q, &page); err != nil {
			return nil, err
		}
		for _, u := range page.Users {
			b := UserBrief{ID: u.ID, Username: u.Username, Status: u.Status, DeviceLimit: u.DeviceLimit}
			if u.TelegramID != nil {
				b.TelegramID = *u.TelegramID
			}
			if u.Tag != nil {
				b.Tag = *u.Tag
			}
			all = append(all, b)
		}
		if len(page.Users) == 0 || start+len(page.Users) >= page.Total {
			return all, nil
		}
	}
}

// FallbackDeviceLimit is the device limit of users without their own.
func (c *Client) FallbackDeviceLimit(ctx context.Context) (int, error) {
	var s struct {
		HWID *struct {
			FallbackDeviceLimit int `json:"fallbackDeviceLimit"`
		} `json:"hwidSettings"`
	}
	if err := c.get(ctx, "/api/subscription-settings", nil, &s); err != nil {
		return 0, err
	}
	if s.HWID == nil {
		return 0, nil
	}
	return s.HWID.FallbackDeviceLimit, nil
}

// DisableUser turns the user's subscription off in the panel.
func (c *Client) DisableUser(ctx context.Context, id int64) error {
	return c.do(ctx, "POST", fmt.Sprintf("/api/users/%d/actions/disable", id), nil, nil, nil)
}

// EnableUser turns it back on.
func (c *Client) EnableUser(ctx context.Context, id int64) error {
	return c.do(ctx, "POST", fmt.Sprintf("/api/users/%d/actions/enable", id), nil, nil, nil)
}

// DropUserConnections closes the users' open connections on every node.
func (c *Client) DropUserConnections(ctx context.Context, ids []int64) error {
	body := map[string]any{"dropBy": map[string]any{"by": "userIds", "userIds": ids}}
	return c.do(ctx, "POST", "/api/connections/drop", nil, body, nil)
}

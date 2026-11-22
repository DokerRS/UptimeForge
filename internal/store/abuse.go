package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/wh3r3ar3you/uptimeforge/internal/abuse"
)

// The antifraud keeps client addresses for days (remnawave.abuse.retention),
// what it remembers per user between polls, and what it did.
const abuseMigration = `
CREATE TABLE abuse_ips (
	user_id BIGINT NOT NULL, prefix TEXT NOT NULL, first_seen TIMESTAMPTZ NOT NULL, last_seen TIMESTAMPTZ NOT NULL,
	nodes JSONB NOT NULL DEFAULT '[]', PRIMARY KEY (user_id, prefix));
CREATE INDEX abuse_ips_last ON abuse_ips (last_seen);
CREATE TABLE abuse_state (user_id BIGINT PRIMARY KEY, state JSONB NOT NULL);
CREATE TABLE abuse_events (
	id BIGSERIAL PRIMARY KEY, at TIMESTAMPTZ NOT NULL, user_id BIGINT NOT NULL, username TEXT NOT NULL DEFAULT '',
	action TEXT NOT NULL, now_ips INTEGER NOT NULL DEFAULT 0, day_ips INTEGER NOT NULL DEFAULT 0, device_limit INTEGER NOT NULL DEFAULT 0,
	nodes JSONB NOT NULL DEFAULT '[]', error TEXT NOT NULL DEFAULT '');
CREATE INDEX abuse_events_user ON abuse_events (user_id, at);
CREATE INDEX abuse_events_at ON abuse_events (at);
`

// WriteAbuseSeen upserts addresses as the tracker holds them.
func (s *Store) WriteAbuseSeen(ctx context.Context, seen []abuse.Seen) error {
	if len(seen) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.PrepareContext(ctx, `INSERT INTO abuse_ips (user_id, prefix, first_seen, last_seen, nodes) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, prefix) DO UPDATE SET first_seen = LEAST(abuse_ips.first_seen, excluded.first_seen),
		last_seen = GREATEST(abuse_ips.last_seen, excluded.last_seen), nodes = excluded.nodes`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, x := range seen {
		if _, err := st.ExecContext(ctx, x.User, x.Prefix, x.First, x.Last, jsonList(x.Nodes)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadAbuseSeen reads the addresses seen after since.
func (s *Store) LoadAbuseSeen(ctx context.Context, since time.Time) ([]abuse.Seen, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id, prefix, first_seen, last_seen, nodes FROM abuse_ips WHERE last_seen > $1`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []abuse.Seen
	for rows.Next() {
		var x abuse.Seen
		var nodes []byte
		if err := rows.Scan(&x.User, &x.Prefix, &x.First, &x.Last, &nodes); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(nodes, &x.Nodes)
		x.First, x.Last = x.First.UTC(), x.Last.UTC()
		out = append(out, x)
	}
	return out, rows.Err()
}

// SaveAbuseStates replaces the remembered per-user states.
func (s *Store) SaveAbuseStates(ctx context.Context, states map[int64]abuse.State) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM abuse_state`); err != nil {
		return err
	}
	for id, st := range states {
		b, err := json.Marshal(st)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO abuse_state (user_id, state) VALUES ($1, $2)`, id, b); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadAbuseStates reads them back after a restart.
func (s *Store) LoadAbuseStates(ctx context.Context) (map[int64]abuse.State, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id, state FROM abuse_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]abuse.State{}
	for rows.Next() {
		var id int64
		var b []byte
		if err := rows.Scan(&id, &b); err != nil {
			return nil, err
		}
		var st abuse.State
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, err
		}
		out[id] = st
	}
	return out, rows.Err()
}

// AbuseEvent is one thing the antifraud did: a message, a ban, a would-be
// ban, an unban by hand. Error is set when the panel refused.
type AbuseEvent struct {
	At       time.Time `json:"at"`
	User     int64     `json:"user"`
	Username string    `json:"username,omitempty"`
	Action   string    `json:"action"`
	Now      int       `json:"now"`
	Day      int       `json:"day"`
	Limit    int       `json:"limit"`
	Nodes    []string  `json:"nodes"`
	Error    string    `json:"error,omitempty"`
}

func (s *Store) AddAbuseEvent(ctx context.Context, e AbuseEvent) error {
	if e.Nodes == nil {
		e.Nodes = []string{}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO abuse_events (at, user_id, username, action, now_ips, day_ips, device_limit, nodes, error)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, e.At, e.User, e.Username, e.Action, e.Now, e.Day, e.Limit, jsonList(e.Nodes), e.Error)
	return err
}

// AbuseEvents lists events after since, newest first; user 0 means everyone.
func (s *Store) AbuseEvents(ctx context.Context, user int64, since time.Time, limit int) ([]AbuseEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT at, user_id, username, action, now_ips, day_ips, device_limit, nodes, error FROM abuse_events
		WHERE at > $1 AND ($2 = 0 OR user_id = $2) ORDER BY at DESC, id DESC LIMIT $3`, since, user, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AbuseEvent
	for rows.Next() {
		var e AbuseEvent
		var nodes []byte
		if err := rows.Scan(&e.At, &e.User, &e.Username, &e.Action, &e.Now, &e.Day, &e.Limit, &nodes, &e.Error); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(nodes, &e.Nodes)
		e.At = e.At.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneAbuse drops addresses last seen before ipsBefore and events before
// eventsBefore.
func (s *Store) PruneAbuse(ctx context.Context, ipsBefore, eventsBefore time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM abuse_ips WHERE last_seen < $1`, ipsBefore); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM abuse_events WHERE at < $1`, eventsBefore)
	return err
}

// jsonList is a string list as jsonb text; nil becomes [].
func jsonList(l []string) string {
	if l == nil {
		l = []string{}
	}
	b, _ := json.Marshal(l)
	return string(b)
}

package store

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/wh3r3ar3you/uptimeforge/internal/abuse"
)

func TestAbuseStorage(t *testing.T) {
	s, ctx := open(t), context.Background()
	t0 := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

	if err := s.WriteAbuseSeen(ctx, []abuse.Seen{
		{User: 7, Prefix: "83.149.47.17", First: t0, Last: t0, Nodes: []string{"de"}},
		{User: 7, Prefix: "2a00:1fa0::/64", First: t0, Last: t0, Nodes: []string{"nl"}},
		{User: 9, Prefix: "5.6.7.8", First: t0.Add(-48 * time.Hour), Last: t0.Add(-48 * time.Hour), Nodes: []string{"de"}},
	}); err != nil {
		t.Fatal(err)
	}
	// A later poll moves last_seen on and the node list follows the tracker.
	if err := s.WriteAbuseSeen(ctx, []abuse.Seen{{User: 7, Prefix: "83.149.47.17", First: t0, Last: t0.Add(time.Minute), Nodes: []string{"de", "fi"}}}); err != nil {
		t.Fatal(err)
	}
	seen, err := s.LoadAbuseSeen(ctx, t0.Add(-time.Hour))
	if err != nil || len(seen) != 2 {
		t.Fatalf("seen %+v %v", seen, err)
	}
	for _, x := range seen {
		if x.Prefix == "83.149.47.17" && (!x.Last.Equal(t0.Add(time.Minute)) || !slices.Equal(x.Nodes, []string{"de", "fi"}) || !x.First.Equal(t0)) {
			t.Fatalf("upsert %+v", x)
		}
	}

	states := map[int64]abuse.State{7: {User: 7, Level: abuse.LevelNotify, NotifySince: t0, NotifiedAt: t0.Add(15 * time.Minute), NotifiedNow: 8}}
	if err := s.SaveAbuseStates(ctx, states); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAbuseStates(ctx, map[int64]abuse.State{9: {User: 9, Level: abuse.LevelBan, BannedAt: t0}}); err != nil {
		t.Fatal(err)
	}
	back, err := s.LoadAbuseStates(ctx)
	if err != nil || len(back) != 1 || back[9].Level != abuse.LevelBan || !back[9].BannedAt.Equal(t0) {
		t.Fatalf("states replace, got %+v %v", back, err)
	}

	for i, a := range []abuse.Action{abuse.ActNotify, abuse.ActWouldBan} {
		ev := AbuseEvent{At: t0.Add(time.Duration(i) * time.Minute), User: 7, Username: "saveoleshki", Action: string(a), Now: 8 + i, Day: 20, Limit: 1, Nodes: []string{"de"}}
		if err := s.AddAbuseEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	s.AddAbuseEvent(ctx, AbuseEvent{At: t0, User: 9, Action: "ban", Error: "remnawave: POST /api/users/9/actions/disable: HTTP 500"})
	evs, err := s.AbuseEvents(ctx, 7, t0.Add(-time.Hour), 10)
	if err != nil || len(evs) != 2 || evs[0].Action != "would_ban" || evs[0].Now != 9 || evs[1].Username != "saveoleshki" {
		t.Fatalf("events of 7: %+v %v", evs, err)
	}
	all, _ := s.AbuseEvents(ctx, 0, t0.Add(-time.Hour), 10)
	if len(all) != 3 {
		t.Fatalf("all events %d", len(all))
	}

	if err := s.PruneAbuse(ctx, t0.Add(-time.Hour), t0.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	seen, _ = s.LoadAbuseSeen(ctx, time.Time{})
	if len(seen) != 2 {
		t.Fatalf("pruned fresh or kept stale addresses: %+v", seen)
	}
	all, _ = s.AbuseEvents(ctx, 0, time.Time{}, 10)
	if len(all) != 1 || all[0].Action != "would_ban" {
		t.Fatalf("events after prune %+v", all)
	}
}

package notify

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestAbuseNoticeText(t *testing.T) {
	n := AbuseNotice{Action: "notify", UserID: 7, Username: "save<oleshki>", TelegramID: 8620400077, Limit: 1, Now: 16, Day: 58,
		Nodes: []string{"de-1", "nl-2"}, Operators: []string{"MTS", "Beeline"}}
	ru := (&Formatter{Lang: "ru"}).Abuse(n)
	for _, want := range []string{"Антифрод", "<code>7</code>", "save&lt;oleshki&gt;", "8620400077", "Лимит устройств: 1", "сейчас: <b>16</b>", "за 24 ч: 58", "de-1, nl-2", "MTS, Beeline"} {
		if !strings.Contains(ru, want) {
			t.Errorf("ru text has no %q:\n%s", want, ru)
		}
	}
	if strings.Contains(ru, "83.") || strings.Contains(ru, "заблокир") {
		t.Errorf("an address or a ban in a plain notice:\n%s", ru)
	}

	n.Action = "would_ban"
	if s := (&Formatter{Lang: "ru"}).Abuse(n); !strings.Contains(s, "был бы заблокирован") {
		t.Errorf("would_ban:\n%s", s)
	}
	n.Action = "ban"
	if s := (&Formatter{Lang: "en"}).Abuse(n); !strings.Contains(s, "Subscription disabled") {
		t.Errorf("ban:\n%s", s)
	}
	n.Error = "remnawave: POST /api/users/7/actions/disable: HTTP 500"
	if s := (&Formatter{Lang: "en"}).Abuse(n); !strings.Contains(s, "Could not disable") || !strings.Contains(s, "HTTP 500") {
		t.Errorf("failed ban:\n%s", s)
	}
}

func TestAbuseNoticeFollowsItsRoute(t *testing.T) {
	tg, calls := fakeBot(t, TelegramConfig{Routes: map[string]Route{EventAbuse: {Topic: 42, Silent: true}}})
	if err := tg.NotifyAbuse(context.Background(), AbuseNotice{Action: "notify", UserID: 7, Limit: 1, Now: 9}); err != nil {
		t.Fatal(err)
	}
	c := calls()
	if len(c) != 1 || c[0].topic != 42 || !c[0].silent || !strings.Contains(c[0].text, "<code>7</code>") {
		t.Fatalf("calls %+v", c)
	}

	off, calls := fakeBot(t, TelegramConfig{Routes: map[string]Route{EventAbuse: {Off: true}}})
	if err := off.NotifyAbuse(context.Background(), AbuseNotice{Action: "notify", UserID: 7}); err != nil {
		t.Fatal(err)
	}
	if c := calls(); len(c) != 0 {
		t.Fatalf("a muted route sent %+v", c)
	}
}

func TestAbuseHasATestMessage(t *testing.T) {
	if s := (&Formatter{Lang: "ru"}).Test(EventAbuse); !strings.Contains(s, "Антифрод") {
		t.Fatalf("test message %q", s)
	}
}

// The message lists the addresses with their provider, so the admin sees at
// a glance whether it is one phone hopping inside one operator or a crowd.
func TestAbuseNoticeListsAddresses(t *testing.T) {
	n := AbuseNotice{Action: "notify", UserID: 7, Limit: 1, Now: 25, Operators: []string{"MTS · 20", "Beeline · 5"}}
	for i := range 25 {
		n.Addresses = append(n.Addresses, AbuseAddress{IP: fmt.Sprintf("83.1.0.%d", i+1), ASN: "as8359", Org: "MTS <PJSC>"})
	}
	s := (&Formatter{Lang: "ru"}).Abuse(n)
	for _, want := range []string{"Адреса (25)", "<code>83.1.0.1</code> — MTS &lt;PJSC&gt; · AS8359", "<code>83.1.0.20</code>", "…и ещё 5", "MTS · 20, Beeline · 5"} {
		if !strings.Contains(s, want) {
			t.Errorf("no %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "83.1.0.21") {
		t.Errorf("more than 20 addresses listed:\n%s", s)
	}
	if len(s) > 4000 {
		t.Errorf("a message of %d characters may not fit Telegram", len(s))
	}
}

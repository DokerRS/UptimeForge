package notify

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestAbuseNoticeText(t *testing.T) {
	n := AbuseNotice{Action: "notify", UserID: 7, Username: "save<oleshki>", TelegramID: 8620400077, Limit: 1, Now: 16, Day: 58,
		Nodes: []string{"de-1", "nl-2"}, Operators: []AbuseOperator{{"MTS", 10}, {"Beeline", 6}}}
	ru := (&Formatter{Lang: "ru"}).Abuse(n)
	for _, want := range []string{"Антифрод", "<code>7</code>", "save&lt;oleshki&gt;", "8620400077", "Лимит устройств: 1", "сейчас: <b>16</b>", "за 24 ч: 58", "de-1, nl-2", "MTS · 10, Beeline · 6"} {
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
	n := AbuseNotice{Action: "notify", UserID: 7, Limit: 1, Now: 25, Operators: []AbuseOperator{{"MTS", 20}, {"Beeline", 5}}}
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

// The antifraud card is a rich message: a heading, a table of facts, the
// operators, the addresses folded away, and the plain HTML as the fallback.
func TestAbuseRichCard(t *testing.T) {
	n := AbuseNotice{Action: "would_ban", UserID: 3038, Username: "sale<s>", TelegramID: 8620400077, Limit: 2, Now: 17, Day: 40,
		Nodes: []string{"DE-1", "NL-2"}, Operators: []AbuseOperator{{"MTS PJSC", 12}, {"Beeline", 5}}}
	for i := range 17 {
		n.Addresses = append(n.Addresses, AbuseAddress{IP: fmt.Sprintf("83.1.0.%d", i+1), ASN: "as8359", Org: "MTS PJSC"})
	}
	s := (&Formatter{Lang: "ru"}).RichAbuse(n)
	for _, want := range []string{
		"<h3>⛔ Антифрод · был бы заблокирован</h3>", "<table", "👤", "<code>3038</code>", "sale&lt;s&gt;", "📱", ">2<", "🌐", "<b>17</b>",
		"🕓", ">40<", "🖥", "DE-1, NL-2", "📡", "MTS PJSC", ">12<", "<details><summary>🌍 Адреса (17)</summary>", "<code>83.1.0.17</code>", "AS8359", "<footer>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("no %q in:\n%s", want, s)
		}
	}

	tg, calls := fakeBot(t, TelegramConfig{})
	if err := tg.NotifyAbuse(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if c := calls(); len(c) != 1 || !c[0].rich || !strings.Contains(c[0].text, "<table") {
		t.Fatalf("not sent as a rich card: %+v", c)
	}
}

// The Test button of the abuse route sends a sample card, so its look can
// be judged before anyone trips the antifraud.
func TestAbuseTestIsASampleCard(t *testing.T) {
	tg, calls := fakeBot(t, TelegramConfig{})
	if err := tg.SendTest(context.Background(), EventAbuse); err != nil {
		t.Fatal(err)
	}
	if c := calls(); len(c) != 1 || !c[0].rich || !strings.Contains(c[0].text, "<table") || !strings.Contains(c[0].text, "203.0.113.") {
		t.Fatalf("calls %+v", c)
	}
}

// Counted per /20, the card says so and still gives the addresses.
func TestAbuseCardCountsNetworks(t *testing.T) {
	n := AbuseNotice{Action: "notify", UserID: 5660, Limit: 3, Now: 10, Addrs: 28, Day: 14, Prefix: 20}
	rich := (&Formatter{Lang: "ru"}).RichAbuse(n)
	for _, want := range []string{"🌐 Подсетей /20 сейчас", "<b>10</b> · адресов 28 · в 3,3 раза больше лимита", "🕓 Подсетей за 24 часа"} {
		if !strings.Contains(rich, want) {
			t.Errorf("no %q in:\n%s", want, rich)
		}
	}
	if s := (&Formatter{Lang: "en"}).RichAbuse(n); !strings.Contains(s, "🌐 /20 networks now") || !strings.Contains(s, "<b>10</b> · 28 addresses") {
		t.Errorf("en card:\n%s", s)
	}
	if s := (&Formatter{Lang: "ru"}).Abuse(n); !strings.Contains(s, "подсетей /20 сейчас: <b>10</b> (адресов 28)") {
		t.Errorf("plain:\n%s", s)
	}
	n.Prefix = 32 // every address counted: the card reads as before
	if s := (&Formatter{Lang: "ru"}).RichAbuse(n); !strings.Contains(s, "🌐 Адресов сейчас") || strings.Contains(s, "Подсетей") {
		t.Errorf("per address:\n%s", s)
	}
}

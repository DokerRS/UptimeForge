package notify

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// EventAbuse is the antifraud's message about a subscriber far over its
// device limit. It is no incident: no card to update, no recovery.
const EventAbuse = "abuse"

// AbuseAddress is one client address (an IPv6 /64) and who it belongs to.
type AbuseAddress struct {
	IP  string
	ASN string // "as8359", "" when unknown
	Org string
}

// AbuseOperator is an operator and how many of the addresses are its.
type AbuseOperator struct {
	Name  string
	Count int
}

// abuseMaxAddresses keeps a message well inside Telegram's 4096 characters.
const abuseMaxAddresses = 20

// AbuseNotice is one antifraud message: who, how many addresses and from
// which operators, with the addresses themselves (the first 20).
type AbuseNotice struct {
	Action     string // notify, would_ban, ban
	UserID     int64
	Username   string
	TelegramID int64
	Limit      int
	Now        int // addresses at once, or networks when Prefix is under 32
	Addrs      int // addresses at once when counted per network
	Day        int // over 24 hours, counted as Now
	Prefix     int // the IPv4 network size counted; 0 or 32: every address
	Nodes      []string
	Operators  []AbuseOperator // most addresses first
	Addresses  []AbuseAddress
	Error      string // the panel refused the ban
	DropError  string // disabled, but its open connections were not closed
}

// grouped: the counts are of IPv4 networks, not of single addresses.
func (n AbuseNotice) grouped() bool { return n.Prefix > 0 && n.Prefix < 32 }

var abuseTexts = map[string]map[string]string{
	"ru": {
		"notify": "🚨 <b>Антифрод: превышение устройств</b>", "would_ban": "⛔ <b>Антифрод: был бы заблокирован</b>",
		"ban": "⛔ <b>Антифрод: подписка отключена</b>", "ban_failed": "⚠️ <b>Антифрод: не удалось отключить подписку</b>",
		"client": "Клиент", "limit": "Лимит устройств: %d · адресов сейчас: <b>%d</b> · за 24 ч: %d", "limit_net": "Лимит устройств: %d · подсетей /%d сейчас: <b>%d</b> (адресов %d) · за 24 ч: %d",
		"nodes": "Ноды", "operators": "Операторы", "addresses": "Адреса (%d)", "more": "…и ещё %d", "error": "Ошибка панели", "drop_error": "Подписка отключена, но подключения не оборваны",
		"would_hint": "В режиме ban клиент был бы заблокирован. Включить: Настройки → Remnawave → Антифрод.",
	},
	"en": {
		"notify": "🚨 <b>Antifraud: over the device limit</b>", "would_ban": "⛔ <b>Antifraud: would be banned</b>",
		"ban": "⛔ <b>Antifraud: Subscription disabled</b>", "ban_failed": "⚠️ <b>Antifraud: Could not disable the subscription</b>",
		"client": "Client", "limit": "Device limit: %d · addresses now: <b>%d</b> · over 24 h: %d", "limit_net": "Device limit: %d · /%d networks now: <b>%d</b> (%d addresses) · over 24 h: %d",
		"nodes": "Nodes", "operators": "Operators", "addresses": "Addresses (%d)", "more": "…and %d more", "error": "Panel error", "drop_error": "Disabled, but its connections were not closed",
		"would_hint": "In ban mode this client would be disabled. Turn it on in Settings → Remnawave → Antifraud.",
	},
}

// Abuse renders an antifraud message as Telegram HTML.
func (f *Formatter) Abuse(n AbuseNotice) string {
	d, ok := abuseTexts[f.Lang]
	if !ok {
		d = abuseTexts["en"]
	}
	head := d[n.Action]
	if n.Action == "ban" && n.Error != "" {
		head = d["ban_failed"]
	}
	if head == "" {
		head = d["notify"]
	}
	who := []string{fmt.Sprintf("<code>%d</code>", n.UserID)}
	if n.Username != "" {
		who = append(who, esc(n.Username))
	}
	if n.TelegramID != 0 {
		who = append(who, fmt.Sprintf("tg <code>%d</code>", n.TelegramID))
	}
	counts := fmt.Sprintf(d["limit"], n.Limit, n.Now, n.Day)
	if n.grouped() {
		counts = fmt.Sprintf(d["limit_net"], n.Limit, n.Prefix, n.Now, n.Addrs, n.Day)
	}
	lines := []string{head, "", d["client"] + ": " + strings.Join(who, " · "), counts}
	if len(n.Nodes) > 0 {
		lines = append(lines, d["nodes"]+": "+esc(strings.Join(n.Nodes, ", ")))
	}
	if len(n.Operators) > 0 {
		ops := make([]string, len(n.Operators))
		for i, o := range n.Operators {
			ops[i] = fmt.Sprintf("%s · %d", o.Name, o.Count)
		}
		lines = append(lines, d["operators"]+": "+esc(strings.Join(ops, ", ")))
	}
	if len(n.Addresses) > 0 {
		lines = append(lines, "", fmt.Sprintf(d["addresses"], len(n.Addresses)))
		for _, x := range n.Addresses[:min(len(n.Addresses), abuseMaxAddresses)] {
			line := "<code>" + esc(x.IP) + "</code>"
			var who []string
			if x.Org != "" {
				who = append(who, esc(x.Org))
			}
			if x.ASN != "" {
				who = append(who, strings.ToUpper(esc(x.ASN)))
			}
			if len(who) > 0 {
				line += " — " + strings.Join(who, " · ")
			}
			lines = append(lines, line)
		}
		if extra := len(n.Addresses) - abuseMaxAddresses; extra > 0 {
			lines = append(lines, fmt.Sprintf(d["more"], extra))
		}
	}
	if n.Error != "" {
		lines = append(lines, d["error"]+": <code>"+esc(n.Error)+"</code>")
	}
	if n.DropError != "" {
		lines = append(lines, d["drop_error"]+": <code>"+esc(n.DropError)+"</code>")
	}
	if n.Action == "would_ban" {
		lines = append(lines, "", "<i>"+d["would_hint"]+"</i>")
	}
	return strings.Join(lines, "\n")
}

// NotifyAbuse sends an antifraud message to the abuse route (off: nothing).
func (t *Telegram) NotifyAbuse(ctx context.Context, n AbuseNotice) error {
	to := t.route(EventAbuse, nil)
	if to.off {
		return nil
	}
	// A rich card, or the plain HTML on a Bot API server without rich messages.
	_, err := t.sendCard(ctx, to, t.f.RichAbuse(n), t.f.Abuse(n), to.silent, nil)
	return err
}

var abuseRichTexts = map[string]map[string]string{
	"ru": {
		"h_notify": "🚨 Антифрод · превышение устройств", "h_would_ban": "⛔ Антифрод · был бы заблокирован",
		"h_ban": "🔒 Антифрод · подписка отключена", "h_ban_failed": "⚠️ Антифрод · не удалось отключить",
		"client": "👤 Клиент", "tg": "✈️ Telegram", "limit": "📱 Лимит устройств", "now": "🌐 Адресов сейчас", "now_net": "🌐 Подсетей /%d сейчас", "addrs": "адресов %d", "day_net": "🕓 Подсетей за 24 часа", "over": "в %s раза больше лимита",
		"day": "🕓 За 24 часа", "nodes": "🖥 Ноды", "action": "⚖️ Действие",
		"a_notify": "🔔 только уведомление", "a_would_ban": "⛔ был бы заблокирован (включён режим уведомлений)",
		"a_ban": "🔒 подписка отключена, подключения оборваны", "a_ban_failed": "⚠️ панель не дала отключить",
		"operators": "📡 Операторы", "operator": "Оператор", "count": "Адресов", "addresses": "🌍 Адреса (%d)", "address": "Адрес",
		"more": "…и ещё %d", "error": "Ошибка панели", "drop_error": "Подписка отключена, но подключения не оборваны",
		"would_hint": "💡 Чтобы такие клиенты блокировались сами: Настройки → Remnawave → Антифрод → «Уведомлять и блокировать».",
	},
	"en": {
		"h_notify": "🚨 Antifraud · over the device limit", "h_would_ban": "⛔ Antifraud · would be banned",
		"h_ban": "🔒 Antifraud · subscription disabled", "h_ban_failed": "⚠️ Antifraud · could not disable",
		"client": "👤 Client", "tg": "✈️ Telegram", "limit": "📱 Device limit", "now": "🌐 Addresses now", "now_net": "🌐 /%d networks now", "addrs": "%d addresses", "day_net": "🕓 Networks over 24 hours", "over": "%s× the limit",
		"day": "🕓 Over 24 hours", "nodes": "🖥 Nodes", "action": "⚖️ Action",
		"a_notify": "🔔 notice only", "a_would_ban": "⛔ would be banned (notify mode is on)",
		"a_ban": "🔒 subscription disabled, connections closed", "a_ban_failed": "⚠️ the panel refused",
		"operators": "📡 Operators", "operator": "Operator", "count": "Addresses", "addresses": "🌍 Addresses (%d)", "address": "Address",
		"more": "…and %d more", "error": "Panel error", "drop_error": "Disabled, but its connections were not closed",
		"would_hint": "💡 To have such subscribers banned automatically: Settings → Remnawave → Antifraud → \"Notify and ban\".",
	},
}

// abuseRichAddresses caps the folded address table.
const abuseRichAddresses = 30

// RichAbuse renders an antifraud message as a rich card: a table of facts,
// the operators, and the addresses folded away.
func (f *Formatter) RichAbuse(n AbuseNotice) string {
	d, ok := abuseRichTexts[f.Lang]
	if !ok {
		d = abuseRichTexts["en"]
	}
	kind := n.Action
	if kind == "ban" && n.Error != "" {
		kind = "ban_failed"
	}
	if d["h_"+kind] == "" {
		kind = "notify"
	}
	var b strings.Builder
	b.WriteString("<h3>" + d["h_"+kind] + "</h3>")

	row := func(k, v string) { b.WriteString("<tr><td>" + k + "</td><td>" + v + "</td></tr>") }
	b.WriteString("<table bordered striped compact>")
	who := fmt.Sprintf("<code>%d</code>", n.UserID)
	if n.Username != "" {
		who += " · " + esc(n.Username)
	}
	row(d["client"], who)
	if n.TelegramID != 0 {
		row(d["tg"], fmt.Sprintf("<code>%d</code>", n.TelegramID))
	}
	row(d["limit"], fmt.Sprint(n.Limit))
	now := fmt.Sprintf("<b>%d</b>", n.Now)
	nowKey, dayKey := d["now"], d["day"]
	if n.grouped() {
		nowKey, dayKey = fmt.Sprintf(d["now_net"], n.Prefix), d["day_net"]
		now += " · " + fmt.Sprintf(d["addrs"], n.Addrs)
	}
	if n.Limit > 0 {
		x := strings.TrimSuffix(strings.TrimSuffix(fmt.Sprintf("%.1f", float64(n.Now)/float64(n.Limit)), "0"), ".")
		if f.Lang == "ru" {
			x = strings.ReplaceAll(x, ".", ",")
		}
		now += " · " + fmt.Sprintf(d["over"], x)
	}
	row(nowKey, now)
	row(dayKey, fmt.Sprint(n.Day))
	if len(n.Nodes) > 0 {
		row(d["nodes"], esc(strings.Join(n.Nodes, ", ")))
	}
	row(d["action"], d["a_"+kind])
	b.WriteString("</table>")

	if len(n.Operators) > 0 {
		b.WriteString("<p><b>" + d["operators"] + "</b></p><table bordered striped compact><tr><th>" + d["operator"] + "</th><th>" + d["count"] + "</th></tr>")
		for _, o := range n.Operators {
			b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%d</td></tr>", esc(o.Name), o.Count))
		}
		b.WriteString("</table>")
	}
	if len(n.Addresses) > 0 {
		b.WriteString("<details><summary>" + fmt.Sprintf(d["addresses"], len(n.Addresses)) + "</summary><table bordered striped compact><tr><th>" +
			d["address"] + "</th><th>" + d["operator"] + "</th></tr>")
		for _, x := range n.Addresses[:min(len(n.Addresses), abuseRichAddresses)] {
			who := []string{}
			if x.Org != "" {
				who = append(who, esc(x.Org))
			}
			if x.ASN != "" {
				who = append(who, strings.ToUpper(esc(x.ASN)))
			}
			org := strings.Join(who, " · ")
			if org == "" {
				org = "—"
			}
			b.WriteString("<tr><td><code>" + esc(x.IP) + "</code></td><td>" + org + "</td></tr>")
		}
		if extra := len(n.Addresses) - abuseRichAddresses; extra > 0 {
			b.WriteString(`<tr><td colspan="2">` + fmt.Sprintf(d["more"], extra) + "</td></tr>")
		}
		b.WriteString("</table></details>")
	}
	if n.Error != "" {
		b.WriteString("<blockquote>⚠️ " + d["error"] + ": <code>" + esc(n.Error) + "</code></blockquote>")
	}
	if n.DropError != "" {
		b.WriteString("<blockquote>⚠️ " + d["drop_error"] + ": <code>" + esc(n.DropError) + "</code></blockquote>")
	}
	if kind == "would_ban" {
		b.WriteString("<blockquote>" + d["would_hint"] + "</blockquote>")
	}
	at := time.Now()
	if f.Now != nil {
		at = f.Now()
	}
	if f.Loc != nil {
		at = at.In(f.Loc)
	}
	b.WriteString("<footer>🛡 UptimeForge · " + at.Format("02.01 15:04") + "</footer>")
	return b.String()
}

// SampleAbuse is a made-up case for the Test button (documentation
// addresses, no real subscriber).
func SampleAbuse() AbuseNotice {
	n := AbuseNotice{Action: "would_ban", UserID: 1001, Username: "sample_user", TelegramID: 777000111, Limit: 2, Now: 9, Addrs: 14, Day: 23, Prefix: 20,
		Nodes: []string{"de-frankfurt-1", "nl-amsterdam-1"}, Operators: []AbuseOperator{{"MTS PJSC", 9}, {"PJSC Rostelecom", 5}}}
	for i := range 14 {
		org, asn := "MTS PJSC", "as8359"
		if i >= 9 {
			org, asn = "PJSC Rostelecom", "as12389"
		}
		n.Addresses = append(n.Addresses, AbuseAddress{IP: fmt.Sprintf("203.0.113.%d", 10+i), ASN: asn, Org: org})
	}
	return n
}

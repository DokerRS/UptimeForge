package notify

import (
	"context"
	"fmt"
	"strings"
)

// EventAbuse is the antifraud's message about a subscriber far over its
// device limit. It is no incident: no card to update, no recovery.
const EventAbuse = "abuse"

// AbuseNotice is one antifraud message. It never carries client addresses:
// the hub's Antifraud page has them, for admins.
type AbuseNotice struct {
	Action     string // notify, would_ban, ban
	UserID     int64
	Username   string
	TelegramID int64
	Limit      int
	Now        int // addresses at once
	Day        int // addresses over 24 hours
	Nodes      []string
	Operators  []string
	Error      string // the panel refused the ban
}

var abuseTexts = map[string]map[string]string{
	"ru": {
		"notify": "🚨 <b>Антифрод: превышение устройств</b>", "would_ban": "⛔ <b>Антифрод: был бы заблокирован</b>",
		"ban": "⛔ <b>Антифрод: подписка отключена</b>", "ban_failed": "⚠️ <b>Антифрод: не удалось отключить подписку</b>",
		"client": "Клиент", "limit": "Лимит устройств: %d · адресов сейчас: <b>%d</b> · за 24 ч: %d",
		"nodes": "Ноды", "operators": "Операторы", "error": "Ошибка панели",
		"would_hint": "В режиме ban клиент был бы заблокирован. Включить: Настройки → Remnawave → Антифрод.",
	},
	"en": {
		"notify": "🚨 <b>Antifraud: over the device limit</b>", "would_ban": "⛔ <b>Antifraud: would be banned</b>",
		"ban": "⛔ <b>Antifraud: Subscription disabled</b>", "ban_failed": "⚠️ <b>Antifraud: Could not disable the subscription</b>",
		"client": "Client", "limit": "Device limit: %d · addresses now: <b>%d</b> · over 24 h: %d",
		"nodes": "Nodes", "operators": "Operators", "error": "Panel error",
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
	lines := []string{head, "", d["client"] + ": " + strings.Join(who, " · "), fmt.Sprintf(d["limit"], n.Limit, n.Now, n.Day)}
	if len(n.Nodes) > 0 {
		lines = append(lines, d["nodes"]+": "+esc(strings.Join(n.Nodes, ", ")))
	}
	if len(n.Operators) > 0 {
		lines = append(lines, d["operators"]+": "+esc(strings.Join(n.Operators, ", ")))
	}
	if n.Error != "" {
		lines = append(lines, d["error"]+": <code>"+esc(n.Error)+"</code>")
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
	_, err := t.send(ctx, to, t.f.Abuse(n), to.silent, 0, nil)
	return err
}

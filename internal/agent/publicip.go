package agent

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// DefaultPublicIPURLs answer with the caller's address: Cloudflare's trace
// ("ip=…" among other lines) or a bare address.
var DefaultPublicIPURLs = []string{
	"https://www.cloudflare.com/cdn-cgi/trace",
	"https://api.ipify.org",
	"https://ipv4.icanhazip.com",
}

const (
	publicIPTTL     = 10 * time.Minute // how long a known address is kept
	publicIPRetry   = time.Minute      // after every service failed
	publicIPTimeout = 3 * time.Second  // one service
)

// publicIP is the agent's public address, asked of public services and kept
// for a while: the hello needs it on every reconnect, and a reconnect must
// not wait on them. Only the Run goroutine touches it.
type publicIP struct {
	ip   string
	next time.Time // ask again from then on
}

// get is the public address, asked again when it is due. A failed round
// keeps the last known address and is retried a minute later.
func (p *publicIP) get(ctx context.Context, c *http.Client, urls []string) string {
	if len(urls) == 0 || time.Now().Before(p.next) {
		return p.ip
	}
	if c == nil {
		c = http.DefaultClient
	}
	for _, u := range urls {
		if ip := askPublicIP(ctx, c, u); ip != "" {
			p.ip, p.next = ip, time.Now().Add(publicIPTTL)
			return p.ip
		}
	}
	p.next = time.Now().Add(publicIPRetry)
	return p.ip
}

// askPublicIP is the public address one service answers with, or "".
func askPublicIP(ctx context.Context, c *http.Client, url string) string {
	ctx, cancel := context.WithTimeout(ctx, publicIPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	resp, err := c.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 4<<10))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if v, ok := strings.CutPrefix(line, "ip="); ok {
			line = v
		}
		if a, err := netip.ParseAddr(line); err == nil {
			if a = a.Unmap(); a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a) {
				return a.String()
			}
			return ""
		}
	}
	return ""
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

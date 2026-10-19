package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The webhook (DR-024 D2) is the one place the platform sends something out on its own. It is set by the operator in the provisioning configuration (never
// from the browser), carries a small closed JSON body with no secret, never follows a redirect, refuses non-public addresses unless the operator said the
// URL is internal, and checks the address at connect time so a name that later resolves somewhere else is still refused.

// ErrWebhookURL is returned for a URL that is not acceptable.
var ErrWebhookURL = errors.New("alerts: invalid webhook url")

const (
	maxURLLen      = 512
	sendTimeout    = 5 * time.Second
	maxBodyBytes   = 1024
	maxAttempts    = 3
	queueLen       = 64
	breakerFails   = 5
	breakerOpenFor = 5 * time.Minute
)

// cgnat is 100.64.0.0/10, not public although netip does not call it private.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// publicIP reports whether ip is an ordinary public unicast address.
func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	switch {
	case !ip.IsValid(), ip.IsLoopback(), ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast(), ip.IsUnspecified():
		return false
	case ip.Is4() && (cgnat.Contains(ip) || ip.As4()[0] == 0 || ip.As4()[0] >= 240):
		return false
	}
	return true
}

// ValidateWebhook checks a webhook URL as written in the configuration. The scheme must be https (http only for an internal URL), there must be no
// credentials, fragment or empty host, and an IP literal or the name "localhost" must be public unless internal is set. A name is checked again when
// connecting.
func ValidateWebhook(raw string, internal bool) error {
	if raw == "" || len(raw) > maxURLLen || strings.ContainsAny(raw, " \t\r\n\x00") {
		return ErrWebhookURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return ErrWebhookURL
	}
	if u.Scheme != "https" && !(internal && u.Scheme == "http") {
		return ErrWebhookURL
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return ErrWebhookURL
		}
	}
	host := u.Hostname()
	if host == "" {
		return ErrWebhookURL
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !internal && !publicIP(ip) {
			return ErrWebhookURL
		}
	} else if h := strings.ToLower(strings.TrimSuffix(host, ".")); !internal && (h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal")) {
		return ErrWebhookURL
	}
	return nil
}

// Webhook is the validated destination.
type Webhook struct {
	URL      string
	Internal bool
}

// Payload is the JSON body. Nothing in it comes from the host.
type Payload struct {
	V            int    `json:"v"`
	Event        string `json:"event"`
	AlertID      string `json:"alert_id"`
	Rule         string `json:"rule"`
	Severity     string `json:"severity"`
	State        string `json:"state"`
	ResourceKind string `json:"resource_kind"`
	ResourceID   string `json:"resource_id"`
	Value        *int   `json:"value"`
	At           string `json:"at"`
}

// PayloadOf builds the body for a change.
func PayloadOf(c Change) Payload {
	return Payload{V: 1, Event: c.Event, AlertID: c.Alert.ID, Rule: c.Alert.Type, Severity: c.Alert.Severity, State: c.Alert.State,
		ResourceKind: c.Alert.Kind, ResourceID: c.Alert.ResourceID, Value: c.Alert.Value, At: c.Alert.UpdatedAt.UTC().Format(time.RFC3339)}
}

// Notifier delivers changes to the webhook, best effort: a bounded queue, three attempts per change, and a circuit breaker that stops sending for a while
// after repeated failures. Delivery is not guaranteed and the queue is not persisted.
type Notifier struct {
	Hook   Webhook
	Client *http.Client // nil builds the confined client
	Now    func() time.Time
	// Sleep is injectable for tests.
	Sleep func(time.Duration)

	q    chan Change
	mu   sync.Mutex
	fail int
	open time.Time
	// Sent and Dropped count deliveries, for tests and diagnostics.
	Sent, Dropped int
}

// NewNotifier returns a notifier for a validated webhook.
func NewNotifier(h Webhook) (*Notifier, error) {
	if err := ValidateWebhook(h.URL, h.Internal); err != nil {
		return nil, err
	}
	n := &Notifier{Hook: h, q: make(chan Change, queueLen)}
	n.Client = confinedClient(h.Internal)
	return n, nil
}

// confinedClient never follows a redirect, ignores proxy variables, and refuses to connect to a non-public address unless internal.
func confinedClient(internal bool) *http.Client {
	d := &net.Dialer{Timeout: sendTimeout}
	if !internal {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return ErrWebhookURL
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || !publicIP(ip) {
				return ErrWebhookURL
			}
			return nil
		}
	}
	return &http.Client{
		Timeout:       sendTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{Proxy: nil, DialContext: d.DialContext, DisableKeepAlives: true, TLSHandshakeTimeout: sendTimeout,
			ResponseHeaderTimeout: sendTimeout, MaxResponseHeaderBytes: 8 << 10},
	}
}

// Notify queues changes without blocking; a full queue drops the change.
func (n *Notifier) Notify(cs []Change) {
	for _, c := range cs {
		select {
		case n.q <- c:
		default:
			n.mu.Lock()
			n.Dropped++
			n.mu.Unlock()
		}
	}
}

func (n *Notifier) now() time.Time {
	if n.Now != nil {
		return n.Now()
	}
	return time.Now()
}

// Run delivers queued changes until ctx ends.
func (n *Notifier) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-n.q:
			n.deliver(ctx, c)
		}
	}
}

func (n *Notifier) breakerOpen() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.fail >= breakerFails && n.now().Before(n.open)
}

func (n *Notifier) record(ok bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ok {
		n.fail = 0
		n.Sent++
		return
	}
	n.fail++
	if n.fail >= breakerFails {
		n.open = n.now().Add(breakerOpenFor)
	}
}

func (n *Notifier) deliver(ctx context.Context, c Change) {
	if n.breakerOpen() {
		n.mu.Lock()
		n.Dropped++
		n.mu.Unlock()
		return
	}
	body, err := json.Marshal(PayloadOf(c))
	if err != nil || len(body) > maxBodyBytes {
		return
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			wait := time.Duration(attempt*attempt) * time.Second
			if n.Sleep != nil {
				n.Sleep(wait)
			} else {
				select {
				case <-time.After(wait):
				case <-ctx.Done():
					return
				}
			}
		}
		if n.post(ctx, body) {
			n.record(true)
			return
		}
	}
	n.record(false)
}

func (n *Notifier) post(ctx context.Context, body []byte) bool {
	rctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, n.Hook.URL, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "svavyom-alerts/1")
	res, err := n.Client.Do(req) // #nosec G107 G704 -- the URL is operator configuration, validated, and the client refuses non-public addresses and redirects
	if err != nil {
		return false
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	return res.StatusCode >= 200 && res.StatusCode < 300
}

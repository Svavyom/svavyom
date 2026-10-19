package api

import (
	"context"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/console"
	"example.invalid/dedicatedcloud/backend/internal/hypervisor"
)

// The console route family (M1-D). It is deliberately NOT part of the /api/v1 OpenAPI convention (a WebSocket upgrade cannot be
// expressed in its JSON-only subset); it has its own documented contract (docs/CONSOLE.md, contracts/console-channel.json) and the
// same session, CSRF and same-origin rules, the same typed Error envelope, and the same deny-by-default posture:
//
//	GET  /console/v1/vms/{id}/serial   bounded serial boot output and a typed state        (session)
//	POST /console/v1/vms/{id}/tickets  a short-lived, single-use console ticket             (session + CSRF + same origin + console switch)
//	GET  /console/v1/vms/{id}/socket   WebSocket: the interactive serial console            (session + same origin + ticket)
//	POST /console/v1/vms/{id}/graphics-tickets  as tickets, bound to the graphical console    (DR-026 D1)
//	GET  /console/v1/vms/{id}/graphics-socket   WebSocket: the graphical (VNC) console          (session + same origin + ticket)

// ConsoleAudit is one console audit event: who, which VM and what happened. It never carries console content, a ticket or a cookie.
type ConsoleAudit struct {
	At      time.Time
	Actor   string
	VM      string
	Event   string // serial.read | ticket.minted | ticket.refused | console.opened | console.closed | console.refused
	Outcome string // ok | a closed reason / category
}

// Console wires the serial console. Nil keeps every console route closed.
type Console struct {
	// Enabled is the Development Preview console switch: false (the default) refuses tickets and sockets; reading the serial output
	// does not need it.
	Enabled bool
	Tickets *console.Tickets
	Broker  *console.Client
	Audit   func(ConsoleAudit)
	// MaxSession bounds one interactive connection (default one hour); SessionCheck is how often the session is re-validated
	// (default 5 seconds).
	MaxSession   time.Duration
	SessionCheck time.Duration
}

const (
	consoleProto  = "svavyom.console.v1"
	graphicsProto = "svavyom.graphics.v1"
	ticketPrefix  = "t."
	maxInputBytes = 4 << 10
	// maxGraphicsMessage bounds one message from the browser's VNC client (pointer and key events are a few bytes; a clipboard paste is the largest).
	maxGraphicsMessage = 64 << 10
)

var consoleRouteRE = regexp.MustCompile(`^/console/v1/vms/([A-Za-z0-9][A-Za-z0-9._-]{0,62})/(serial|tickets|socket|graphics-tickets|graphics-socket)$`)

func (h *Handler) audit(actor, vm, event, outcome string) {
	if c := h.deps.Console; c != nil && c.Audit != nil {
		c.Audit(ConsoleAudit{At: h.now().UTC(), Actor: actor, VM: vm, Event: event, Outcome: outcome})
	}
}

// serveConsole routes the console family. An unmatched path is not_found like any undeclared path.
func (h *Handler) serveConsole(w http.ResponseWriter, r *http.Request) {
	m := consoleRouteRE.FindStringSubmatch(r.URL.Path)
	if m == nil || h.deps.Console == nil || h.deps.Console.Broker == nil {
		h.reject(w, categoryNotFound)
		return
	}
	switch {
	case m[2] == "serial" && r.Method == http.MethodGet:
		h.serialOutput(w, r, m[1])
	case m[2] == "tickets" && r.Method == http.MethodPost:
		h.mintTicket(w, r, m[1], console.KindSerial)
	case m[2] == "socket" && r.Method == http.MethodGet:
		h.consoleSocket(w, r, m[1], console.KindSerial)
	case m[2] == "graphics-tickets" && r.Method == http.MethodPost:
		h.mintTicket(w, r, m[1], console.KindGraphics)
	case m[2] == "graphics-socket" && r.Method == http.MethodGet:
		h.consoleSocket(w, r, m[1], console.KindGraphics)
	default:
		h.reject(w, categoryNotFound)
	}
}

// brokerError maps a broker failure to the typed API error.
func (h *Handler) brokerError(w http.ResponseWriter, err error) {
	switch console.CategoryOf(err) {
	case "not_found":
		h.reject(w, categoryNotFound)
	case "conflict":
		h.reject(w, categoryConflict)
	case "prohibited":
		h.reject(w, categoryProhibited)
	case "validation":
		h.reject(w, categoryValidation)
	default:
		h.reject(w, categoryUnavailable)
	}
}

type serialJSON struct {
	State     string `json:"state"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated"`
	Running   bool   `json:"running"`
}

// serialText turns console bytes into text that is safe to show: valid UTF-8, no escape sequences, no control characters other than
// newline and tab (carriage returns are folded into newlines). The browser still renders it as text, never as markup.
func serialText(b []byte) string {
	if !utf8.Valid(b) {
		b = []byte(strings.ToValidUTF8(string(b), "�"))
	}
	var out strings.Builder
	esc := 0 // 0 normal, 1 after ESC, 2 inside a CSI sequence
	var prev rune
	for _, c := range string(b) {
		switch {
		case esc == 1:
			if c == '[' {
				esc = 2
			} else {
				esc = 0
			}
			continue
		case esc == 2:
			if c >= 0x40 && c <= 0x7e {
				esc = 0
			}
			continue
		case c == 0x1b:
			esc = 1
			continue
		case c == '\r':
			prev = c
			continue
		case c == '\n':
			out.WriteByte('\n')
		case c == '\t':
			out.WriteByte('\t')
		case c < 0x20 || c == 0x7f:
			prev = c
			continue
		default:
			if prev == '\r' && out.Len() > 0 {
				// a bare carriage return redraws a line (progress bars): keep what was printed, start a new line
				s := out.String()
				if !strings.HasSuffix(s, "\n") {
					out.WriteByte('\n')
				}
			}
			out.WriteRune(c)
		}
		prev = c
	}
	return out.String()
}

func (h *Handler) consoleSession(w http.ResponseWriter, r *http.Request) (user, token string, ok bool) {
	if h.deps.Auth == nil {
		h.reject(w, categoryUnauthenticated)
		return "", "", false
	}
	sess, tok, authed, failed := h.session(r)
	switch {
	case failed:
		h.reject(w, categoryUnavailable)
		return "", "", false
	case !authed:
		h.reject(w, categoryUnauthenticated)
		return "", "", false
	}
	return sess.Username, tok, true
}

func (h *Handler) serialOutput(w http.ResponseWriter, r *http.Request, vm string) {
	user, _, ok := h.consoleSession(w, r)
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		h.reject(w, categoryValidation)
		return
	}
	if !console.ValidVM(vm) {
		h.reject(w, categoryNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	rep, data, err := h.deps.Console.Broker.Snapshot(ctx, vm, 32<<10)
	if err != nil {
		if console.CategoryOf(err) == "unavailable" || console.CategoryOf(err) == "" {
			// The broker is not reachable: that is a typed state of the console, not an API failure.
			h.audit(user, vm, "serial.read", "unavailable")
			writeJSON(w, http.StatusOK, serialJSON{State: string(console.Unavailable)})
			return
		}
		h.audit(user, vm, "serial.read", console.CategoryOf(err))
		h.brokerError(w, err)
		return
	}
	h.audit(user, vm, "serial.read", "ok")
	writeJSON(w, http.StatusOK, serialJSON{State: string(rep.State), Text: serialText(data), Truncated: rep.Truncated, Running: rep.Running})
}

type ticketJSON struct {
	Ticket    string `json:"ticket"`
	ExpiresAt string `json:"expires_at"`
}

// consolePrechecks refuses a console for a VM that is not a running Svavyom-managed VM.
func (h *Handler) consolePrechecks(w http.ResponseWriter, r *http.Request, vm, kind string) bool {
	if h.deps.VMs == nil {
		h.reject(w, categoryUnavailable)
		return false
	}
	d, err := h.deps.VMs.Lookup(r.Context(), vm)
	switch hypervisor.CategoryOf(err) {
	case "":
	case hypervisor.NotFound:
		h.reject(w, categoryNotFound)
		return false
	default:
		h.reject(w, categoryUnavailable)
		return false
	}
	switch {
	case !d.Managed:
		h.reject(w, categoryProhibited)
		return false
	case d.State != hypervisor.StateRunning:
		h.reject(w, categoryConflict)
		return false
	case kind == console.KindGraphics && !d.Graphics:
		h.reject(w, categoryConflict) // the VM has no graphical console device (graphics_enable adds it while the VM is stopped)
		return false
	}
	return true
}

// evName gives the audit event name of a console kind: the serial events keep their names, the graphical ones are prefixed.
func evName(kind, event string) string {
	if kind == console.KindGraphics {
		return "graphics." + event
	}
	return event
}

func (h *Handler) mintTicket(w http.ResponseWriter, r *http.Request, vm, kind string) {
	c := h.deps.Console
	if h.deps.Auth == nil {
		h.reject(w, categoryUnauthenticated)
		return
	}
	sess, token, authed, failed := h.session(r)
	switch {
	case failed:
		h.reject(w, categoryUnavailable)
		return
	case !authed:
		h.reject(w, categoryUnauthenticated)
		return
	}
	if !h.sameOrigin(r) || !sess.CSRFMatches(r.Header.Get(csrfHeader)) {
		h.reject(w, categoryForbidden)
		return
	}
	if !sess.Role.AtLeast(auth.RoleOperator) { // the interactive console is a full-power channel into the guest: not for a viewer
		h.audit(sess.Username, vm, evName(kind, "ticket.refused"), "role")
		h.reject(w, categoryForbidden)
		return
	}
	if !c.Enabled || c.Tickets == nil {
		h.audit(sess.Username, vm, evName(kind, "ticket.refused"), "disabled")
		h.reject(w, categoryProhibited)
		return
	}
	if len(r.URL.Query()) != 0 || (r.ContentLength > 0 && !decodeBodyLimit(w, r, &struct{}{}, 64)) {
		h.reject(w, categoryValidation)
		return
	}
	if !h.consolePrechecks(w, r, vm, kind) {
		h.audit(sess.Username, vm, evName(kind, "ticket.refused"), "precheck")
		return
	}
	tk, exp, err := c.Tickets.Mint(token, vm, kind)
	if err != nil {
		h.reject(w, categoryUnavailable)
		return
	}
	h.audit(sess.Username, vm, evName(kind, "ticket.minted"), "ok")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, ticketJSON{Ticket: tk, ExpiresAt: exp.UTC().Format(time.RFC3339)})
}

// consoleSocket serves the interactive console. Every refusal happens BEFORE the upgrade, as a typed HTTP error; after it the
// connection carries only console bytes.
func (h *Handler) consoleSocket(w http.ResponseWriter, r *http.Request, vm, kind string) {
	c := h.deps.Console
	proto, maxMsg := consoleProto, maxInputBytes
	if kind == console.KindGraphics {
		proto, maxMsg = graphicsProto, maxGraphicsMessage
	}
	user, token, ok := h.consoleSession(w, r)
	if !ok {
		return
	}
	// A browser always sends Origin on a WebSocket handshake; its absence means this is not a browser page of ours.
	if r.Header.Get("Origin") == "" || !h.sameOrigin(r) {
		h.audit(user, vm, evName(kind, "console.refused"), "origin")
		h.reject(w, categoryForbidden)
		return
	}
	if !c.Enabled || c.Tickets == nil {
		h.audit(user, vm, evName(kind, "console.refused"), "disabled")
		h.reject(w, categoryProhibited)
		return
	}
	if _, err := console.CheckUpgrade(r); err != nil || len(r.URL.Query()) != 0 {
		h.reject(w, categoryValidation)
		return
	}
	ticket, protoOK := "", false
	for _, p := range console.Subprotocols(r) {
		switch {
		case p == proto:
			protoOK = true
		case strings.HasPrefix(p, ticketPrefix) && ticket == "":
			ticket = strings.TrimPrefix(p, ticketPrefix)
		default:
			protoOK = false
			ticket = "\x00" // an unknown extra protocol: refuse the lot
		}
	}
	if !protoOK || ticket == "" {
		h.audit(user, vm, evName(kind, "console.refused"), "protocol")
		h.reject(w, categoryValidation)
		return
	}
	// One answer for every ticket failure: unknown, tampered, expired, replayed, another session's, another VM's.
	if err := c.Tickets.Redeem(ticket, token, vm, kind); err != nil {
		h.audit(user, vm, evName(kind, "console.refused"), "ticket")
		h.reject(w, categoryForbidden)
		return
	}
	if !h.consolePrechecks(w, r, vm, kind) {
		h.audit(user, vm, evName(kind, "console.refused"), "precheck")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	if kind == console.KindGraphics {
		conn, err := c.Broker.Graphics(ctx, vm)
		cancel()
		if err != nil {
			h.audit(user, vm, evName(kind, "console.refused"), console.CategoryOf(err))
			h.brokerError(w, err)
			return
		}
		ws, err := console.Accept(w, r, proto, maxMsg)
		if err != nil {
			_ = conn.Close()
			h.reject(w, categoryValidation)
			return
		}
		h.audit(user, vm, evName(kind, "console.opened"), "ok")
		reason := h.pumpGraphics(ws, conn, token, c)
		h.audit(user, vm, evName(kind, "console.closed"), reason)
		return
	}
	att, err := c.Broker.Attach(ctx, vm)
	cancel()
	if err != nil {
		h.audit(user, vm, "console.refused", console.CategoryOf(err))
		h.brokerError(w, err)
		return
	}
	ws, err := console.Accept(w, r, proto, maxMsg)
	if err != nil {
		att.Close()
		h.reject(w, categoryValidation)
		return
	}
	h.audit(user, vm, "console.opened", "ok")
	reason := h.pumpConsole(ws, att, token, c)
	h.audit(user, vm, "console.closed", reason)
}

// pumpConsole joins the WebSocket and the broker attachment until either ends, the session ends or the lifetime bound is reached.
// It returns the closed reason (for the audit trail).
func (h *Handler) pumpConsole(ws *console.WS, att *console.Attachment, token string, c *Console) string {
	maxLife, check := c.MaxSession, c.SessionCheck
	if maxLife <= 0 {
		maxLife = time.Hour
	}
	if check <= 0 {
		check = 5 * time.Second
	}
	var once sync.Once
	reason := ""
	done := make(chan struct{})
	finish := func(why string, code int) {
		once.Do(func() {
			reason = why
			ws.Close(code)
			att.Close()
			close(done)
		})
	}
	go func() { // broker -> browser
		for {
			f, err := att.Recv()
			if err != nil {
				finish("broker", console.CloseGoingAway)
				return
			}
			switch f.T {
			case console.FrameOut:
				b, derr := console.Decode(f.D, console.MaxChunk)
				if derr != nil || ws.Write(b) != nil {
					finish("error", console.CloseInternal)
					return
				}
			case console.FrameEnd:
				if f.Reason == console.ReasonVMEnded {
					finish(f.Reason, console.CloseNormal)
				} else {
					finish(f.Reason, console.CloseGoingAway)
				}
				return
			}
		}
	}()
	go func() { // browser -> broker
		for {
			_, data, err := ws.Read()
			if err != nil {
				finish("client", console.CloseNormal)
				return
			}
			if att.Send(data) != nil {
				finish("broker", console.CloseGoingAway)
				return
			}
		}
	}()
	go func() { // the session must stay valid for as long as the console is open
		t := time.NewTicker(check)
		defer t.Stop()
		life := time.NewTimer(maxLife)
		defer life.Stop()
		for {
			select {
			case <-done:
				return
			case <-life.C:
				finish("lifetime", console.CloseGoingAway)
				return
			case <-t.C:
				if _, _, ok, failed := h.sessionByToken(context.Background(), token); !ok && !failed {
					finish("session_ended", console.ClosePolicy)
					return
				}
			}
		}
	}()
	<-done
	return reason
}

// pumpGraphics joins the WebSocket and the broker's raw VNC stream until either ends, the session ends or the lifetime bound is reached. It returns the
// closed reason for the audit trail. Nothing is interpreted here: the bytes are RFB, spoken between noVNC in the browser and the VM's VNC server.
func (h *Handler) pumpGraphics(ws *console.WS, conn net.Conn, token string, c *Console) string {
	maxLife, check := c.MaxSession, c.SessionCheck
	if maxLife <= 0 {
		maxLife = time.Hour
	}
	if check <= 0 {
		check = 5 * time.Second
	}
	var once sync.Once
	reason := ""
	done := make(chan struct{})
	finish := func(why string, code int) {
		once.Do(func() {
			reason = why
			ws.Close(code)
			_ = conn.Close()
			close(done)
		})
	}
	go func() { // VM -> browser
		buf := make([]byte, 32<<10)
		for {
			n, err := conn.Read(buf)
			if n > 0 && ws.Write(append([]byte(nil), buf[:n]...)) != nil {
				finish("error", console.CloseInternal)
				return
			}
			if err != nil {
				finish("vm_or_broker", console.CloseGoingAway)
				return
			}
		}
	}()
	go func() { // browser -> VM
		for {
			_, data, err := ws.Read()
			if err != nil {
				finish("client", console.CloseNormal)
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if _, err := conn.Write(data); err != nil {
				finish("broker", console.CloseGoingAway)
				return
			}
		}
	}()
	go func() { // the session must stay valid for as long as the console is open
		t := time.NewTicker(check)
		defer t.Stop()
		life := time.NewTimer(maxLife)
		defer life.Stop()
		for {
			select {
			case <-done:
				return
			case <-life.C:
				finish("lifetime", console.CloseGoingAway)
				return
			case <-t.C:
				if _, _, ok, failed := h.sessionByToken(context.Background(), token); !ok && !failed {
					finish("session_ended", console.ClosePolicy)
					return
				}
			}
		}
	}()
	<-done
	return reason
}

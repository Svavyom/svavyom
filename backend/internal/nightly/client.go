package nightly

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// Client is the check's API: an ordinary signed-in session of the service account over loopback, speaking the browser contract.
type Client struct {
	Base     string
	User     string
	Password string
	// RootCAs, when set, is the only trust (the installed self-signed certificate); ServerName is the name that certificate carries.
	RootCAs    *x509.CertPool
	ServerName string
	Now        func() time.Time
	Sleep      func(context.Context, time.Duration) error
	Poll       time.Duration

	hc   *http.Client
	csrf string
}

const maxReply = 1 << 20

func (c *Client) client() (*http.Client, error) {
	if c.hc != nil {
		return c.hc, nil
	}
	u, err := url.Parse(c.Base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, errors.New("nightly: bad API address")
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return nil, errors.New("nightly: the API address must be a loopback address") // the credential never leaves this host
	}
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.RootCAs, ServerName: c.ServerName}}
	c.hc = &http.Client{Jar: jar, Timeout: 30 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c.hc, nil
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) (int, http.Header, error) {
	hc, err := c.client()
	if err != nil {
		return 0, nil, err
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Base, "/")+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	res, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxReply))
	if err != nil {
		return res.StatusCode, res.Header, err
	}
	if out != nil && res.StatusCode >= 200 && res.StatusCode < 300 {
		if err := json.Unmarshal(b, out); err != nil {
			return res.StatusCode, res.Header, err
		}
	}
	return res.StatusCode, res.Header, nil
}

// SignIn performs the two-step sign-in of the browser contract.
func (c *Client) SignIn(ctx context.Context) error {
	c.csrf = ""
	st, h, err := c.do(ctx, http.MethodGet, "/api/v1/auth/session", nil, nil)
	if err != nil || st != http.StatusOK || h.Get("X-CSRF-Token") == "" {
		return errors.New("nightly: the API did not answer the session request")
	}
	c.csrf = h.Get("X-CSRF-Token")
	st, h, err = c.do(ctx, http.MethodPost, "/api/v1/auth/session", map[string]string{"username": c.User, "password": c.Password}, nil)
	if err != nil || st != http.StatusOK || h.Get("X-CSRF-Token") == "" {
		c.csrf = ""
		return errors.New("nightly: sign-in was refused")
	}
	c.csrf = h.Get("X-CSRF-Token")
	return nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	if c.csrf == "" {
		if err := c.SignIn(ctx); err != nil {
			return err
		}
	}
	st, _, err := c.do(ctx, http.MethodGet, path, nil, out)
	if err != nil {
		return err
	}
	if st == http.StatusUnauthorized { // the session ended: sign in once more
		if err := c.SignIn(ctx); err != nil {
			return err
		}
		st, _, err = c.do(ctx, http.MethodGet, path, nil, out)
		if err != nil {
			return err
		}
	}
	if st != http.StatusOK {
		return errors.New("nightly: unexpected answer")
	}
	return nil
}

type hostWire struct {
	Observed struct {
		MemoryMiB int `json:"memory_mib"`
		Creation  struct {
			Ready    bool  `json:"ready"`
			VCPUs    []int `json:"vcpu_options"`
			Memory   []int `json:"memory_mib_options"`
			DiskGiBs []int `json:"disk_gib_options"`
		} `json:"creation"`
		Storage struct {
			PoolFree *int `json:"pool_free_gib"`
		} `json:"storage"`
		Usage struct {
			State string `json:"state"`
			Used  *int64 `json:"memory_used_mib"`
		} `json:"usage"`
	} `json:"observed"`
}

// Host implements API.
func (c *Client) Host(ctx context.Context) (HostState, error) {
	var h hostWire
	if err := c.get(ctx, "/api/v1/hosts/local", &h); err != nil {
		return HostState{}, err
	}
	o := h.Observed
	hs := HostState{CreationReady: o.Creation.Ready, PoolFreeGiB: o.Storage.PoolFree, VCPUOptions: o.Creation.VCPUs, MemoryOptions: o.Creation.Memory, DiskOptions: o.Creation.DiskGiBs}
	if o.Usage.State == "available" && o.Usage.Used != nil && o.MemoryMiB > 0 {
		free := o.MemoryMiB - int(*o.Usage.Used)
		hs.MemoryFreeMiB = &free
	}
	return hs, nil
}

// Images implements API.
func (c *Client) Images(ctx context.Context) ([]Image, error) {
	var l struct {
		Items []struct {
			ID       string `json:"id"`
			Observed struct {
				Media         string `json:"media"`
				Qualification string `json:"qualification"`
				MinDisk       int    `json:"min_disk_gib"`
			} `json:"observed"`
		} `json:"items"`
	}
	if err := c.get(ctx, "/api/v1/images?limit=200", &l); err != nil {
		return nil, err
	}
	var out []Image
	for _, i := range l.Items {
		out = append(out, Image{ID: i.ID, Qualified: i.Observed.Qualification == "qualified" && i.Observed.Media == "disk", MinDisk: i.Observed.MinDisk})
	}
	return out, nil
}

// VMs implements API.
func (c *Client) VMs(ctx context.Context) ([]VM, error) {
	var l struct {
		Items []struct {
			Name     string `json:"name"`
			Observed struct {
				Power   string  `json:"power"`
				Managed bool    `json:"managed"`
				IP      *string `json:"ip_address"`
			} `json:"observed"`
		} `json:"items"`
	}
	if err := c.get(ctx, "/api/v1/vms?limit=200", &l); err != nil {
		return nil, err
	}
	var out []VM
	for _, v := range l.Items {
		vm := VM{Name: v.Name, Managed: v.Observed.Managed, Power: v.Observed.Power}
		if v.Observed.IP != nil {
			vm.IP = *v.Observed.IP
		}
		out = append(out, vm)
	}
	return out, nil
}

// ActiveOperations implements API: how many operations are queued, running or waiting to be retried.
func (c *Client) ActiveOperations(ctx context.Context) (int, error) {
	var l struct {
		Items []struct {
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := c.get(ctx, "/api/v1/operations?limit=100", &l); err != nil {
		return 0, err
	}
	n := 0
	for _, o := range l.Items {
		if o.Status == "pending" || o.Status == "running" || o.Status == "retryable_failure" {
			n++
		}
	}
	return n, nil
}

func randKey() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "nb-" + hex.EncodeToString(b[:])
}

// Submit implements API.
func (c *Client) Submit(ctx context.Context, typ, name string, cr *CreateRequest) (string, error) {
	if c.csrf == "" {
		if err := c.SignIn(ctx); err != nil {
			return "", err
		}
	}
	body := map[string]any{"type": typ, "kind": "VM", "id": name, "idempotency_key": randKey()}
	if cr != nil {
		body["create"] = map[string]any{"vcpus": cr.VCPUs, "memory_mib": cr.MemoryMiB, "disk_gib": cr.DiskGiB, "image_id": cr.ImageID, "ssh_public_key": cr.SSHPublicKey}
	}
	var op struct {
		ID string `json:"id"`
	}
	st, _, err := c.do(ctx, http.MethodPost, "/api/v1/operations", body, &op)
	if err != nil {
		return "", err
	}
	if st != http.StatusAccepted || op.ID == "" {
		return "", errors.New("nightly: the request was refused")
	}
	return op.ID, nil
}

// Wait implements API.
func (c *Client) Wait(ctx context.Context, id string, timeout time.Duration) (string, error) {
	now := c.Now
	if now == nil {
		now = time.Now
	}
	sleep := c.Sleep
	if sleep == nil {
		sleep = func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		}
	}
	poll := c.Poll
	if poll <= 0 {
		poll = 3 * time.Second
	}
	end := now().Add(timeout)
	for {
		var op struct {
			Status string `json:"status"`
		}
		if err := c.get(ctx, "/api/v1/operations/"+id, &op); err != nil {
			return "", err
		}
		switch op.Status {
		case "succeeded", "failed", "cancelled":
			return op.Status, nil
		}
		if now().After(end) {
			return "", errors.New("nightly: still open at the deadline")
		}
		if err := sleep(ctx, poll); err != nil {
			return "", err
		}
	}
}

// DialProber reads the SSH banner with a plain TCP connection to port 22.
type DialProber struct {
	Timeout time.Duration
	Port    string // "22" when empty; tests use another port
}

// SSHBanner implements Prober.
func (p DialProber) SSHBanner(ctx context.Context, ip string) (string, error) {
	if net.ParseIP(ip) == nil {
		return "", errors.New("nightly: not an address")
	}
	to := p.Timeout
	if to <= 0 {
		to = 5 * time.Second
	}
	d := net.Dialer{Timeout: to}
	port := p.Port
	if port == "" {
		port = "22"
	}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(to))
	buf := make([]byte, 255)
	n, err := conn.Read(buf)
	if n == 0 && err != nil {
		return "", err
	}
	line := string(buf[:n])
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	return line, nil
}

package nightly

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeServer speaks just enough of the browser contract to prove the sign-in dance and the request shapes.
type fakeServer struct {
	mu      sync.Mutex
	posts   []map[string]any
	status  []string
	expired bool
	logins  int
}

func (s *fakeServer) handler() http.Handler {
	mux := http.NewServeMux()
	cookie := func(w http.ResponseWriter, n, v string) {
		http.SetCookie(w, &http.Cookie{Name: n, Value: v, Path: "/", HttpOnly: true})
	}
	mux.HandleFunc("/api/v1/auth/session", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch r.Method {
		case "GET":
			cookie(w, "svavyom_login", "nonce")
			w.Header().Set("X-CSRF-Token", "login-csrf")
			_, _ = w.Write([]byte(`{"authenticated":false}`))
		case "POST":
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			if r.Header.Get("X-CSRF-Token") != "login-csrf" || b["username"] != "svavyom-nightly" || b["password"] != "right-password" {
				w.WriteHeader(401)
				return
			}
			s.logins++
			s.expired = false
			cookie(w, "svavyom_session", "sess")
			w.Header().Set("X-CSRF-Token", "session-csrf")
			_, _ = w.Write([]byte(`{"authenticated":true}`))
		}
	})
	authed := func(w http.ResponseWriter, r *http.Request) bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		c, err := r.Cookie("svavyom_session")
		if err != nil || c.Value != "sess" || s.expired {
			w.WriteHeader(401)
			return false
		}
		return true
	}
	mux.HandleFunc("/api/v1/hosts/local", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) {
			_, _ = w.Write([]byte(`{"observed":{"memory_mib":16000,"creation":{"ready":true,"vcpu_options":[1,2],"memory_mib_options":[512,1024],"disk_gib_options":[10,20]},"storage":{"pool_free_gib":300},"usage":{"state":"available","memory_used_mib":4000}}}`))
		}
	})
	mux.HandleFunc("/api/v1/images", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) {
			_, _ = w.Write([]byte(`{"items":[{"id":"iso-1","observed":{"media":"iso","qualification":"qualified","min_disk_gib":5}},{"id":"deb","observed":{"media":"disk","qualification":"verified","min_disk_gib":3}},{"id":"ubu","observed":{"media":"disk","qualification":"qualified","min_disk_gib":10}}]}`))
		}
	})
	mux.HandleFunc("/api/v1/vms", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) {
			_, _ = w.Write([]byte(`{"items":[{"name":"svnb-1","observed":{"power":"running","managed":true,"ip_address":"192.168.122.9"}},{"name":"web","observed":{"power":"stopped","managed":false,"ip_address":null}}]}`))
		}
	})
	mux.HandleFunc("/api/v1/operations", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		if r.Method == "POST" {
			if r.Header.Get("X-CSRF-Token") != "session-csrf" {
				w.WriteHeader(403)
				return
			}
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			s.mu.Lock()
			s.posts = append(s.posts, b)
			s.mu.Unlock()
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"id":"op-1"}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[{"status":"succeeded"},{"status":"running"},{"status":"retryable_failure"},{"status":"failed"}]}`))
	})
	mux.HandleFunc("/api/v1/operations/op-1", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		s.mu.Lock()
		st := "succeeded"
		if len(s.status) > 0 {
			st, s.status = s.status[0], s.status[1:]
		}
		s.mu.Unlock()
		_, _ = w.Write([]byte(`{"status":"` + st + `"}`))
	})
	return mux
}

func newClient(t *testing.T, s *fakeServer) *Client {
	t.Helper()
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	return &Client{Base: srv.URL, User: "svavyom-nightly", Password: "right-password", Sleep: func(context.Context, time.Duration) error { return nil }}
}

func TestClientSignsInAndReadsTheHostImagesAndVMs(t *testing.T) {
	s := &fakeServer{}
	c := newClient(t, s)
	ctx := context.Background()
	h, err := c.Host(ctx)
	if err != nil || !h.CreationReady || h.PoolFreeGiB == nil || *h.PoolFreeGiB != 300 || h.MemoryFreeMiB == nil || *h.MemoryFreeMiB != 12000 || len(h.DiskOptions) != 2 {
		t.Fatalf("%+v %v", h, err)
	}
	imgs, err := c.Images(ctx)
	if err != nil || len(imgs) != 3 || imgs[0].Qualified || imgs[1].Qualified || !imgs[2].Qualified || imgs[2].MinDisk != 10 {
		t.Fatalf("an installation ISO is never the check's image: %+v %v", imgs, err)
	}
	vms, err := c.VMs(ctx)
	if err != nil || len(vms) != 2 || vms[0].IP != "192.168.122.9" || !vms[0].Managed || vms[1].Managed || vms[1].IP != "" {
		t.Fatalf("%+v %v", vms, err)
	}
	if n, err := c.ActiveOperations(ctx); err != nil || n != 2 {
		t.Fatalf("two open operations: %d %v", n, err)
	}
	if s.logins != 1 {
		t.Fatalf("one sign-in serves them all: %d", s.logins)
	}
}

func TestClientSubmitsTheContractShapesAndFollowsTheOperation(t *testing.T) {
	s := &fakeServer{status: []string{"pending", "running", "succeeded"}}
	c := newClient(t, s)
	ctx := context.Background()
	id, err := c.Submit(ctx, "create", "svnb-ab12", &CreateRequest{VCPUs: 1, MemoryMiB: 512, DiskGiB: 10, ImageID: "ubu", SSHPublicKey: "ssh-ed25519 AAAA"})
	if err != nil || id != "op-1" {
		t.Fatalf("%q %v", id, err)
	}
	if _, err := c.Submit(ctx, "stop", "svnb-ab12", nil); err != nil {
		t.Fatal(err)
	}
	p := s.posts[0]
	cr, _ := p["create"].(map[string]any)
	if p["type"] != "create" || p["kind"] != "VM" || p["id"] != "svnb-ab12" || !strings.HasPrefix(p["idempotency_key"].(string), "nb-") || cr["image_id"] != "ubu" || cr["disk_gib"] != float64(10) {
		t.Fatalf("%v", p)
	}
	if _, ok := s.posts[1]["create"]; ok {
		t.Fatal("only a create carries a definition")
	}
	st, err := c.Wait(ctx, "op-1", time.Minute)
	if err != nil || st != "succeeded" {
		t.Fatalf("%q %v", st, err)
	}
}

func TestClientWaitGivesUpAtTheDeadline(t *testing.T) {
	s := &fakeServer{status: []string{"running", "running", "running", "running", "running"}}
	c := newClient(t, s)
	clock := time.Now()
	c.Now = func() time.Time { return clock }
	c.Sleep = func(_ context.Context, d time.Duration) error { clock = clock.Add(d); return nil }
	c.Poll = 10 * time.Second
	if st, err := c.Wait(context.Background(), "op-1", 25*time.Second); err == nil {
		t.Fatalf("an operation still open at the deadline is an error, got %q", st)
	}
}

func TestClientSignsInAgainWhenTheSessionEnds(t *testing.T) {
	s := &fakeServer{}
	c := newClient(t, s)
	ctx := context.Background()
	if _, err := c.VMs(ctx); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.expired = true
	s.mu.Unlock()
	if _, err := c.VMs(ctx); err != nil {
		t.Fatalf("a 401 triggers one new sign-in: %v", err)
	}
	if s.logins != 2 {
		t.Fatalf("%d", s.logins)
	}
}

func TestClientRefusesAWrongPasswordAndANonLoopbackAddress(t *testing.T) {
	s := &fakeServer{}
	c := newClient(t, s)
	c.Password = "wrong"
	if _, err := c.VMs(context.Background()); err == nil {
		t.Fatal("a refused sign-in is an error")
	}
	for _, base := range []string{"http://10.0.0.5:8443", "https://example.com", "http://localhost:8443", "ftp://127.0.0.1", "127.0.0.1"} {
		bad := &Client{Base: base, User: "u", Password: "p"}
		if _, err := bad.VMs(context.Background()); err == nil {
			t.Errorf("%s: the credential must not be sent anywhere but a loopback address", base)
		}
	}
}

func TestDialProberReadsOnlyTheFirstLineOfTheBanner(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener")
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\nsecond line"))
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	b, err := (DialProber{Port: port}).SSHBanner(context.Background(), "127.0.0.1")
	if err != nil || b != "SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := (DialProber{}).SSHBanner(context.Background(), "not-an-ip"); err == nil {
		t.Fatal("only an address is probed")
	}
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	_, closed, _ := net.SplitHostPort(l2.Addr().String())
	_ = l2.Close()
	if _, err := (DialProber{Port: closed, Timeout: time.Second}).SSHBanner(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("nothing listening is an error")
	}
}

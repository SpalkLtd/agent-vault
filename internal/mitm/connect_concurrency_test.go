package mitm

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// openRawTunnel dials the proxy, sends a CONNECT with valid proxy auth, reads
// the status line, and returns the still-open connection plus the status code.
// The caller is responsible for closing the connection (which releases the
// tunnel's concurrency slot).
func openRawTunnel(t *testing.T, proxyURL *url.URL, token string) (net.Conn, int) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte(token + ":"))
	_, _ = fmt.Fprintf(conn,
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic %s\r\n\r\n",
		auth)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	_ = conn.SetReadDeadline(time.Time{})
	return conn, resp.StatusCode
}

// TestMITMConnectConcurrencyCap verifies the MEDIUM fix: simultaneously-open
// CONNECT tunnels are bounded, so a malicious agent holding a valid proxy
// token cannot open unbounded tunnels (each pinning an fd/goroutine/TLS conn)
// and exhaust the proxy for all tenants.
func TestMITMConnectConcurrencyCap(t *testing.T) {
	sr := validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
	cp := &fakeCredProvider{}
	proxyURL, _, _ := setupProxy(t, sr, cp, func(o *Options) {
		o.MaxConcurrentTunnels = 2
	})
	// Non-loopback peer so the tunnel path is exercised normally.
	// (loopback is exempt from the auth flood gate but not from the cap.)

	// Hold two tunnels open — fills the cap.
	c1, s1 := openRawTunnel(t, proxyURL, "av_sess_ok")
	defer c1.Close()
	c2, s2 := openRawTunnel(t, proxyURL, "av_sess_ok")
	defer c2.Close()
	if s1 != http.StatusOK || s2 != http.StatusOK {
		t.Fatalf("first two tunnels should be established: got %d, %d", s1, s2)
	}

	// Third concurrent tunnel must be rejected (capacity).
	c3, s3 := openRawTunnel(t, proxyURL, "av_sess_ok")
	defer c3.Close()
	if s3 != http.StatusServiceUnavailable {
		t.Fatalf("third concurrent tunnel: got %d, want 503 (cap=2)", s3)
	}

	// Free a slot; a new tunnel should now be admitted.
	c1.Close()
	var s4 int
	var c4 net.Conn
	for i := 0; i < 50; i++ { // allow the freed slot to be released
		c4, s4 = openRawTunnel(t, proxyURL, "av_sess_ok")
		if s4 == http.StatusOK {
			break
		}
		c4.Close()
		time.Sleep(20 * time.Millisecond)
	}
	defer func() {
		if c4 != nil {
			c4.Close()
		}
	}()
	if s4 != http.StatusOK {
		t.Fatalf("tunnel after freeing a slot: got %d, want 200", s4)
	}
}

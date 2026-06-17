package github

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

var testEncKey = []byte("0123456789abcdef0123456789abcdef") // 32 bytes

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// ghAPIServer fakes the two GitHub endpoints the resolver uses, counting token
// mints. mintStatus lets a test force a failure.
func ghAPIServer(t *testing.T, mints *int32, mintStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/access_tokens"):
			if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
				t.Errorf("mint missing bearer JWT, got %q", got)
			}
			n := atomic.AddInt32(mints, 1)
			if mintStatus != 0 && mintStatus != 201 {
				w.WriteHeader(mintStatus)
				_, _ = io.WriteString(w, `{"message":"nope"}`)
				return
			}
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"token":"ghs_mint%d","expires_at":"2099-01-01T00:00:00Z"}`, n)
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/app"):
			_, _ = io.WriteString(w, `{"slug":"spalk-agent"}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
}

func seedInstall(t *testing.T, st *store.SQLiteStore, key string, withKey bool) string {
	t.Helper()
	ctx := context.Background()
	v, err := st.CreateVault(ctx, "test")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	inst := &store.GitHubAppInstallation{VaultID: v.ID, CredentialKey: key, AppID: "123", InstallationID: "456"}
	if withKey {
		pemKey, _ := testRSAKeyPEM(t, false)
		ct, nonce, err := crypto.Encrypt(pemKey, testEncKey)
		if err != nil {
			t.Fatalf("encrypt pem: %v", err)
		}
		inst.PrivateKeyCT, inst.PrivateKeyNonce = ct, nonce
	}
	if err := st.SetGitHubAppInstallation(ctx, inst); err != nil {
		t.Fatalf("seed install: %v", err)
	}
	return v.ID
}

func withAPIBase(t *testing.T, url string) {
	t.Helper()
	old := APIBase
	APIBase = url
	t.Cleanup(func() { APIBase = old })
}

func TestResolveMintsAndCaches(t *testing.T) {
	var mints int32
	ts := ghAPIServer(t, &mints, 201)
	defer ts.Close()
	withAPIBase(t, ts.URL)

	st := newStore(t)
	vaultID := seedInstall(t, st, "GITHUB", true)
	r := NewResolver(st, testEncKey, testLogger())
	ctx := context.Background()

	tok, ok, err := r.Resolve(ctx, vaultID, "GITHUB")
	if err != nil || !ok || tok != "ghs_mint1" {
		t.Fatalf("Resolve: tok=%q ok=%v err=%v", tok, ok, err)
	}
	tok2, _, err := r.Resolve(ctx, vaultID, "GITHUB")
	if err != nil || tok2 != "ghs_mint1" {
		t.Fatalf("second Resolve (cache): tok=%q err=%v", tok2, err)
	}
	if got := atomic.LoadInt32(&mints); got != 1 {
		t.Fatalf("expected 1 mint (cached), got %d", got)
	}
}

func TestResolveSingleFlight(t *testing.T) {
	var mints int32
	ts := ghAPIServer(t, &mints, 201)
	defer ts.Close()
	withAPIBase(t, ts.URL)

	st := newStore(t)
	vaultID := seedInstall(t, st, "GITHUB", true)
	r := NewResolver(st, testEncKey, testLogger())

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _, _ = r.Resolve(context.Background(), vaultID, "GITHUB") }()
	}
	wg.Wait()
	if got := atomic.LoadInt32(&mints); got != 1 {
		t.Fatalf("single-flight: expected 1 mint for 20 concurrent resolves, got %d", got)
	}
}

func TestResolveNotConnected(t *testing.T) {
	st := newStore(t)
	vaultID := seedInstall(t, st, "GITHUB", false) // no private key
	r := NewResolver(st, testEncKey, testLogger())
	_, ok, err := r.Resolve(context.Background(), vaultID, "GITHUB")
	if ok || err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("expected not-connected error, got ok=%v err=%v", ok, err)
	}
}

func TestResolveUnknownKeyFallsThrough(t *testing.T) {
	st := newStore(t)
	vaultID := seedInstall(t, st, "GITHUB", true)
	r := NewResolver(st, testEncKey, testLogger())
	val, ok, err := r.Resolve(context.Background(), vaultID, "STRIPE_KEY")
	if ok || err != nil || val != "" {
		t.Fatalf("expected (\"\",false,nil) for non-github key, got (%q,%v,%v)", val, ok, err)
	}
}

func TestResolveMintError(t *testing.T) {
	var mints int32
	ts := ghAPIServer(t, &mints, 403) // installation token mint forbidden
	defer ts.Close()
	withAPIBase(t, ts.URL)

	st := newStore(t)
	vaultID := seedInstall(t, st, "GITHUB", true)
	r := NewResolver(st, testEncKey, testLogger())
	_, ok, err := r.Resolve(context.Background(), vaultID, "GITHUB")
	if ok || err == nil || !strings.Contains(err.Error(), "mint") {
		t.Fatalf("expected mint error, got ok=%v err=%v", ok, err)
	}
	// last_mint_error recorded.
	cred, _ := st.GetGitHubAppInstallation(context.Background(), vaultID, "GITHUB")
	if cred.LastMintError == "" {
		t.Fatalf("expected last_mint_error recorded")
	}
}

func TestResolveBadPEM(t *testing.T) {
	var mints int32
	ts := ghAPIServer(t, &mints, 201)
	defer ts.Close()
	withAPIBase(t, ts.URL)

	st := newStore(t)
	ctx := context.Background()
	v, _ := st.CreateVault(ctx, "test")
	ct, nonce, _ := crypto.Encrypt([]byte("-----BEGIN RSA PRIVATE KEY-----\nbad\n-----END RSA PRIVATE KEY-----\n"), testEncKey)
	_ = st.SetGitHubAppInstallation(ctx, &store.GitHubAppInstallation{
		VaultID: v.ID, CredentialKey: "GITHUB", AppID: "1", InstallationID: "2",
		PrivateKeyCT: ct, PrivateKeyNonce: nonce,
	})
	r := NewResolver(st, testEncKey, testLogger())
	if _, ok, err := r.Resolve(ctx, v.ID, "GITHUB"); ok || err == nil {
		t.Fatalf("expected bad-PEM error, got ok=%v err=%v", ok, err)
	}
}

func TestValidateCapturesSlug(t *testing.T) {
	var mints int32
	ts := ghAPIServer(t, &mints, 201)
	defer ts.Close()
	withAPIBase(t, ts.URL)

	st := newStore(t)
	vaultID := seedInstall(t, st, "GITHUB", true)
	r := NewResolver(st, testEncKey, testLogger())

	slug, err := r.Validate(context.Background(), vaultID, "GITHUB")
	if err != nil || slug != "spalk-agent" {
		t.Fatalf("Validate: slug=%q err=%v", slug, err)
	}
	cred, _ := st.GetGitHubAppInstallation(context.Background(), vaultID, "GITHUB")
	if cred.AppSlug != "spalk-agent" || cred.ConnectedAt == nil {
		t.Fatalf("Validate should persist slug + connected_at: %+v", cred)
	}
}

func TestEnumerate(t *testing.T) {
	st := newStore(t)
	vaultID := seedInstall(t, st, "GITHUB", true)
	r := NewResolver(st, testEncKey, testLogger())
	creds, err := r.Enumerate(context.Background(), vaultID)
	if err != nil || len(creds) != 1 || creds[0].Key != "GITHUB" || !creds[0].Connected {
		t.Fatalf("enumerate: %+v err=%v", creds, err)
	}
}

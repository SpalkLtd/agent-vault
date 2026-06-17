package github

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

var testKey = []byte("0123456789abcdef0123456789abcdef") // 32 bytes

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func enc(t *testing.T, s string) (ct, nonce []byte) {
	t.Helper()
	ct, nonce, err := crypto.Encrypt([]byte(s), testKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return ct, nonce
}

// seedConnected creates a vault and a connected GitHub credential, returning the
// vault ID.
func seedConnected(t *testing.T, st *store.SQLiteStore, key, refreshTok string) string {
	t.Helper()
	ctx := context.Background()
	v, err := st.CreateVault(ctx, "test")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	csCT, csNonce := enc(t, "client-secret")
	if err := st.SetGitHubAppCredential(ctx, &store.GitHubAppCredential{
		VaultID:           v.ID,
		CredentialKey:     key,
		ClientID:          "cid",
		ClientSecretCT:    csCT,
		ClientSecretNonce: csNonce,
		Scopes:            "repo,read:org",
	}); err != nil {
		t.Fatalf("set github cred: %v", err)
	}
	rct, rnonce := enc(t, refreshTok)
	if err := st.UpdateGitHubRefreshToken(ctx, v.ID, key, rct, rnonce, nil, "alice"); err != nil {
		t.Fatalf("set refresh token: %v", err)
	}
	return v.ID
}

// tokenServer returns an httptest server that mints rotating tokens and counts
// hits. Each response rotates the refresh token to refresh-N.
func tokenServer(t *testing.T, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(hits, 1)
		body, _ := io.ReadAll(r.Body)
		if !containsAll(string(body), "grant_type=refresh_token", "client_id=cid") {
			t.Errorf("unexpected token request body: %s", string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"ghu_mint%d","refresh_token":"ghr_rot%d","expires_in":28800,"refresh_token_expires_in":15724800}`, n, n)
	}))
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func newStore(t *testing.T) *store.SQLiteStore {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestResolveMintsCachesAndRotates(t *testing.T) {
	var hits int32
	ts := tokenServer(t, &hits)
	defer ts.Close()
	oldURL := TokenURL
	TokenURL = ts.URL
	defer func() { TokenURL = oldURL }()

	st := newStore(t)
	vaultID := seedConnected(t, st, "GITHUB_TOKEN", "ghr_initial")
	r := NewResolver(st, testKey, testLogger())

	ctx := context.Background()
	tok, ok, err := r.Resolve(ctx, vaultID, "GITHUB_TOKEN")
	if err != nil || !ok {
		t.Fatalf("Resolve: tok=%q ok=%v err=%v", tok, ok, err)
	}
	if tok != "ghu_mint1" {
		t.Fatalf("expected ghu_mint1, got %q", tok)
	}

	// Rotated refresh token persisted.
	cred, err := st.GetGitHubAppCredential(ctx, vaultID, "GITHUB_TOKEN")
	if err != nil {
		t.Fatalf("get cred: %v", err)
	}
	plain, err := crypto.Decrypt(cred.RefreshTokenCT, cred.RefreshTokenNonce, testKey)
	if err != nil {
		t.Fatalf("decrypt refresh: %v", err)
	}
	if string(plain) != "ghr_rot1" {
		t.Fatalf("expected rotated refresh ghr_rot1, got %q", string(plain))
	}
	if cred.RefreshTokenExpiresAt == nil {
		t.Fatalf("expected refresh_token_expires_at to be set")
	}

	// Second resolve hits the in-memory cache: no new mint.
	tok2, _, err := r.Resolve(ctx, vaultID, "GITHUB_TOKEN")
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if tok2 != "ghu_mint1" {
		t.Fatalf("expected cached ghu_mint1, got %q", tok2)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected exactly 1 token-endpoint hit, got %d", got)
	}
}

func TestResolveSingleFlight(t *testing.T) {
	var hits int32
	ts := tokenServer(t, &hits)
	defer ts.Close()
	oldURL := TokenURL
	TokenURL = ts.URL
	defer func() { TokenURL = oldURL }()

	st := newStore(t)
	vaultID := seedConnected(t, st, "GITHUB_TOKEN", "ghr_initial")
	r := NewResolver(st, testKey, testLogger())

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = r.Resolve(context.Background(), vaultID, "GITHUB_TOKEN")
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("single-flight: expected 1 mint for 20 concurrent resolves, got %d", got)
	}
}

func TestResolveNotConnected(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	v, err := st.CreateVault(ctx, "test")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	if err := st.SetGitHubAppCredential(ctx, &store.GitHubAppCredential{
		VaultID: v.ID, CredentialKey: "GITHUB_TOKEN", ClientID: "cid",
	}); err != nil {
		t.Fatalf("set cred: %v", err)
	}
	r := NewResolver(st, testKey, testLogger())

	_, ok, err := r.Resolve(ctx, v.ID, "GITHUB_TOKEN")
	if ok {
		t.Fatalf("expected ok=false for not-connected credential")
	}
	if err == nil {
		t.Fatalf("expected an error for not-connected credential")
	}
}

func TestResolveUnknownKeyFallsThrough(t *testing.T) {
	st := newStore(t)
	vaultID := seedConnected(t, st, "GITHUB_TOKEN", "ghr_initial")
	r := NewResolver(st, testKey, testLogger())

	val, ok, err := r.Resolve(context.Background(), vaultID, "STRIPE_KEY")
	if ok || err != nil || val != "" {
		t.Fatalf("expected (\"\", false, nil) for non-GitHub key, got (%q, %v, %v)", val, ok, err)
	}
}

func TestEnumerate(t *testing.T) {
	st := newStore(t)
	vaultID := seedConnected(t, st, "GITHUB_TOKEN", "ghr_initial")
	r := NewResolver(st, testKey, testLogger())

	creds, err := r.Enumerate(context.Background(), vaultID)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(creds) != 1 || creds[0].Key != "GITHUB_TOKEN" || !creds[0].Connected || creds[0].Identity != "alice" {
		t.Fatalf("unexpected enumerate result: %+v", creds)
	}
}

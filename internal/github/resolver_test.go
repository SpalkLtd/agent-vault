package github

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
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

func TestEnumerateError(t *testing.T) {
	r := NewResolver(&fakeStore{listErr: errors.New("db down")}, testKey, testLogger())
	_, err := r.Enumerate(context.Background(), "v1")
	if err == nil || !contains(err.Error(), "db down") {
		t.Fatalf("expected propagated 'db down' error, got %v", err)
	}
}

func TestEvictVault(t *testing.T) {
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

	if _, _, err := r.Resolve(ctx, vaultID, "GITHUB_TOKEN"); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	r.EvictVault(vaultID)       // drops the cached token
	r.EvictVault("other-vault") // no-op, exercises the non-matching branch
	if _, _, err := r.Resolve(ctx, vaultID, "GITHUB_TOKEN"); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected 2 mints after eviction, got %d", got)
	}
}

func TestResolveGetErrorAndNilCred(t *testing.T) {
	ctx := context.Background()

	// Generic store error propagates verbatim.
	r1 := NewResolver(&fakeStore{getErr: errors.New("db down")}, testKey, testLogger())
	if _, ok, err := r1.Resolve(ctx, "v1", "GITHUB_TOKEN"); ok || err == nil || !contains(err.Error(), "db down") {
		t.Fatalf("expected (false, 'db down'), got ok=%v err=%v", ok, err)
	}

	// Nil credential (no row) → not a GitHub key.
	r2 := NewResolver(&fakeStore{}, testKey, testLogger())
	if _, ok, err := r2.Resolve(ctx, "v1", "GITHUB_TOKEN"); ok || err != nil {
		t.Fatalf("expected (false, nil) on nil cred, got ok=%v err=%v", ok, err)
	}
}

func TestMintDecryptFailures(t *testing.T) {
	ctx := context.Background()

	// Undecryptable refresh token (correct nonce length, wrong content → GCM
	// auth failure, not a panic).
	badCT, badNonce := []byte("0123456789abcdef"), make([]byte, 12)
	r1 := NewResolver(&fakeStore{cred: &store.GitHubAppCredential{
		VaultID: "v1", CredentialKey: "GITHUB_TOKEN", ClientID: "cid",
		RefreshTokenCT: badCT, RefreshTokenNonce: badNonce,
	}}, testKey, testLogger())
	// Must fail specifically on the refresh-token decrypt, before anything else.
	if _, _, err := r1.Resolve(ctx, "v1", "GITHUB_TOKEN"); err == nil || !contains(err.Error(), "decrypt refresh token") {
		t.Fatalf("expected 'decrypt refresh token' failure, got %v", err)
	}

	// Valid refresh token, undecryptable client secret → must fail on the client
	// secret decrypt (proves it got past the refresh-token decrypt).
	rct, rnonce := enc(t, "ghr_x")
	r2 := NewResolver(&fakeStore{cred: &store.GitHubAppCredential{
		VaultID: "v1", CredentialKey: "GITHUB_TOKEN", ClientID: "cid",
		RefreshTokenCT: rct, RefreshTokenNonce: rnonce,
		ClientSecretCT: badCT, ClientSecretNonce: badNonce,
	}}, testKey, testLogger())
	if _, _, err := r2.Resolve(ctx, "v1", "GITHUB_TOKEN"); err == nil || !contains(err.Error(), "decrypt client secret") {
		t.Fatalf("expected 'decrypt client secret' failure, got %v", err)
	}
}

func TestMintRefreshErrors(t *testing.T) {
	ctx := context.Background()
	rct, rnonce := enc(t, "ghr_x")
	connected := func() *store.GitHubAppCredential {
		return &store.GitHubAppCredential{
			VaultID: "v1", CredentialKey: "GITHUB_TOKEN", ClientID: "cid",
			RefreshTokenCT: rct, RefreshTokenNonce: rnonce,
		}
	}

	// Permanent (400) → actionable re-connect message + last_mint_error recorded.
	ts400 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"error":"bad_refresh_token"}`)
	}))
	defer ts400.Close()
	oldURL := TokenURL
	TokenURL = ts400.URL
	fs := &fakeStore{cred: connected()}
	r := NewResolver(fs, testKey, testLogger())
	_, _, err := r.Resolve(ctx, "v1", "GITHUB_TOKEN")
	// Permanent failure must surface the actionable re-connect guidance, both in
	// the returned error and the recorded last_mint_error.
	if err == nil || !contains(err.Error(), "re-run") || !contains(fs.mintErr, "re-run") {
		t.Fatalf("expected permanent 're-run' mint error, err=%v recorded=%q", err, fs.mintErr)
	}

	// Transient (500) → generic mint failure, NOT the re-connect guidance.
	ts500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts500.Close()
	TokenURL = ts500.URL
	defer func() { TokenURL = oldURL }()
	_, _, err = NewResolver(&fakeStore{cred: connected()}, testKey, testLogger()).Resolve(ctx, "v1", "GITHUB_TOKEN")
	if err == nil || !contains(err.Error(), "github mint failed") || contains(err.Error(), "re-run") {
		t.Fatalf("expected transient 'github mint failed' (not re-run), got %v", err)
	}
}

func TestMintPersistAndEncryptFailures(t *testing.T) {
	ctx := context.Background()
	rct, rnonce := enc(t, "ghr_x")
	connected := func() *store.GitHubAppCredential {
		return &store.GitHubAppCredential{
			VaultID: "v1", CredentialKey: "GITHUB_TOKEN", ClientID: "cid",
			RefreshTokenCT: rct, RefreshTokenNonce: rnonce,
		}
	}
	var hits int32
	ts := tokenServer(t, &hits)
	defer ts.Close()
	oldURL := TokenURL
	TokenURL = ts.URL
	defer func() { TokenURL = oldURL }()

	// Persisting the rotated refresh token fails → mint fails specifically there
	// (proves the exchange succeeded and we stopped at persistence, never serving).
	fs := &fakeStore{cred: connected(), updErr: errors.New("write failed")}
	if _, _, err := NewResolver(fs, testKey, testLogger()).Resolve(ctx, "v1", "GITHUB_TOKEN"); err == nil || !contains(err.Error(), "persist rotated refresh token") {
		t.Fatalf("expected 'persist rotated refresh token' failure, got %v", err)
	}

	// Encrypting the rotated refresh token fails → mint fails specifically there.
	r := NewResolver(&fakeStore{cred: connected()}, testKey, testLogger())
	r.encrypt = func(_, _ []byte) ([]byte, []byte, error) { return nil, nil, errors.New("enc fail") }
	if _, _, err := r.Resolve(ctx, "v1", "GITHUB_TOKEN"); err == nil || !contains(err.Error(), "encrypt rotated refresh token") {
		t.Fatalf("expected 'encrypt rotated refresh token' failure, got %v", err)
	}
}

func TestMintExpiryFallback(t *testing.T) {
	ctx := context.Background()
	rct, rnonce := enc(t, "ghr_x")
	// Token server returns a refresh token but NO expires_in → fallback TTL.
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.WriteString(w, `{"access_token":"ghu_x","refresh_token":"ghr_y"}`)
	}))
	defer ts.Close()
	oldURL := TokenURL
	TokenURL = ts.URL
	defer func() { TokenURL = oldURL }()

	r := NewResolver(&fakeStore{cred: &store.GitHubAppCredential{
		VaultID: "v1", CredentialKey: "GITHUB_TOKEN", ClientID: "cid",
		RefreshTokenCT: rct, RefreshTokenNonce: rnonce,
	}}, testKey, testLogger())
	tok, _, err := r.Resolve(ctx, "v1", "GITHUB_TOKEN")
	if err != nil || tok != "ghu_x" {
		t.Fatalf("resolve: tok=%q err=%v", tok, err)
	}
	// Cached under the ~1h fallback TTL: a second resolve does not re-mint.
	if _, _, err := r.Resolve(ctx, "v1", "GITHUB_TOKEN"); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("fallback TTL should cache; expected 1 hit, got %d", hits)
	}
}

func TestFetchIdentity(t *testing.T) {
	oldURL := UserURL
	defer func() { UserURL = oldURL }()

	// Success.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer ghu_x" {
			t.Errorf("missing bearer auth, got %q", got)
		}
		_, _ = io.WriteString(w, `{"login":"alice"}`)
	}))
	defer ok.Close()
	UserURL = ok.URL
	if login, err := FetchIdentity(context.Background(), "ghu_x"); err != nil || login != "alice" {
		t.Fatalf("FetchIdentity success: login=%q err=%v", login, err)
	}

	// Non-2xx.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
	}))
	defer bad.Close()
	UserURL = bad.URL
	if _, err := FetchIdentity(context.Background(), "ghu_x"); err == nil || !contains(err.Error(), "401") {
		t.Fatalf("expected error mentioning 401, got %v", err)
	}

	// Transport error (unreachable URL).
	UserURL = "http://127.0.0.1:0/user"
	if _, err := FetchIdentity(context.Background(), "ghu_x"); err == nil {
		t.Fatalf("expected transport error")
	}

	// Malformed URL → request construction fails.
	UserURL = "http://%zz"
	if _, err := FetchIdentity(context.Background(), "ghu_x"); err == nil {
		t.Fatalf("expected request-build error")
	}

	// 200 with invalid JSON body → decode error.
	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not json")
	}))
	defer badJSON.Close()
	UserURL = badJSON.URL
	if _, err := FetchIdentity(context.Background(), "ghu_x"); err == nil {
		t.Fatalf("expected JSON decode error")
	}
}

func TestResolveUnderFlightRecheck(t *testing.T) {
	rct, rnonce := enc(t, "ghr_x")
	r := NewResolver(&fakeStore{cred: &store.GitHubAppCredential{
		VaultID: "v1", CredentialKey: "GITHUB_TOKEN", ClientID: "cid",
		RefreshTokenCT: rct, RefreshTokenNonce: rnonce,
	}}, testKey, testLogger())
	// Simulate a concurrent flight completing between the outer cache miss and
	// the single-flighted mint: populate a fresh cache entry, so the under-flight
	// re-check returns it without minting.
	r.afterOuterMiss = func() {
		r.mu.Lock()
		r.cache["v1|GITHUB_TOKEN"] = cachedToken{token: "ghu_cached", expireAt: time.Now().Add(time.Hour)}
		r.mu.Unlock()
	}
	tok, ok, err := r.Resolve(context.Background(), "v1", "GITHUB_TOKEN")
	if err != nil || !ok || tok != "ghu_cached" {
		t.Fatalf("expected cached token from under-flight re-check, got tok=%q ok=%v err=%v", tok, ok, err)
	}
}

func TestMintErrorMessage(t *testing.T) {
	if msg := mintErrorMessage(&oauth.TokenError{StatusCode: 400, Permanent: true}); !contains(msg, "re-run") {
		t.Fatalf("permanent error should suggest re-connect, got %q", msg)
	}
	if msg := mintErrorMessage(&oauth.TokenError{StatusCode: 429, Permanent: false}); !contains(msg, "429") {
		t.Fatalf("transient error should pass through, got %q", msg)
	}
	if msg := mintErrorMessage(errors.New("network blip")); msg != "network blip" {
		t.Fatalf("generic error should pass through, got %q", msg)
	}
}

func contains(s, sub string) bool { return containsAll(s, sub) }

// fakeStore is a configurable github.Store for error-path tests.
type fakeStore struct {
	cred    *store.GitHubAppCredential
	getErr  error
	listErr error
	updErr  error
	mintErr string // last recorded mint error
}

func (f *fakeStore) GetGitHubAppCredential(_ context.Context, _, _ string) (*store.GitHubAppCredential, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.cred, nil
}
func (f *fakeStore) ListGitHubAppCredentials(_ context.Context, _ string) ([]store.GitHubAppCredential, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.cred != nil {
		return []store.GitHubAppCredential{*f.cred}, nil
	}
	return nil, nil
}
func (f *fakeStore) UpdateGitHubRefreshToken(_ context.Context, _, _ string, _, _ []byte, _ *time.Time, _ string) error {
	return f.updErr
}
func (f *fakeStore) UpdateGitHubMintError(_ context.Context, _, _, msg string) error {
	f.mintErr = msg
	return nil
}

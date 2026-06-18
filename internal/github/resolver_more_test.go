package github

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

// fakeStore is a configurable github.Store for error-path tests.
type fakeStore struct {
	cred    *store.GitHubAppInstallation
	getErr  error
	listErr error
	metaErr error
}

func (f *fakeStore) GetGitHubAppInstallation(_ context.Context, _, _ string) (*store.GitHubAppInstallation, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.cred, nil
}
func (f *fakeStore) ListGitHubAppInstallations(_ context.Context, _ string) ([]store.GitHubAppInstallation, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.cred != nil {
		return []store.GitHubAppInstallation{*f.cred}, nil
	}
	return nil, nil
}
func (f *fakeStore) UpdateGitHubInstallationMeta(_ context.Context, _, _, _ string) error {
	return f.metaErr
}
func (f *fakeStore) UpdateGitHubInstallationMintError(_ context.Context, _, _, _ string) error {
	return nil
}

// connectedCred returns a fake-store credential with a real, decryptable PEM.
func connectedCred(t *testing.T) *store.GitHubAppInstallation {
	t.Helper()
	pemKey, _ := testRSAKeyPEM(t, false)
	ct, nonce, err := crypto.Encrypt(pemKey, testEncKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return &store.GitHubAppInstallation{
		VaultID: "v1", CredentialKey: "GITHUB", AppID: "1", InstallationID: "2",
		PrivateKeyCT: ct, PrivateKeyNonce: nonce,
	}
}

func TestInstallationTokenBody(t *testing.T) {
	// none -> nil reader (full installation permissions).
	if body, err := installationTokenBody(&store.GitHubAppInstallation{}); err != nil || body != nil {
		t.Fatalf("empty: body=%v err=%v", body, err)
	}
	// permissions + repositories -> JSON with both.
	body, err := installationTokenBody(&store.GitHubAppInstallation{
		Permissions: `{"contents":"write"}`, Repositories: "repo-a, repo-b ,",
	})
	if err != nil || body == nil {
		t.Fatalf("scoped: err=%v", err)
	}
	raw, _ := io.ReadAll(body)
	var got struct {
		Permissions  map[string]string `json:"permissions"`
		Repositories []string          `json:"repositories"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("body not json: %v (%s)", err, raw)
	}
	if got.Permissions["contents"] != "write" {
		t.Fatalf("permissions missing: %s", raw)
	}
	if len(got.Repositories) != 2 || got.Repositories[0] != "repo-a" || got.Repositories[1] != "repo-b" {
		t.Fatalf("repositories not parsed/trimmed: %+v", got.Repositories)
	}
}

func TestResolveSendsScopingBody(t *testing.T) {
	var gotBody atomic.Value
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/access_tokens") {
			b, _ := io.ReadAll(r.Body)
			gotBody.Store(string(b))
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"token":"ghs_x","expires_at":"2099-01-01T00:00:00Z"}`)
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()
	withAPIBase(t, ts.URL)

	st := newStore(t)
	ctx := context.Background()
	v, _ := st.CreateVault(ctx, "test")
	pemKey, _ := testRSAKeyPEM(t, false)
	ct, nonce, _ := crypto.Encrypt(pemKey, testEncKey)
	_ = st.SetGitHubAppInstallation(ctx, &store.GitHubAppInstallation{
		VaultID: v.ID, CredentialKey: "GITHUB", AppID: "1", InstallationID: "2",
		PrivateKeyCT: ct, PrivateKeyNonce: nonce,
		Permissions: `{"contents":"write"}`, Repositories: "repo-a",
	})
	r := NewResolver(st, testEncKey, testLogger())
	if _, _, err := r.Resolve(ctx, v.ID, "GITHUB"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	body, _ := gotBody.Load().(string)
	if !strings.Contains(body, `"contents":"write"`) || !strings.Contains(body, "repo-a") {
		t.Fatalf("scoping body not sent: %q", body)
	}
}

func TestEvictVault(t *testing.T) {
	var mints int32
	ts := ghAPIServer(t, &mints, 201)
	defer ts.Close()
	withAPIBase(t, ts.URL)

	st := newStore(t)
	vaultID := seedInstall(t, st, "GITHUB", true)
	r := NewResolver(st, testEncKey, testLogger())
	ctx := context.Background()

	if _, _, err := r.Resolve(ctx, vaultID, "GITHUB"); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	r.EvictVault("other-vault") // non-matching branch
	r.EvictVault(vaultID)       // drops cached token
	if _, _, err := r.Resolve(ctx, vaultID, "GITHUB"); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if got := atomic.LoadInt32(&mints); got != 2 {
		t.Fatalf("expected 2 mints after eviction, got %d", got)
	}
}

func TestResolveGetErrorAndNilCred(t *testing.T) {
	ctx := context.Background()
	r1 := NewResolver(&fakeStore{getErr: errors.New("db down")}, testEncKey, testLogger())
	if _, ok, err := r1.Resolve(ctx, "v1", "GITHUB"); ok || err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("expected propagated 'db down', got ok=%v err=%v", ok, err)
	}
	r2 := NewResolver(&fakeStore{}, testEncKey, testLogger())
	if _, ok, err := r2.Resolve(ctx, "v1", "GITHUB"); ok || err != nil {
		t.Fatalf("expected (false,nil) on nil cred, got ok=%v err=%v", ok, err)
	}
}

func TestEnumerateError(t *testing.T) {
	r := NewResolver(&fakeStore{listErr: errors.New("db down")}, testEncKey, testLogger())
	if _, err := r.Enumerate(context.Background(), "v1"); err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("expected 'db down' from Enumerate, got %v", err)
	}
}

func TestEnumerateIdentity(t *testing.T) {
	st := newStore(t)
	vaultID := seedInstall(t, st, "GITHUB", true)
	_ = st.UpdateGitHubInstallationMeta(context.Background(), vaultID, "GITHUB", "spalk-agent")
	r := NewResolver(st, testEncKey, testLogger())
	creds, _ := r.Enumerate(context.Background(), vaultID)
	if len(creds) != 1 || creds[0].Identity != "spalk-agent[bot]" {
		t.Fatalf("expected slug[bot] identity, got %+v", creds)
	}
}

func TestValidateMintError(t *testing.T) {
	var mints int32
	ts := ghAPIServer(t, &mints, 403)
	defer ts.Close()
	withAPIBase(t, ts.URL)
	st := newStore(t)
	vaultID := seedInstall(t, st, "GITHUB", true)
	r := NewResolver(st, testEncKey, testLogger())
	if _, err := r.Validate(context.Background(), vaultID, "GITHUB"); err == nil || !strings.Contains(err.Error(), "mint") {
		t.Fatalf("expected mint error from Validate, got %v", err)
	}
}

func TestValidateSlugBestEffort(t *testing.T) {
	// Mint succeeds but GET /app fails -> Validate still succeeds with empty slug.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/access_tokens") {
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"token":"ghs_x","expires_at":"2099-01-01T00:00:00Z"}`)
			return
		}
		w.WriteHeader(500) // /app fails
	}))
	defer ts.Close()
	withAPIBase(t, ts.URL)
	st := newStore(t)
	vaultID := seedInstall(t, st, "GITHUB", true)
	r := NewResolver(st, testEncKey, testLogger())
	slug, err := r.Validate(context.Background(), vaultID, "GITHUB")
	if err != nil || slug != "" {
		t.Fatalf("expected success with empty slug, got slug=%q err=%v", slug, err)
	}
}

func TestValidateNotConnectedAndBadKey(t *testing.T) {
	st := newStore(t)
	vaultID := seedInstall(t, st, "GITHUB", false) // no PEM
	r := NewResolver(st, testEncKey, testLogger())
	if _, err := r.Validate(context.Background(), vaultID, "GITHUB"); err == nil || !strings.Contains(err.Error(), "no private key") {
		t.Fatalf("expected 'no private key', got %v", err)
	}
	// get error path
	r2 := NewResolver(&fakeStore{getErr: errors.New("db down")}, testEncKey, testLogger())
	if _, err := r2.Validate(context.Background(), "v", "GITHUB"); err == nil {
		t.Fatalf("expected get error from Validate")
	}
}

func TestParseRSAKeyErrors(t *testing.T) {
	// PKCS8 but Ed25519 (not RSA).
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(edPriv)
	edPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := ValidatePrivateKey(edPEM); err == nil || !strings.Contains(err.Error(), "not RSA") {
		t.Fatalf("expected 'not RSA', got %v", err)
	}
	// Valid PEM envelope, garbage DER -> both PKCS1 and PKCS8 parse fail.
	garbage := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")})
	if err := ValidatePrivateKey(garbage); err == nil || !strings.Contains(err.Error(), "parse private key") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestRequestInstallationTokenExpiryFallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"token":"ghs_x"}`) // no expires_at
	}))
	defer ts.Close()
	withAPIBase(t, ts.URL)
	r := NewResolver(newStore(t), testEncKey, testLogger())
	r.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
	tok, err := r.requestInstallationToken(context.Background(), "jwt", &store.GitHubAppInstallation{InstallationID: "1"})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if !tok.ExpiresAt.After(time.Unix(1_700_000_000, 0)) {
		t.Fatalf("expected fallback expiry in the future, got %v", tok.ExpiresAt)
	}
}

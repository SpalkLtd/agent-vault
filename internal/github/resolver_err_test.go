package github

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

// badPEMCred returns a connected cred whose stored "PEM" is undecryptable
// (valid 12-byte nonce, wrong content → GCM auth failure, not a panic).
func undecryptableCred() *store.GitHubAppInstallation {
	return &store.GitHubAppInstallation{
		VaultID: "v1", CredentialKey: "GITHUB", AppID: "1", InstallationID: "2",
		PrivateKeyCT: []byte("0123456789abcdef"), PrivateKeyNonce: make([]byte, 12),
	}
}

func TestMintDecryptError(t *testing.T) {
	r := NewResolver(&fakeStore{cred: undecryptableCred()}, testEncKey, testLogger())
	if _, ok, err := r.Resolve(context.Background(), "v1", "GITHUB"); ok || err == nil || !strings.Contains(err.Error(), "decrypt private key") {
		t.Fatalf("expected 'decrypt private key', got ok=%v err=%v", ok, err)
	}
}

func TestValidateDecryptError(t *testing.T) {
	r := NewResolver(&fakeStore{cred: undecryptableCred()}, testEncKey, testLogger())
	if _, err := r.Validate(context.Background(), "v1", "GITHUB"); err == nil || !strings.Contains(err.Error(), "decrypt private key") {
		t.Fatalf("expected 'decrypt private key' from Validate, got %v", err)
	}
}

func TestRequestTokenTransportError(t *testing.T) {
	withAPIBase(t, "http://127.0.0.1:0") // unreachable
	r := NewResolver(&fakeStore{cred: connectedCred(t)}, testEncKey, testLogger())
	if _, ok, err := r.Resolve(context.Background(), "v1", "GITHUB"); ok || err == nil || !strings.Contains(err.Error(), "mint failed") {
		t.Fatalf("expected transport mint failure, got ok=%v err=%v", ok, err)
	}
}

func TestRequestTokenBadURL(t *testing.T) {
	withAPIBase(t, "http://%zz") // unparseable → http.NewRequest fails
	r := NewResolver(&fakeStore{cred: connectedCred(t)}, testEncKey, testLogger())
	if _, ok, err := r.Resolve(context.Background(), "v1", "GITHUB"); ok || err == nil {
		t.Fatalf("expected request-build failure, got ok=%v err=%v", ok, err)
	}
}

func TestRequestTokenMalformedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = io.WriteString(w, "not json")
	}))
	defer ts.Close()
	withAPIBase(t, ts.URL)
	r := NewResolver(&fakeStore{cred: connectedCred(t)}, testEncKey, testLogger())
	if _, ok, err := r.Resolve(context.Background(), "v1", "GITHUB"); ok || err == nil || !strings.Contains(err.Error(), "mint failed") {
		t.Fatalf("expected parse failure surfaced as mint failed, got ok=%v err=%v", ok, err)
	}
}

func TestMintMetaWriteFailureStillServes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"token":"ghs_x","expires_at":"2099-01-01T00:00:00Z"}`)
	}))
	defer ts.Close()
	withAPIBase(t, ts.URL)
	// Meta write fails, but the token still serves (meta is best-effort).
	r := NewResolver(&fakeStore{cred: connectedCred(t), metaErr: io.ErrClosedPipe}, testEncKey, testLogger())
	tok, ok, err := r.Resolve(context.Background(), "v1", "GITHUB")
	if !ok || err != nil || tok != "ghs_x" {
		t.Fatalf("token should serve despite meta-write failure, got tok=%q ok=%v err=%v", tok, ok, err)
	}
}

func TestValidateSignError(t *testing.T) {
	// Stored key decrypts fine but is not a valid PEM → signJWT fails.
	pk := connectedCred(t)
	badCT, badNonce, _ := crypto.Encrypt([]byte("not a pem"), testEncKey)
	pk.PrivateKeyCT, pk.PrivateKeyNonce = badCT, badNonce
	r := NewResolver(&fakeStore{cred: pk}, testEncKey, testLogger())
	if _, err := r.Validate(context.Background(), "v1", "GITHUB"); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("expected signJWT 'private key' error, got %v", err)
	}
}

func TestValidateMetaWriteError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/access_tokens") {
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"token":"ghs_x","expires_at":"2099-01-01T00:00:00Z"}`)
			return
		}
		_, _ = io.WriteString(w, `{"slug":"spalk-agent"}`)
	}))
	defer ts.Close()
	withAPIBase(t, ts.URL)
	r := NewResolver(&fakeStore{cred: connectedCred(t), metaErr: io.ErrClosedPipe}, testEncKey, testLogger())
	if _, err := r.Validate(context.Background(), "v1", "GITHUB"); err == nil {
		t.Fatalf("expected Validate to surface the meta-write error")
	}
}

func TestResolveUnderFlightRecheck(t *testing.T) {
	r := NewResolver(&fakeStore{cred: connectedCred(t)}, testEncKey, testLogger())
	// Simulate a concurrent flight completing between the outer cache miss and
	// the single-flighted mint: populate a fresh entry so the under-flight
	// re-check returns it without minting.
	r.afterOuterMiss = func() {
		r.mu.Lock()
		r.cache["v1|GITHUB"] = cachedToken{token: "ghs_cached", expireAt: r.clock().Add(time.Hour)}
		r.mu.Unlock()
	}
	tok, ok, err := r.Resolve(context.Background(), "v1", "GITHUB")
	if err != nil || !ok || tok != "ghs_cached" {
		t.Fatalf("expected cached token from under-flight re-check, got tok=%q ok=%v err=%v", tok, ok, err)
	}
}

func TestFetchAppSlugDecodeError(t *testing.T) {
	// Mint OK, GET /app returns 200 + malformed JSON → Validate still succeeds
	// (slug best-effort) with empty slug.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/access_tokens") {
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"token":"ghs_x","expires_at":"2099-01-01T00:00:00Z"}`)
			return
		}
		_, _ = io.WriteString(w, "not json") // /app
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

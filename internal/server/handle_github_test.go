package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/github"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

func ghTestServer(t *testing.T, opts ...testServerOption) (*Server, *store.SQLiteStore, string) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	opts = append([]testServerOption{withStore(st)}, opts...)
	srv := newTestServer(opts...)
	v, err := st.CreateVault(context.Background(), "myvault")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	return srv, st, v.ID
}

// scopedReq builds a request carrying a vault-scoped session in its context,
// bypassing the auth middleware for direct handler calls.
func scopedReq(method, target string, body []byte, vaultID, role string) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if vaultID != "" {
		sess := &store.Session{ID: "s1", VaultID: vaultID, VaultRole: role}
		r = r.WithContext(context.WithValue(r.Context(), sessionContextKey, sess))
	}
	return r
}

func ghTokenServer(t *testing.T, withRefresh bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if withRefresh {
			_, _ = io.WriteString(w, `{"access_token":"ghu_new","refresh_token":"ghr_new","expires_in":28800,"refresh_token_expires_in":15724800}`)
		} else {
			_, _ = io.WriteString(w, `{"access_token":"gho_new","expires_in":28800}`)
		}
	}))
}

func ghIdentityServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"login":"alice"}`)
	}))
}

// --- connect ---------------------------------------------------------------

func TestHandleGitHubConnect(t *testing.T) {
	connectBody := func(vault, key, clientID, secret, scopes string) []byte {
		b, _ := json.Marshal(map[string]string{
			"vault": vault, "key": key, "client_id": clientID, "client_secret": secret, "scopes": scopes,
		})
		return b
	}

	t.Run("happy", func(t *testing.T) {
		srv, st, vaultID := ghTestServer(t)
		srv.githubDynamic = github.NewResolver(st, srv.encKey, slog.New(slog.DiscardHandler))
		rec := httptest.NewRecorder()
		srv.handleGitHubConnect(rec, scopedReq("POST", "/v1/credentials/github/connect",
			connectBody("myvault", "", "Iv1.abc", "shh", "repo,read:org"), vaultID, "member"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			AuthorizationURL string `json:"authorization_url"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !bytes.Contains([]byte(resp.AuthorizationURL), []byte("github.com/login/oauth/authorize")) {
			t.Fatalf("unexpected auth url: %s", resp.AuthorizationURL)
		}
		// Credential row + encrypted secret persisted under the default key.
		cred, err := st.GetGitHubAppCredential(context.Background(), vaultID, "GITHUB_TOKEN")
		if err != nil {
			t.Fatalf("get cred: %v", err)
		}
		got, _ := crypto.Decrypt(cred.ClientSecretCT, cred.ClientSecretNonce, srv.encKey)
		if string(got) != "shh" || cred.ClientID != "Iv1.abc" {
			t.Fatalf("cred not stored correctly: %+v", cred)
		}
	})

	t.Run("sentinel reuses secret; empty clears", func(t *testing.T) {
		srv, st, vaultID := ghTestServer(t)
		rec := httptest.NewRecorder()
		srv.handleGitHubConnect(rec, scopedReq("POST", "/x", connectBody("myvault", "GITHUB_TOKEN", "cid", "s1", ""), vaultID, "member"))
		if rec.Code != http.StatusOK {
			t.Fatalf("first connect: %d", rec.Code)
		}
		// Sentinel keeps the stored secret.
		rec = httptest.NewRecorder()
		srv.handleGitHubConnect(rec, scopedReq("POST", "/x", connectBody("myvault", "GITHUB_TOKEN", "cid", oauthSecretSentinel, ""), vaultID, "member"))
		if rec.Code != http.StatusOK {
			t.Fatalf("sentinel connect: %d", rec.Code)
		}
		cred, _ := st.GetGitHubAppCredential(context.Background(), vaultID, "GITHUB_TOKEN")
		got, _ := crypto.Decrypt(cred.ClientSecretCT, cred.ClientSecretNonce, srv.encKey)
		if string(got) != "s1" {
			t.Fatalf("sentinel should preserve secret, got %q", string(got))
		}
		// Empty secret clears it.
		rec = httptest.NewRecorder()
		srv.handleGitHubConnect(rec, scopedReq("POST", "/x", connectBody("myvault", "GITHUB_TOKEN", "cid", "", ""), vaultID, "member"))
		cred, _ = st.GetGitHubAppCredential(context.Background(), vaultID, "GITHUB_TOKEN")
		if len(cred.ClientSecretCT) != 0 {
			t.Fatalf("empty secret should clear stored secret")
		}
	})

	t.Run("validation and auth errors", func(t *testing.T) {
		srv, _, vaultID := ghTestServer(t)
		cases := []struct {
			name    string
			body    []byte
			sess    string // vaultID for session, "" = no session
			want    int
			wantMsg string
		}{
			{"bad json", []byte("{"), vaultID, http.StatusBadRequest, "Invalid request body"},
			{"bad key", connectBody("myvault", "bad key", "cid", "s", ""), vaultID, http.StatusBadRequest, "Invalid credential key"},
			{"no client id", connectBody("myvault", "GITHUB_TOKEN", "", "s", ""), vaultID, http.StatusBadRequest, "client_id"},
			{"vault not found", connectBody("nope", "GITHUB_TOKEN", "cid", "s", ""), vaultID, http.StatusNotFound, "not found"},
			{"no session", connectBody("myvault", "GITHUB_TOKEN", "cid", "s", ""), "", http.StatusForbidden, "Authentication required"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				rec := httptest.NewRecorder()
				srv.handleGitHubConnect(rec, scopedReq("POST", "/x", c.body, c.sess, "member"))
				assertJSONError(t, rec, c.want, c.wantMsg)
			})
		}
	})

	t.Run("external store rejected", func(t *testing.T) {
		srv, st, vaultID := ghTestServer(t)
		if _, err := st.SetVaultExternalStore(context.Background(), store.SetVaultExternalStoreParams{
			VaultID: vaultID, Kind: "infisical",
			ConfigJSON: `{"project_id":"p","environment":"e","secret_path":"/"}`, PollIntervalSeconds: 60,
		}); err != nil {
			t.Fatalf("set external store: %v", err)
		}
		rec := httptest.NewRecorder()
		srv.handleGitHubConnect(rec, scopedReq("POST", "/x", connectBody("myvault", "GITHUB_TOKEN", "cid", "s", ""), vaultID, "member"))
		assertJSONError(t, rec, http.StatusConflict, "external credential store")
	})

	t.Run("encryption failure", func(t *testing.T) {
		srv, _, vaultID := ghTestServer(t, withEncKey(make([]byte, 5))) // invalid AES key size
		rec := httptest.NewRecorder()
		srv.handleGitHubConnect(rec, scopedReq("POST", "/x", connectBody("myvault", "GITHUB_TOKEN", "cid", "s", ""), vaultID, "member"))
		assertJSONError(t, rec, http.StatusInternalServerError, "Encryption failed")
	})
}

// --- callback --------------------------------------------------------------

// seedState creates a github credential + an OAuth state row, returning the raw
// state token to present on the callback.
func seedState(t *testing.T, srv *Server, st *store.SQLiteStore, vaultID, key string, clientSecretCT, clientSecretNonce []byte, expired bool) string {
	t.Helper()
	ctx := context.Background()
	if err := st.SetGitHubAppCredential(ctx, &store.GitHubAppCredential{
		VaultID: vaultID, CredentialKey: key, ClientID: "cid",
		ClientSecretCT: clientSecretCT, ClientSecretNonce: clientSecretNonce,
	}); err != nil {
		t.Fatalf("seed cred: %v", err)
	}
	raw := oauthPrefixedToken("av_ghst_")
	exp := time.Now().Add(time.Hour)
	if expired {
		exp = time.Now().Add(-time.Hour)
	}
	if err := st.CreateCredentialOAuthState(ctx, &store.CredentialOAuthState{
		ID: oauthPublicID(), StateHash: hashOAuthState(raw), CodeVerifier: "",
		VaultID: vaultID, CredentialKey: key, CreatedAt: time.Now(), ExpiresAt: exp,
	}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	return raw
}

func locationStatus(rec *httptest.ResponseRecorder) string {
	loc := rec.Header().Get("Location")
	if bytes.Contains([]byte(loc), []byte("status=success")) {
		return "success"
	}
	if bytes.Contains([]byte(loc), []byte("status=error")) {
		return "error"
	}
	return loc
}

// locationMessage returns the decoded `message` query param of the redirect, so
// tests can assert the specific failure mode (not merely that some error fired).
func locationMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	return u.Query().Get("message")
}

// assertErrorRedirect asserts an error redirect whose message contains want.
func assertErrorRedirect(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	if locationStatus(rec) != "error" {
		t.Fatalf("expected error redirect, got loc=%s", rec.Header().Get("Location"))
	}
	if msg := locationMessage(t, rec); !strings.Contains(msg, want) {
		t.Fatalf("expected error message containing %q, got %q", want, msg)
	}
}

// assertJSONError asserts a jsonError response with the given status and a body
// whose "error" message contains want — pinning the specific failure mode.
func assertJSONError(t *testing.T, rec *httptest.ResponseRecorder, status int, want string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("expected status %d, got %d (%s)", status, rec.Code, rec.Body.String())
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error body: %v", err)
	}
	if !strings.Contains(body.Error, want) {
		t.Fatalf("expected error message containing %q, got %q", want, body.Error)
	}
}

func TestHandleGitHubCallback(t *testing.T) {
	t.Run("happy path persists refresh token + identity", func(t *testing.T) {
		srv, st, vaultID := ghTestServer(t)
		srv.githubDynamic = github.NewResolver(st, srv.encKey, slog.New(slog.DiscardHandler))
		tok := ghTokenServer(t, true)
		defer tok.Close()
		id := ghIdentityServer(t)
		defer id.Close()
		swapURLs(t, tok.URL, id.URL)

		// Seed with a real client secret so the decrypt-success path is exercised.
		csCT, csNonce, _ := crypto.Encrypt([]byte("shh"), srv.encKey)
		raw := seedState(t, srv, st, vaultID, "GITHUB_TOKEN", csCT, csNonce, false)

		rec := httptest.NewRecorder()
		srv.handleGitHubCallback(rec, scopedReq("GET", "/cb?code=abc&state="+raw, nil, "", ""))
		if rec.Code != http.StatusFound || locationStatus(rec) != "success" {
			t.Fatalf("expected success redirect, got %d loc=%s", rec.Code, rec.Header().Get("Location"))
		}
		cred, _ := st.GetGitHubAppCredential(context.Background(), vaultID, "GITHUB_TOKEN")
		if !cred.Connected() || cred.Identity != "alice" {
			t.Fatalf("expected connected+identity, got %+v", cred)
		}
		got, _ := crypto.Decrypt(cred.RefreshTokenCT, cred.RefreshTokenNonce, srv.encKey)
		if string(got) != "ghr_new" {
			t.Fatalf("expected stored refresh ghr_new, got %q", string(got))
		}
	})

	t.Run("identity capture failure still succeeds", func(t *testing.T) {
		srv, st, vaultID := ghTestServer(t)
		tok := ghTokenServer(t, true)
		defer tok.Close()
		swapURLs(t, tok.URL, "http://127.0.0.1:0/user") // unreachable identity endpoint
		raw := seedState(t, srv, st, vaultID, "GITHUB_TOKEN", nil, nil, false)
		rec := httptest.NewRecorder()
		srv.handleGitHubCallback(rec, scopedReq("GET", "/cb?code=abc&state="+raw, nil, "", ""))
		if locationStatus(rec) != "success" {
			t.Fatalf("expected success despite identity failure, loc=%s", rec.Header().Get("Location"))
		}
	})

	t.Run("no refresh token rejected", func(t *testing.T) {
		srv, st, vaultID := ghTestServer(t)
		tok := ghTokenServer(t, false) // OAuth-App-style: no refresh token
		defer tok.Close()
		swapURLs(t, tok.URL, "")
		raw := seedState(t, srv, st, vaultID, "GITHUB_TOKEN", nil, nil, false)
		rec := httptest.NewRecorder()
		srv.handleGitHubCallback(rec, scopedReq("GET", "/cb?code=abc&state="+raw, nil, "", ""))
		assertErrorRedirect(t, rec, "Expiring user authorization tokens")
	})

	t.Run("error redirects", func(t *testing.T) {
		srv, st, vaultID := ghTestServer(t)

		// Missing code/state with an explicit error_description → surfaces it.
		rec := httptest.NewRecorder()
		srv.handleGitHubCallback(rec, scopedReq("GET", "/cb?error_description=denied", nil, "", ""))
		assertErrorRedirect(t, rec, "denied")

		// Missing code/state with no error params → default message branch.
		rec = httptest.NewRecorder()
		srv.handleGitHubCallback(rec, scopedReq("GET", "/cb", nil, "", ""))
		assertErrorRedirect(t, rec, "Missing code or state parameter")

		// Invalid state.
		rec = httptest.NewRecorder()
		srv.handleGitHubCallback(rec, scopedReq("GET", "/cb?code=c&state=bogus", nil, "", ""))
		assertErrorRedirect(t, rec, "Invalid or expired OAuth state")

		// Expired state.
		raw := seedState(t, srv, st, vaultID, "GH_EXPIRED", nil, nil, true)
		rec = httptest.NewRecorder()
		srv.handleGitHubCallback(rec, scopedReq("GET", "/cb?code=c&state="+raw, nil, "", ""))
		assertErrorRedirect(t, rec, "OAuth state expired")
	})

	t.Run("client secret decrypt failure", func(t *testing.T) {
		srv, st, vaultID := ghTestServer(t)
		// Valid nonce length, wrong content → GCM auth failure (not a panic).
		raw := seedState(t, srv, st, vaultID, "GITHUB_TOKEN", []byte("0123456789abcdef"), make([]byte, 12), false)
		rec := httptest.NewRecorder()
		srv.handleGitHubCallback(rec, scopedReq("GET", "/cb?code=c&state="+raw, nil, "", ""))
		assertErrorRedirect(t, rec, "Failed to decrypt client secret")
	})

	t.Run("token exchange failure", func(t *testing.T) {
		srv, st, vaultID := ghTestServer(t)
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(400) }))
		defer bad.Close()
		swapURLs(t, bad.URL, "")
		raw := seedState(t, srv, st, vaultID, "GITHUB_TOKEN", nil, nil, false)
		rec := httptest.NewRecorder()
		srv.handleGitHubCallback(rec, scopedReq("GET", "/cb?code=c&state="+raw, nil, "", ""))
		assertErrorRedirect(t, rec, "Token exchange failed")
	})

	t.Run("refresh token encrypt failure", func(t *testing.T) {
		// Bad enc key; no client secret so the only crypto op is encrypting refresh.
		srv, st, vaultID := ghTestServer(t, withEncKey(make([]byte, 5)))
		tok := ghTokenServer(t, true)
		defer tok.Close()
		swapURLs(t, tok.URL, "")
		raw := seedState(t, srv, st, vaultID, "GITHUB_TOKEN", nil, nil, false)
		rec := httptest.NewRecorder()
		srv.handleGitHubCallback(rec, scopedReq("GET", "/cb?code=c&state="+raw, nil, "", ""))
		assertErrorRedirect(t, rec, "Failed to encrypt refresh token")
	})

	t.Run("config not found", func(t *testing.T) {
		srv, st, vaultID := ghTestServer(t)
		// Create a state row whose credential has no github_app_credentials row.
		raw := oauthPrefixedToken("av_ghst_")
		_ = st.CreateCredentialOAuthState(context.Background(), &store.CredentialOAuthState{
			ID: oauthPublicID(), StateHash: hashOAuthState(raw), VaultID: vaultID,
			CredentialKey: "MISSING", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		})
		rec := httptest.NewRecorder()
		srv.handleGitHubCallback(rec, scopedReq("GET", "/cb?code=c&state="+raw, nil, "", ""))
		assertErrorRedirect(t, rec, "GitHub configuration not found")
	})
}

// --- status ----------------------------------------------------------------

func TestHandleGitHubStatus(t *testing.T) {
	srv, st, vaultID := ghTestServer(t)
	ctx := context.Background()

	// Credential not found (distinct from a missing vault).
	rec := httptest.NewRecorder()
	srv.handleGitHubStatus(rec, scopedReq("GET", "/s?vault=myvault&key=GITHUB_TOKEN", nil, vaultID, "member"))
	assertJSONError(t, rec, http.StatusNotFound, "GitHub credential")

	// Vault not found.
	rec = httptest.NewRecorder()
	srv.handleGitHubStatus(rec, scopedReq("GET", "/s?vault=nope", nil, vaultID, "member"))
	assertJSONError(t, rec, http.StatusNotFound, "Vault \"nope\" not found")

	// No session → 403.
	rec = httptest.NewRecorder()
	srv.handleGitHubStatus(rec, scopedReq("GET", "/s?vault=myvault", nil, "", ""))
	assertJSONError(t, rec, http.StatusForbidden, "Authentication required")

	// Connected credential.
	_ = st.SetGitHubAppCredential(ctx, &store.GitHubAppCredential{VaultID: vaultID, CredentialKey: "GITHUB_TOKEN", ClientID: "cid"})
	exp := time.Now().Add(180 * 24 * time.Hour)
	_ = st.UpdateGitHubRefreshToken(ctx, vaultID, "GITHUB_TOKEN", []byte("rct"), []byte("rn"), &exp, "alice")
	_ = st.UpdateGitHubMintError(ctx, vaultID, "GITHUB_TOKEN", "stale error")

	rec = httptest.NewRecorder()
	srv.handleGitHubStatus(rec, scopedReq("GET", "/s?vault=myvault&key=GITHUB_TOKEN", nil, vaultID, "member"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp struct {
		Connected             bool   `json:"connected"`
		Identity              string `json:"identity"`
		ConnectedAt           string `json:"connected_at"`
		RefreshTokenExpiresAt string `json:"refresh_token_expires_at"`
		LastError             string `json:"last_error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Connected || resp.Identity != "alice" || resp.ConnectedAt == "" || resp.RefreshTokenExpiresAt == "" || resp.LastError != "stale error" {
		t.Fatalf("unexpected status: %+v", resp)
	}
}

// --- enumerate -------------------------------------------------------------

func TestEnumerateGitHubCredentials(t *testing.T) {
	srv, st, vaultID := ghTestServer(t)
	ctx := context.Background()

	// Nil resolver → nil.
	if got := srv.enumerateGitHubCredentials(ctx, vaultID); got != nil {
		t.Fatalf("nil resolver should yield nil, got %v", got)
	}

	// Success.
	_ = st.SetGitHubAppCredential(ctx, &store.GitHubAppCredential{VaultID: vaultID, CredentialKey: "GITHUB_TOKEN", ClientID: "cid"})
	srv.githubDynamic = github.NewResolver(st, srv.encKey, slog.New(slog.DiscardHandler))
	got := srv.enumerateGitHubCredentials(ctx, vaultID)
	if len(got) != 1 || got[0].Key != "GITHUB_TOKEN" {
		t.Fatalf("expected 1 enumerated cred, got %+v", got)
	}

	// Store error → nil (logged, non-fatal).
	srv.githubDynamic = github.NewResolver(errEnumStore{}, srv.encKey, slog.New(slog.DiscardHandler))
	if got := srv.enumerateGitHubCredentials(ctx, vaultID); got != nil {
		t.Fatalf("store error should yield nil, got %v", got)
	}
}

// faultStore wraps a real Store and injects failures on specific methods, to
// exercise the handlers' store-error branches.
type faultStore struct {
	Store
	failSet    bool
	failState  bool
	failUpdate bool
	getErr     error
}

func (f *faultStore) SetGitHubAppCredential(ctx context.Context, g *store.GitHubAppCredential) error {
	if f.failSet {
		return errors.New("set failed")
	}
	return f.Store.SetGitHubAppCredential(ctx, g)
}
func (f *faultStore) CreateCredentialOAuthState(ctx context.Context, s *store.CredentialOAuthState) error {
	if f.failState {
		return errors.New("state failed")
	}
	return f.Store.CreateCredentialOAuthState(ctx, s)
}
func (f *faultStore) UpdateGitHubRefreshToken(ctx context.Context, vaultID, key string, ct, nonce []byte, exp *time.Time, identity string) error {
	if f.failUpdate {
		return errors.New("update failed")
	}
	return f.Store.UpdateGitHubRefreshToken(ctx, vaultID, key, ct, nonce, exp, identity)
}
func (f *faultStore) GetGitHubAppCredential(ctx context.Context, vaultID, key string) (*store.GitHubAppCredential, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.Store.GetGitHubAppCredential(ctx, vaultID, key)
}

func TestGitHubHandlerStoreFaults(t *testing.T) {
	connectBody, _ := json.Marshal(map[string]string{"vault": "myvault", "key": "GITHUB_TOKEN", "client_id": "cid", "client_secret": "s"})

	t.Run("connect set failure → 500", func(t *testing.T) {
		st, _ := store.Open(":memory:")
		t.Cleanup(func() { _ = st.Close() })
		v, _ := st.CreateVault(context.Background(), "myvault")
		srv := newTestServer(withStore(&faultStore{Store: st, failSet: true}))
		rec := httptest.NewRecorder()
		srv.handleGitHubConnect(rec, scopedReq("POST", "/x", connectBody, v.ID, "member"))
		assertJSONError(t, rec, http.StatusInternalServerError, "Failed to save GitHub configuration")
	})

	t.Run("connect state failure → 500", func(t *testing.T) {
		st, _ := store.Open(":memory:")
		t.Cleanup(func() { _ = st.Close() })
		v, _ := st.CreateVault(context.Background(), "myvault")
		srv := newTestServer(withStore(&faultStore{Store: st, failState: true}))
		rec := httptest.NewRecorder()
		srv.handleGitHubConnect(rec, scopedReq("POST", "/x", connectBody, v.ID, "member"))
		assertJSONError(t, rec, http.StatusInternalServerError, "Failed to create OAuth state")
	})

	t.Run("status get failure → 500", func(t *testing.T) {
		st, _ := store.Open(":memory:")
		t.Cleanup(func() { _ = st.Close() })
		v, _ := st.CreateVault(context.Background(), "myvault")
		srv := newTestServer(withStore(&faultStore{Store: st, getErr: errors.New("boom")}))
		rec := httptest.NewRecorder()
		srv.handleGitHubStatus(rec, scopedReq("GET", "/s?vault=myvault&key=GITHUB_TOKEN", nil, v.ID, "member"))
		assertJSONError(t, rec, http.StatusInternalServerError, "Failed to read GitHub credential")
	})

	t.Run("callback update failure → error redirect", func(t *testing.T) {
		st, _ := store.Open(":memory:")
		t.Cleanup(func() { _ = st.Close() })
		v, _ := st.CreateVault(context.Background(), "myvault")
		fs := &faultStore{Store: st, failUpdate: true}
		srv := newTestServer(withStore(fs))
		tok := ghTokenServer(t, true)
		defer tok.Close()
		swapURLs(t, tok.URL, "")
		raw := seedState(t, srv, st, v.ID, "GITHUB_TOKEN", nil, nil, false)
		rec := httptest.NewRecorder()
		srv.handleGitHubCallback(rec, scopedReq("GET", "/cb?code=c&state="+raw, nil, "", ""))
		assertErrorRedirect(t, rec, "Failed to store refresh token")
	})
}

func TestGitHubHandlersDefaultVault(t *testing.T) {
	st, _ := store.Open(":memory:")
	t.Cleanup(func() { _ = st.Close() })
	v, err := st.GetVault(context.Background(), store.DefaultVault) // seeded by Open
	if err != nil || v == nil {
		t.Fatalf("default vault: %v", err)
	}
	srv := newTestServer(withStore(st))

	// Connect with empty vault → defaults to "default".
	body, _ := json.Marshal(map[string]string{"key": "GITHUB_TOKEN", "client_id": "cid", "client_secret": "s"})
	rec := httptest.NewRecorder()
	srv.handleGitHubConnect(rec, scopedReq("POST", "/x", body, v.ID, "member"))
	if rec.Code != http.StatusOK {
		t.Fatalf("connect default vault: %d %s", rec.Code, rec.Body.String())
	}

	// Status with empty vault → defaults to "default".
	rec = httptest.NewRecorder()
	srv.handleGitHubStatus(rec, scopedReq("GET", "/s", nil, v.ID, "member"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status default vault: %d", rec.Code)
	}
}

// errEnumStore implements github.Store with a failing List for the error path.
type errEnumStore struct{}

func (errEnumStore) GetGitHubAppCredential(context.Context, string, string) (*store.GitHubAppCredential, error) {
	return nil, nil
}
func (errEnumStore) ListGitHubAppCredentials(context.Context, string) ([]store.GitHubAppCredential, error) {
	return nil, errors.New("boom")
}
func (errEnumStore) UpdateGitHubRefreshToken(context.Context, string, string, []byte, []byte, *time.Time, string) error {
	return nil
}
func (errEnumStore) UpdateGitHubMintError(context.Context, string, string, string) error { return nil }

// swapURLs points the github package's token and user endpoints at test servers
// for the duration of a test. An empty userURL is left unchanged.
func swapURLs(t *testing.T, tokenURL, userURL string) {
	t.Helper()
	oldTok := github.TokenURL
	github.TokenURL = tokenURL
	// The server wraps oauth.TokenClient with netguard (blocks loopback); use a
	// plain client so the httptest token endpoint is reachable.
	oldClient := oauth.TokenClient
	oauth.TokenClient = &http.Client{Timeout: 5 * time.Second}
	t.Cleanup(func() { github.TokenURL = oldTok; oauth.TokenClient = oldClient })
	if userURL != "" {
		oldUser := github.UserURL
		github.UserURL = userURL
		t.Cleanup(func() { github.UserURL = oldUser })
	}
}

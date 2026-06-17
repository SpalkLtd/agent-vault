package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/github"
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
	srv.githubDynamic = github.NewResolver(st, srv.encKey, slog.New(slog.DiscardHandler))
	v, err := st.CreateVault(context.Background(), "myvault")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	return srv, st, v.ID
}

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

func testPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

// ghAPIServer fakes the GitHub endpoints used at connect-time validation.
func ghAPIServer(t *testing.T, mintStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			if mintStatus != 0 && mintStatus != 201 {
				w.WriteHeader(mintStatus)
				return
			}
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"token":"ghs_x","expires_at":"2099-01-01T00:00:00Z"}`)
		case strings.HasSuffix(r.URL.Path, "/app"):
			_, _ = io.WriteString(w, `{"slug":"spalk-agent"}`)
		default:
			w.WriteHeader(404)
		}
	}))
}

func useGitHubAPI(t *testing.T, url string) {
	t.Helper()
	old := github.APIBase
	github.APIBase = url
	t.Cleanup(func() { github.APIBase = old })
}

func connectBody(vault, key, appID, instID, pemKey string) []byte {
	b, _ := json.Marshal(map[string]string{
		"vault": vault, "key": key, "app_id": appID, "installation_id": instID, "private_key": pemKey,
	})
	return b
}

func assertJSONError(t *testing.T, rec *httptest.ResponseRecorder, status int, want string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("expected status %d, got %d (%s)", status, rec.Code, rec.Body.String())
	}
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if !strings.Contains(body.Error, want) {
		t.Fatalf("expected error containing %q, got %q", want, body.Error)
	}
}

func TestHandleGitHubConnect(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		srv, st, vaultID := ghTestServer(t)
		ts := ghAPIServer(t, 201)
		defer ts.Close()
		useGitHubAPI(t, ts.URL)

		rec := httptest.NewRecorder()
		srv.handleGitHubConnect(rec, scopedReq("POST", "/x",
			connectBody("myvault", "", "123", "456", testPEM(t)), vaultID, "member"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Connected bool   `json:"connected"`
			Identity  string `json:"identity"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if !resp.Connected || resp.Identity != "spalk-agent[bot]" {
			t.Fatalf("unexpected resp: %+v", resp)
		}
		cred, err := st.GetGitHubAppInstallation(context.Background(), vaultID, "GITHUB")
		if err != nil || cred.AppID != "123" || cred.InstallationID != "456" || len(cred.PrivateKeyCT) == 0 || cred.AppSlug != "spalk-agent" {
			t.Fatalf("cred not stored: %+v err=%v", cred, err)
		}
	})

	t.Run("validation + auth errors", func(t *testing.T) {
		srv, _, vaultID := ghTestServer(t)
		pemKey := testPEM(t)
		cases := []struct {
			name    string
			body    []byte
			sess    string
			want    int
			wantMsg string
		}{
			{"bad json", []byte("{"), vaultID, http.StatusBadRequest, "Invalid request body"},
			{"bad key", connectBody("myvault", "bad key", "1", "2", pemKey), vaultID, http.StatusBadRequest, "Invalid credential key"},
			{"no app id", connectBody("myvault", "GITHUB", "", "2", pemKey), vaultID, http.StatusBadRequest, "app_id"},
			{"no installation id", connectBody("myvault", "GITHUB", "1", "", pemKey), vaultID, http.StatusBadRequest, "installation_id"},
			{"no private key", connectBody("myvault", "GITHUB", "1", "2", ""), vaultID, http.StatusBadRequest, "private_key"},
			{"bad pem", connectBody("myvault", "GITHUB", "1", "2", "not a pem"), vaultID, http.StatusBadRequest, "private key"},
			{"vault not found", connectBody("nope", "GITHUB", "1", "2", pemKey), vaultID, http.StatusNotFound, "not found"},
			{"no session", connectBody("myvault", "GITHUB", "1", "2", pemKey), "", http.StatusForbidden, "Authentication required"},
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
		srv.handleGitHubConnect(rec, scopedReq("POST", "/x", connectBody("myvault", "GITHUB", "1", "2", testPEM(t)), vaultID, "member"))
		assertJSONError(t, rec, http.StatusConflict, "external credential store")
	})

	t.Run("validation mint failure", func(t *testing.T) {
		srv, _, vaultID := ghTestServer(t)
		ts := ghAPIServer(t, 403) // installation token mint forbidden
		defer ts.Close()
		useGitHubAPI(t, ts.URL)
		rec := httptest.NewRecorder()
		srv.handleGitHubConnect(rec, scopedReq("POST", "/x", connectBody("myvault", "GITHUB", "1", "2", testPEM(t)), vaultID, "member"))
		assertJSONError(t, rec, http.StatusBadGateway, "mint")
	})
}

func TestHandleGitHubStatus(t *testing.T) {
	srv, st, vaultID := ghTestServer(t)
	ctx := context.Background()

	rec := httptest.NewRecorder()
	srv.handleGitHubStatus(rec, scopedReq("GET", "/s?vault=myvault&key=GITHUB", nil, vaultID, "member"))
	assertJSONError(t, rec, http.StatusNotFound, "GitHub credential")

	rec = httptest.NewRecorder()
	srv.handleGitHubStatus(rec, scopedReq("GET", "/s?vault=nope", nil, vaultID, "member"))
	assertJSONError(t, rec, http.StatusNotFound, "Vault \"nope\" not found")

	rec = httptest.NewRecorder()
	srv.handleGitHubStatus(rec, scopedReq("GET", "/s?vault=myvault", nil, "", ""))
	assertJSONError(t, rec, http.StatusForbidden, "Authentication required")

	_ = st.SetGitHubAppInstallation(ctx, &store.GitHubAppInstallation{
		VaultID: vaultID, CredentialKey: "GITHUB", AppID: "123", InstallationID: "456",
		PrivateKeyCT: []byte("ct"), PrivateKeyNonce: []byte("n"),
	})
	_ = st.UpdateGitHubInstallationMeta(ctx, vaultID, "GITHUB", "spalk-agent")

	rec = httptest.NewRecorder()
	srv.handleGitHubStatus(rec, scopedReq("GET", "/s?vault=myvault&key=GITHUB", nil, vaultID, "member"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp struct {
		Connected      bool   `json:"connected"`
		Identity       string `json:"identity"`
		AppID          string `json:"app_id"`
		InstallationID string `json:"installation_id"`
		ConnectedAt    string `json:"connected_at"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Connected || resp.Identity != "spalk-agent[bot]" || resp.AppID != "123" || resp.InstallationID != "456" || resp.ConnectedAt == "" {
		t.Fatalf("unexpected status: %+v", resp)
	}
}

// faultStore wraps a real Store and injects failures for handler error paths.
type faultStore struct {
	Store
	failSet bool
	getErr  error
}

func (f *faultStore) SetGitHubAppInstallation(ctx context.Context, g *store.GitHubAppInstallation) error {
	if f.failSet {
		return errors.New("set failed")
	}
	return f.Store.SetGitHubAppInstallation(ctx, g)
}
func (f *faultStore) GetGitHubAppInstallation(ctx context.Context, vaultID, key string) (*store.GitHubAppInstallation, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.Store.GetGitHubAppInstallation(ctx, vaultID, key)
}

func TestHandleGitHubConnect_MoreBranches(t *testing.T) {
	t.Run("default vault", func(t *testing.T) {
		st, _ := store.Open(":memory:")
		t.Cleanup(func() { _ = st.Close() })
		v, err := st.GetVault(context.Background(), store.DefaultVault) // seeded by Open
		if err != nil || v == nil {
			t.Fatalf("default vault: %v", err)
		}
		srv := newTestServer(withStore(st))
		srv.githubDynamic = github.NewResolver(st, srv.encKey, slog.New(slog.DiscardHandler))
		ts := ghAPIServer(t, 201)
		defer ts.Close()
		useGitHubAPI(t, ts.URL)

		body, _ := json.Marshal(map[string]string{"app_id": "1", "installation_id": "2", "private_key": testPEM(t)})
		rec := httptest.NewRecorder()
		srv.handleGitHubConnect(rec, scopedReq("POST", "/x", body, v.ID, "member"))
		if rec.Code != http.StatusOK {
			t.Fatalf("default-vault connect: %d %s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		srv.handleGitHubStatus(rec, scopedReq("GET", "/s", nil, v.ID, "member")) // no vault/key → defaults
		if rec.Code != http.StatusOK {
			t.Fatalf("default-vault status: %d", rec.Code)
		}
	})

	t.Run("encryption failure", func(t *testing.T) {
		srv, _, vaultID := ghTestServer(t, withEncKey(make([]byte, 5)))
		rec := httptest.NewRecorder()
		srv.handleGitHubConnect(rec, scopedReq("POST", "/x", connectBody("myvault", "GITHUB", "1", "2", testPEM(t)), vaultID, "member"))
		assertJSONError(t, rec, http.StatusInternalServerError, "Encryption failed")
	})

	t.Run("set failure", func(t *testing.T) {
		st, _ := store.Open(":memory:")
		t.Cleanup(func() { _ = st.Close() })
		v, _ := st.CreateVault(context.Background(), "myvault")
		fs := &faultStore{Store: st, failSet: true}
		srv := newTestServer(withStore(fs))
		srv.githubDynamic = github.NewResolver(fs, srv.encKey, slog.New(slog.DiscardHandler))
		rec := httptest.NewRecorder()
		srv.handleGitHubConnect(rec, scopedReq("POST", "/x", connectBody("myvault", "GITHUB", "1", "2", testPEM(t)), v.ID, "member"))
		assertJSONError(t, rec, http.StatusInternalServerError, "Failed to save GitHub configuration")
	})

	t.Run("resolver unavailable", func(t *testing.T) {
		srv, _, vaultID := ghTestServer(t)
		srv.githubDynamic = nil
		rec := httptest.NewRecorder()
		srv.handleGitHubConnect(rec, scopedReq("POST", "/x", connectBody("myvault", "GITHUB", "1", "2", testPEM(t)), vaultID, "member"))
		assertJSONError(t, rec, http.StatusServiceUnavailable, "resolver not available")
	})
}

func TestHandleGitHubStatus_MoreBranches(t *testing.T) {
	t.Run("store read error", func(t *testing.T) {
		st, _ := store.Open(":memory:")
		t.Cleanup(func() { _ = st.Close() })
		v, _ := st.CreateVault(context.Background(), "myvault")
		srv := newTestServer(withStore(&faultStore{Store: st, getErr: errors.New("boom")}))
		rec := httptest.NewRecorder()
		srv.handleGitHubStatus(rec, scopedReq("GET", "/s?vault=myvault&key=GITHUB", nil, v.ID, "member"))
		assertJSONError(t, rec, http.StatusInternalServerError, "Failed to read GitHub credential")
	})

	t.Run("connected without slug → empty identity", func(t *testing.T) {
		srv, st, vaultID := ghTestServer(t)
		_ = st.SetGitHubAppInstallation(context.Background(), &store.GitHubAppInstallation{
			VaultID: vaultID, CredentialKey: "GITHUB", AppID: "1", InstallationID: "2",
			PrivateKeyCT: []byte("ct"), PrivateKeyNonce: []byte("n"),
		})
		rec := httptest.NewRecorder()
		srv.handleGitHubStatus(rec, scopedReq("GET", "/s?vault=myvault&key=GITHUB", nil, vaultID, "member"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d", rec.Code)
		}
		var resp struct {
			Connected bool   `json:"connected"`
			Identity  string `json:"identity"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if !resp.Connected || resp.Identity != "" {
			t.Fatalf("expected connected with empty identity, got %+v", resp)
		}
	})
}

func TestEnumerateGitHubCredentialsError(t *testing.T) {
	st, _ := store.Open(":memory:")
	t.Cleanup(func() { _ = st.Close() })
	v, _ := st.CreateVault(context.Background(), "myvault")
	srv := newTestServer(withStore(st))
	srv.githubDynamic = github.NewResolver(errEnumStore{}, srv.encKey, slog.New(slog.DiscardHandler))
	if got := srv.enumerateGitHubCredentials(context.Background(), v.ID); got != nil {
		t.Fatalf("store error should yield nil, got %v", got)
	}
}

// errEnumStore implements github.Store with a failing List.
type errEnumStore struct{}

func (errEnumStore) GetGitHubAppInstallation(context.Context, string, string) (*store.GitHubAppInstallation, error) {
	return nil, nil
}
func (errEnumStore) ListGitHubAppInstallations(context.Context, string) ([]store.GitHubAppInstallation, error) {
	return nil, errors.New("boom")
}
func (errEnumStore) UpdateGitHubInstallationMeta(context.Context, string, string, string) error {
	return nil
}
func (errEnumStore) UpdateGitHubInstallationMintError(context.Context, string, string, string) error {
	return nil
}

func TestEnumerateGitHubCredentials(t *testing.T) {
	srv, st, vaultID := ghTestServer(t)
	ctx := context.Background()

	if got := srv.enumerateGitHubCredentials(ctx, vaultID); got != nil {
		// resolver is set but no creds yet → empty (nil) slice
		if len(got) != 0 {
			t.Fatalf("expected no creds, got %+v", got)
		}
	}
	_ = st.SetGitHubAppInstallation(ctx, &store.GitHubAppInstallation{
		VaultID: vaultID, CredentialKey: "GITHUB", AppID: "1", InstallationID: "2",
		PrivateKeyCT: []byte("ct"), PrivateKeyNonce: []byte("n"),
	})
	got := srv.enumerateGitHubCredentials(ctx, vaultID)
	if len(got) != 1 || got[0].Key != "GITHUB" {
		t.Fatalf("expected 1 enumerated cred, got %+v", got)
	}

	// nil resolver → nil
	srv.githubDynamic = nil
	if got := srv.enumerateGitHubCredentials(ctx, vaultID); got != nil {
		t.Fatalf("nil resolver should yield nil, got %v", got)
	}
}

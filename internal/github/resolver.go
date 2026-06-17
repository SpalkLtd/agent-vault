package github

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

// refreshSkew re-mints this far ahead of the installation token's expiry.
const refreshSkew = 5 * time.Minute

// Store is the slice of the persistence layer the resolver needs.
type Store interface {
	GetGitHubAppInstallation(ctx context.Context, vaultID, key string) (*store.GitHubAppInstallation, error)
	ListGitHubAppInstallations(ctx context.Context, vaultID string) ([]store.GitHubAppInstallation, error)
	UpdateGitHubInstallationMeta(ctx context.Context, vaultID, key, appSlug string) error
	UpdateGitHubInstallationMintError(ctx context.Context, vaultID, key, errMsg string) error
}

type cachedToken struct {
	token    string
	expireAt time.Time
}

// Resolver mints, caches, and re-mints GitHub App installation access tokens.
type Resolver struct {
	store     Store
	encKey    []byte
	refresher *oauth.Refresher
	logger    *slog.Logger
	clock     func() time.Time
	// afterOuterMiss is nil in production; a test hook fired after the lock-free
	// cache miss and before the single-flighted mint, to deterministically
	// exercise the under-flight re-check (otherwise only reachable via a race).
	afterOuterMiss func()

	mu    sync.Mutex
	cache map[string]cachedToken // vaultID|key -> live token
}

// NewResolver constructs a resolver. encKey must be the 32-byte DEK.
func NewResolver(s Store, encKey []byte, logger *slog.Logger) *Resolver {
	return &Resolver{
		store:     s,
		encKey:    encKey,
		refresher: oauth.NewRefresher(),
		logger:    logger,
		clock:     time.Now,
		cache:     make(map[string]cachedToken),
	}
}

// Resolve returns a fresh ghs_ installation token for key if it is a configured
// GitHub credential in vaultID. ok=false means "not a GitHub credential" (caller
// keeps its not-found error / tries other resolvers); a non-nil error is a real
// failure (not connected, mint failed).
func (r *Resolver) Resolve(ctx context.Context, vaultID, key string) (string, bool, error) {
	cred, err := r.store.GetGitHubAppInstallation(ctx, vaultID, key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	if cred == nil {
		return "", false, nil
	}
	if !cred.Connected() {
		return "", false, fmt.Errorf("github credential %q is not connected: run `agent-vault credential github connect`", key)
	}

	ck := vaultID + "|" + key
	r.mu.Lock()
	if c, ok := r.cache[ck]; ok && r.clock().Add(refreshSkew).Before(c.expireAt) {
		r.mu.Unlock()
		return c.token, true, nil
	}
	r.mu.Unlock()

	if r.afterOuterMiss != nil {
		r.afterOuterMiss()
	}

	// Single-flight the mint (GitHub rate-limits token issuance; one in-flight).
	res := r.refresher.Do(ck, func() oauth.RefreshResult {
		r.mu.Lock()
		if c, ok := r.cache[ck]; ok && r.clock().Add(refreshSkew).Before(c.expireAt) {
			r.mu.Unlock()
			return oauth.RefreshResult{AccessToken: c.token, Refreshed: true}
		}
		r.mu.Unlock()
		tok, _, err := r.mint(ctx, cred)
		if err != nil {
			return oauth.RefreshResult{Err: err}
		}
		return oauth.RefreshResult{AccessToken: tok, Refreshed: true}
	})
	if res.Err != nil {
		return "", false, res.Err
	}
	return res.AccessToken, true, nil
}

// installationToken is the response of the installation-token endpoint.
type installationToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// mint signs an app JWT, exchanges it for an installation access token, caches
// the token, and records the outcome. Returns the token and its expiry.
func (r *Resolver) mint(ctx context.Context, cred *store.GitHubAppInstallation) (string, time.Time, error) {
	pemKey, err := crypto.Decrypt(cred.PrivateKeyCT, cred.PrivateKeyNonce, r.encKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("decrypt private key: %w", err)
	}
	jwt, err := signJWT(pemKey, cred.AppID, r.clock())
	if err != nil {
		return "", time.Time{}, err
	}

	tok, err := r.requestInstallationToken(ctx, jwt, cred)
	if err != nil {
		_ = r.store.UpdateGitHubInstallationMintError(ctx, cred.VaultID, cred.CredentialKey, err.Error())
		return "", time.Time{}, fmt.Errorf("github installation token mint failed: %w", err)
	}

	r.mu.Lock()
	r.cache[cred.VaultID+"|"+cred.CredentialKey] = cachedToken{token: tok.Token, expireAt: tok.ExpiresAt}
	r.mu.Unlock()
	// Stamp last_mint_at + clear any prior error (slug "" preserves existing).
	if err := r.store.UpdateGitHubInstallationMeta(ctx, cred.VaultID, cred.CredentialKey, ""); err != nil {
		r.logger.Warn("recording github mint failed", slog.String("vault_id", cred.VaultID), slog.String("err", err.Error()))
	}
	return tok.Token, tok.ExpiresAt, nil
}

// requestInstallationToken POSTs to /app/installations/{id}/access_tokens with
// the app JWT, optionally scoping the token to a permission/repository subset.
func (r *Resolver) requestInstallationToken(ctx context.Context, jwt string, cred *store.GitHubAppInstallation) (*installationToken, error) {
	body, err := installationTokenBody(cred)
	if err != nil {
		return nil, err
	}
	url := APIBase + "/app/installations/" + cred.InstallationID + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("installation token endpoint returned %d", resp.StatusCode)
	}
	var out installationToken
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("parse installation token: %w", err)
	}
	if out.ExpiresAt.IsZero() {
		out.ExpiresAt = r.clock().Add(50 * time.Minute)
	}
	return &out, nil
}

// installationTokenBody builds the optional permission/repository scoping body,
// or a nil reader when neither is configured (full installation permissions).
// Returns io.Reader (not *bytes.Reader) so the empty case is a true nil
// interface — a typed-nil *bytes.Reader would panic in http.NewRequest.
func installationTokenBody(cred *store.GitHubAppInstallation) (io.Reader, error) {
	payload := map[string]any{}
	if strings.TrimSpace(cred.Permissions) != "" {
		payload["permissions"] = json.RawMessage(cred.Permissions)
	}
	if strings.TrimSpace(cred.Repositories) != "" {
		var repos []string
		for _, r := range strings.Split(cred.Repositories, ",") {
			if r = strings.TrimSpace(r); r != "" {
				repos = append(repos, r)
			}
		}
		payload["repositories"] = repos
	}
	if len(payload) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal token scoping: %w", err)
	}
	return bytes.NewReader(b), nil
}

// Validate is the connect-path check: it mints once to confirm the App + key +
// installation work, captures the app slug (GET /app), and persists slug +
// connected_at. Returns the app slug.
func (r *Resolver) Validate(ctx context.Context, vaultID, key string) (string, error) {
	cred, err := r.store.GetGitHubAppInstallation(ctx, vaultID, key)
	if err != nil {
		return "", err
	}
	if !cred.Connected() {
		return "", fmt.Errorf("github credential %q has no private key", key)
	}
	pemKey, err := crypto.Decrypt(cred.PrivateKeyCT, cred.PrivateKeyNonce, r.encKey)
	if err != nil {
		return "", fmt.Errorf("decrypt private key: %w", err)
	}
	jwt, err := signJWT(pemKey, cred.AppID, r.clock())
	if err != nil {
		return "", err
	}

	// Confirm the installation works by minting a token.
	if _, err := r.requestInstallationToken(ctx, jwt, cred); err != nil {
		_ = r.store.UpdateGitHubInstallationMintError(ctx, vaultID, key, err.Error())
		return "", fmt.Errorf("github installation token mint failed: %w", err)
	}
	slug, err := fetchAppSlug(ctx, jwt)
	if err != nil {
		r.logger.Warn("github app slug capture failed", slog.String("vault_id", vaultID), slog.String("err", err.Error()))
	}
	if err := r.store.UpdateGitHubInstallationMeta(ctx, vaultID, key, slug); err != nil {
		return "", err
	}
	return slug, nil
}

// EnumeratedCredential describes a configured GitHub credential for listing.
type EnumeratedCredential struct {
	Key       string
	Identity  string // "<slug>[bot]" when known
	Connected bool
}

// Enumerate lists the vault's configured GitHub credentials WITHOUT minting.
func (r *Resolver) Enumerate(ctx context.Context, vaultID string) ([]EnumeratedCredential, error) {
	rows, err := r.store.ListGitHubAppInstallations(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	out := make([]EnumeratedCredential, 0, len(rows))
	for i := range rows {
		id := ""
		if rows[i].AppSlug != "" {
			id = rows[i].AppSlug + "[bot]"
		}
		out = append(out, EnumeratedCredential{Key: rows[i].CredentialKey, Identity: id, Connected: rows[i].Connected()})
	}
	return out, nil
}

// EvictVault drops the vault's cached tokens (e.g. on reconnect/disconnect).
// ghs_ values are memory-only with ~1h TTLs; GitHub expiry is the backstop.
func (r *Resolver) EvictVault(vaultID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	prefix := vaultID + "|"
	for k := range r.cache {
		if strings.HasPrefix(k, prefix) {
			delete(r.cache, k)
		}
	}
}

// apiClient calls the GitHub REST API. No proxy, isolated transport — same
// posture as the oauth token client.
var apiClient = func() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}()

// fetchAppSlug returns the authenticated App's slug (GET /app) for display.
func fetchAppSlug(ctx context.Context, jwt string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIBase+"/app", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := apiClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github: GET /app returned %d", resp.StatusCode)
	}
	var body struct {
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	return body.Slug, nil
}

// Package github mints short-lived GitHub user-to-server access tokens (ghu_)
// on demand from a durable, DEK-encrypted rotating refresh token. It implements
// brokercore.DynamicCredentialResolver: the issued token is held only in memory
// and re-minted before expiry, while the rotating refresh token is persisted
// (the only durable secret). Tokens act as the individual human; because a
// GitHub App is the actor, GitHub records the app acting on behalf of that user.
package github

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

const (
	// ScopeSeparator is GitHub's scope delimiter in the authorize URL.
	ScopeSeparator = ","
	// refreshSkew re-mints this far ahead of access-token expiry.
	refreshSkew = 5 * time.Minute
)

// GitHub's user-to-server OAuth endpoints. Vars (not consts) so tests can point
// them at an httptest server.
var (
	AuthorizeURL = "https://github.com/login/oauth/authorize"
	TokenURL     = "https://github.com/login/oauth/access_token"
	// UserURL returns the authenticated user, used to capture the human identity.
	UserURL = "https://api.github.com/user"
)

// Store is the slice of the persistence layer the resolver needs.
type Store interface {
	GetGitHubAppCredential(ctx context.Context, vaultID, key string) (*store.GitHubAppCredential, error)
	ListGitHubAppCredentials(ctx context.Context, vaultID string) ([]store.GitHubAppCredential, error)
	UpdateGitHubRefreshToken(ctx context.Context, vaultID, key string, refreshCT, refreshNonce []byte, refreshExpiresAt *time.Time, identity string) error
	UpdateGitHubMintError(ctx context.Context, vaultID, key, errMsg string) error
}

// cachedToken is an in-memory ghu_ token. Never persisted.
type cachedToken struct {
	token    string
	expireAt time.Time
}

// Resolver mints, caches, and re-mints GitHub user-to-server tokens.
type Resolver struct {
	store     Store
	encKey    []byte
	refresher *oauth.Refresher
	logger    *slog.Logger
	clock     func() time.Time
	// encrypt is crypto.Encrypt in production; a field so tests can force the
	// (otherwise key-size-only) failure of persisting a rotated refresh token.
	encrypt func(plaintext, key []byte) (ct, nonce []byte, err error)
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
		encrypt:   crypto.Encrypt,
		cache:     make(map[string]cachedToken),
	}
}

// Resolve returns a fresh ghu_ token for key if it is a configured GitHub
// credential in vaultID. ok=false means "not a GitHub credential" (the caller
// keeps its not-found error / tries other resolvers); a non-nil error is a real
// failure (not connected, mint failed, persistence failed).
func (r *Resolver) Resolve(ctx context.Context, vaultID, key string) (string, bool, error) {
	cred, err := r.store.GetGitHubAppCredential(ctx, vaultID, key)
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

	// Single-flight the mint: the refresh token rotates, so concurrent mints
	// would race and could invalidate the chain. This is correctness, not just
	// an optimization.
	res := r.refresher.Do(ck, func() oauth.RefreshResult {
		r.mu.Lock()
		if c, ok := r.cache[ck]; ok && r.clock().Add(refreshSkew).Before(c.expireAt) {
			r.mu.Unlock()
			return oauth.RefreshResult{AccessToken: c.token, Refreshed: true}
		}
		r.mu.Unlock()
		return r.mint(ctx, cred)
	})
	if res.Err != nil {
		return "", false, res.Err
	}
	return res.AccessToken, true, nil
}

// mint exchanges the stored refresh token for a fresh ghu_ token, persists the
// rotated refresh token BEFORE returning, and caches the access token in memory.
func (r *Resolver) mint(ctx context.Context, cred *store.GitHubAppCredential) oauth.RefreshResult {
	refreshTok, err := crypto.Decrypt(cred.RefreshTokenCT, cred.RefreshTokenNonce, r.encKey)
	if err != nil {
		return oauth.RefreshResult{Err: fmt.Errorf("decrypt refresh token: %w", err)}
	}

	var clientSecret string
	if len(cred.ClientSecretCT) > 0 {
		cs, err := crypto.Decrypt(cred.ClientSecretCT, cred.ClientSecretNonce, r.encKey)
		if err != nil {
			return oauth.RefreshResult{Err: fmt.Errorf("decrypt client secret: %w", err)}
		}
		clientSecret = string(cs)
	}

	tok, err := oauth.Refresh(ctx, oauth.RefreshConfig{
		TokenURL:       TokenURL,
		ClientID:       cred.ClientID,
		ClientSecret:   clientSecret,
		RefreshToken:   string(refreshTok),
		Scopes:         cred.Scopes,
		ScopeSeparator: ScopeSeparator,
	})
	if err != nil {
		msg := mintErrorMessage(err)
		_ = r.store.UpdateGitHubMintError(ctx, cred.VaultID, cred.CredentialKey, msg)
		return oauth.RefreshResult{Err: fmt.Errorf("github mint failed: %s", msg)}
	}

	// Persist the rotated refresh token before serving. If this fails, fail the
	// whole mint — never serve a token whose new refresh token wasn't saved, or
	// the chain is lost.
	if tok.RefreshToken != "" {
		rct, rnonce, err := r.encrypt([]byte(tok.RefreshToken), r.encKey)
		if err != nil {
			return oauth.RefreshResult{Err: fmt.Errorf("encrypt rotated refresh token: %w", err)}
		}
		var rexp *time.Time
		if !tok.RefreshTokenExpiresAt.IsZero() {
			rexp = &tok.RefreshTokenExpiresAt
		}
		if err := r.store.UpdateGitHubRefreshToken(ctx, cred.VaultID, cred.CredentialKey, rct, rnonce, rexp, ""); err != nil {
			return oauth.RefreshResult{Err: fmt.Errorf("persist rotated refresh token: %w", err)}
		}
	}

	expireAt := tok.ExpiresAt
	if expireAt.IsZero() {
		// GitHub user-to-server tokens expire (~8h). If the provider omits
		// expires_in, fall back to a conservative TTL so we still re-mint.
		expireAt = r.clock().Add(time.Hour)
	}
	r.mu.Lock()
	r.cache[cred.VaultID+"|"+cred.CredentialKey] = cachedToken{token: tok.AccessToken, expireAt: expireAt}
	r.mu.Unlock()

	return oauth.RefreshResult{AccessToken: tok.AccessToken, Refreshed: true}
}

// EnumeratedCredential describes a configured GitHub credential for listing.
// The token value is never exposed (injection-only).
type EnumeratedCredential struct {
	Key       string
	Identity  string
	Connected bool
}

// Enumerate lists the vault's configured GitHub credentials WITHOUT minting —
// the key is known from config, unlike a lease whose fields require a mint.
func (r *Resolver) Enumerate(ctx context.Context, vaultID string) ([]EnumeratedCredential, error) {
	rows, err := r.store.ListGitHubAppCredentials(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	out := make([]EnumeratedCredential, 0, len(rows))
	for i := range rows {
		out = append(out, EnumeratedCredential{
			Key:       rows[i].CredentialKey,
			Identity:  rows[i].Identity,
			Connected: rows[i].Connected(),
		})
	}
	return out, nil
}

// EvictVault drops the vault's cached tokens (e.g. on disconnect). The ghu_
// values are memory-only with short TTLs, so there is nothing to revoke
// upstream — GitHub expiry is the backstop.
func (r *Resolver) EvictVault(vaultID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	prefix := vaultID + "|"
	for k := range r.cache {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(r.cache, k)
		}
	}
}

// apiClient calls the GitHub REST API for identity capture. No proxy, isolated
// transport — same posture as the oauth token client.
var apiClient = func() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}()

// FetchIdentity returns the GitHub login for an access token (GET /user).
// Best-effort: callers may proceed with an empty identity on error.
func FetchIdentity(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, UserURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := apiClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github: GET /user returned %d", resp.StatusCode)
	}
	var body struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	return body.Login, nil
}

// mintErrorMessage maps a token-endpoint error to an actionable message,
// flagging a revoked/expired refresh token (which requires a re-connect).
func mintErrorMessage(err error) string {
	var te *oauth.TokenError
	if errors.As(err, &te) && te.Permanent {
		return fmt.Sprintf("refresh token rejected (%d) — re-run `agent-vault credential github connect`", te.StatusCode)
	}
	return err.Error()
}

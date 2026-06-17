package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/github"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

// defaultGitHubCredentialKey is used when a connect/status request omits a key.
// Convention is a single GitHub credential per vault (like any other service).
const defaultGitHubCredentialKey = "GITHUB_TOKEN"

type githubConnectRequest struct {
	Vault        string `json:"vault"`
	Key          string `json:"key"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scopes       string `json:"scopes,omitempty"`
}

// handleGitHubConnect stores the GitHub App OAuth client config and returns an
// authorization URL. The browser consent lands on handleGitHubCallback, which
// captures the rotating refresh token. Requires a GitHub App with expiring user
// tokens (enforced at the callback, where a missing refresh token is rejected).
func (s *Server) handleGitHubConnect(w http.ResponseWriter, r *http.Request) {
	var req githubConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if req.Key == "" {
		req.Key = defaultGitHubCredentialKey
	}
	if !broker.CredentialKeyPattern.MatchString(req.Key) {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid credential key %q: must be SCREAMING_SNAKE_CASE (e.g. GITHUB_TOKEN)", req.Key))
		return
	}
	if req.ClientID == "" {
		jsonError(w, http.StatusBadRequest, "\"client_id\" is required (GitHub App client ID)")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}
	if !s.assertBuiltinCredentialStore(w, ctx, ns.ID, ns.Name) {
		return
	}

	_, _ = s.store.ExpireCredentialOAuthStates(ctx, time.Now())

	// client_secret: sentinel = keep current, empty = clear, other = set new.
	var clientSecretCT, clientSecretNonce []byte
	if req.ClientSecret == oauthSecretSentinel {
		if existing, _ := s.store.GetGitHubAppCredential(ctx, ns.ID, req.Key); existing != nil {
			clientSecretCT = existing.ClientSecretCT
			clientSecretNonce = existing.ClientSecretNonce
		}
	} else if req.ClientSecret != "" {
		clientSecretCT, clientSecretNonce, err = crypto.Encrypt([]byte(req.ClientSecret), s.encKey)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "Encryption failed")
			return
		}
	}

	if err := s.store.SetGitHubAppCredential(ctx, &store.GitHubAppCredential{
		VaultID:           ns.ID,
		CredentialKey:     req.Key,
		ClientID:          req.ClientID,
		ClientSecretCT:    clientSecretCT,
		ClientSecretNonce: clientSecretNonce,
		Scopes:            req.Scopes,
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to save GitHub configuration")
		return
	}
	// Drop any cached token for this vault so a reconnect re-mints.
	if s.githubDynamic != nil {
		s.githubDynamic.EvictVault(ns.ID)
	}

	stateRaw := oauthPrefixedToken("av_ghst_")
	stateHash := hashOAuthState(stateRaw)
	now := time.Now().UTC()
	if err := s.store.CreateCredentialOAuthState(ctx, &store.CredentialOAuthState{
		ID:            oauthPublicID(),
		StateHash:     stateHash,
		CodeVerifier:  "", // GitHub does not support PKCE for this flow
		VaultID:       ns.ID,
		CredentialKey: req.Key,
		CreatedAt:     now,
		ExpiresAt:     now.Add(oauthStateTTL),
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create OAuth state")
		return
	}

	redirectURI := s.baseURL + "/v1/credentials/github/callback"
	authURL := oauth.BuildAuthorizationURL(
		github.AuthorizeURL, req.ClientID, redirectURI,
		stateRaw, "", req.Scopes, github.ScopeSeparator, true,
	)
	jsonOK(w, map[string]string{"authorization_url": authURL})
}

// handleGitHubCallback completes the consent: exchanges the code, requires a
// refresh token (GitHub App with expiring user tokens), captures the human
// identity, and persists the rotating refresh token. The ghu_ access token is
// not stored — it is minted on demand by the resolver.
func (s *Server) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	stateRaw := r.URL.Query().Get("state")
	if code == "" || stateRaw == "" {
		msg := r.URL.Query().Get("error_description")
		if msg == "" {
			msg = "Missing code or state parameter"
		}
		s.redirectOAuthComplete(w, r, "", "", "error", msg)
		return
	}

	ctx := r.Context()
	st, err := s.store.GetCredentialOAuthStateByHash(ctx, hashOAuthState(stateRaw))
	if err != nil {
		s.redirectOAuthComplete(w, r, "", "", "error", "Invalid or expired OAuth state")
		return
	}
	if time.Now().After(st.ExpiresAt) {
		_ = s.store.DeleteCredentialOAuthState(ctx, st.ID)
		s.redirectOAuthComplete(w, r, "", "", "error", "OAuth state expired — please try again")
		return
	}
	_ = s.store.DeleteCredentialOAuthState(ctx, st.ID)

	cred, err := s.store.GetGitHubAppCredential(ctx, st.VaultID, st.CredentialKey)
	if err != nil {
		s.redirectOAuthComplete(w, r, "", "", "error", "GitHub configuration not found")
		return
	}

	var clientSecret string
	if len(cred.ClientSecretCT) > 0 {
		cs, err := crypto.Decrypt(cred.ClientSecretCT, cred.ClientSecretNonce, s.encKey)
		if err != nil {
			s.redirectOAuthComplete(w, r, "", "", "error", "Failed to decrypt client secret")
			return
		}
		clientSecret = string(cs)
	}

	redirectURI := s.baseURL + "/v1/credentials/github/callback"
	tok, err := oauth.Exchange(ctx, oauth.ExchangeConfig{
		TokenURL:     github.TokenURL,
		ClientID:     cred.ClientID,
		ClientSecret: clientSecret,
		Code:         code,
		RedirectURI:  redirectURI,
	})
	if err != nil {
		s.redirectOAuthComplete(w, r, "", "", "error", fmt.Sprintf("Token exchange failed: %v", err))
		return
	}

	// Hard requirement: a GitHub App with expiring user tokens. A bare OAuth App
	// (or a GitHub App without expiring user tokens) returns no refresh token,
	// which cannot back the rotating-mint model and loses on-behalf-of attribution.
	if tok.RefreshToken == "" {
		s.redirectOAuthComplete(w, r, "", "", "error",
			"No refresh token returned — this requires a GitHub App with \"Expiring user authorization tokens\" enabled (not an OAuth App)")
		return
	}

	// Capture the human identity (best-effort; attribution still works without it).
	identity, idErr := github.FetchIdentity(ctx, tok.AccessToken)
	if idErr != nil {
		s.logger.Warn("github identity capture failed", "vault_id", st.VaultID, "err", idErr.Error())
	}

	refreshCT, refreshNonce, err := crypto.Encrypt([]byte(tok.RefreshToken), s.encKey)
	if err != nil {
		s.redirectOAuthComplete(w, r, "", "", "error", "Failed to encrypt refresh token")
		return
	}
	var refreshExp *time.Time
	if !tok.RefreshTokenExpiresAt.IsZero() {
		refreshExp = &tok.RefreshTokenExpiresAt
	}
	if err := s.store.UpdateGitHubRefreshToken(ctx, st.VaultID, st.CredentialKey, refreshCT, refreshNonce, refreshExp, identity); err != nil {
		s.redirectOAuthComplete(w, r, "", "", "error", "Failed to store refresh token")
		return
	}
	if s.githubDynamic != nil {
		s.githubDynamic.EvictVault(st.VaultID)
	}

	vaultName := ""
	if v, err := s.store.GetVaultByID(ctx, st.VaultID); err == nil && v != nil {
		vaultName = v.Name
	}
	s.redirectOAuthComplete(w, r, vaultName, st.CredentialKey, "success", "")
}

// handleGitHubStatus reports connection state for a GitHub credential.
func (s *Server) handleGitHubStatus(w http.ResponseWriter, r *http.Request) {
	vault := r.URL.Query().Get("vault")
	key := r.URL.Query().Get("key")
	if vault == "" {
		vault = store.DefaultVault
	}
	if key == "" {
		key = defaultGitHubCredentialKey
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vault))
		return
	}
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}

	cred, err := s.store.GetGitHubAppCredential(ctx, ns.ID, key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("GitHub credential %q not found", key))
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to read GitHub credential")
		return
	}

	type statusResponse struct {
		Connected             bool    `json:"connected"`
		Identity              string  `json:"identity,omitempty"`
		ConnectedAt           *string `json:"connected_at,omitempty"`
		RefreshTokenExpiresAt *string `json:"refresh_token_expires_at,omitempty"`
		LastError             string  `json:"last_error,omitempty"`
	}
	resp := statusResponse{
		Connected: cred.Connected(),
		Identity:  cred.Identity,
		LastError: cred.LastMintError,
	}
	if cred.ConnectedAt != nil {
		t := cred.ConnectedAt.Format(time.RFC3339)
		resp.ConnectedAt = &t
	}
	if cred.RefreshTokenExpiresAt != nil {
		t := cred.RefreshTokenExpiresAt.Format(time.RFC3339)
		resp.RefreshTokenExpiresAt = &t
	}
	jsonOK(w, resp)
}

// enumerateGitHubCredentials returns the vault's configured GitHub credentials
// for listing. Best-effort; the token value is never exposed.
func (s *Server) enumerateGitHubCredentials(ctx context.Context, vaultID string) []github.EnumeratedCredential {
	if s.githubDynamic == nil {
		return nil
	}
	creds, err := s.githubDynamic.Enumerate(ctx, vaultID)
	if err != nil {
		s.logger.Warn("enumerating github credentials failed", "vault_id", vaultID, "err", err.Error())
		return nil
	}
	return creds
}

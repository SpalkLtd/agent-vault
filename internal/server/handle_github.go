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
	"github.com/Infisical/agent-vault/internal/store"
)

// defaultGitHubCredentialKey is used when a connect/status request omits a key.
const defaultGitHubCredentialKey = "GITHUB"

type githubConnectRequest struct {
	Vault          string `json:"vault"`
	Key            string `json:"key"`
	AppID          string `json:"app_id"`
	InstallationID string `json:"installation_id"`
	PrivateKey     string `json:"private_key"`
	Permissions    string `json:"permissions,omitempty"`  // optional JSON subset
	Repositories   string `json:"repositories,omitempty"` // optional CSV
}

// handleGitHubConnect stores a GitHub App's id/installation/private-key and
// validates it by minting one installation token (server-to-server). No browser
// flow — the App private key is the durable secret. The minted ghs_ token acts
// as the App/bot.
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
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid credential key %q: must be SCREAMING_SNAKE_CASE (e.g. GITHUB)", req.Key))
		return
	}
	if req.AppID == "" {
		jsonError(w, http.StatusBadRequest, "\"app_id\" is required (GitHub App id or client id)")
		return
	}
	if req.InstallationID == "" {
		jsonError(w, http.StatusBadRequest, "\"installation_id\" is required")
		return
	}
	if req.PrivateKey == "" {
		jsonError(w, http.StatusBadRequest, "\"private_key\" is required (GitHub App private key PEM)")
		return
	}
	if err := github.ValidatePrivateKey([]byte(req.PrivateKey)); err != nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Invalid private key: %v", err))
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

	pkCT, pkNonce, err := crypto.Encrypt([]byte(req.PrivateKey), s.encKey)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Encryption failed")
		return
	}
	if err := s.store.SetGitHubAppInstallation(ctx, &store.GitHubAppInstallation{
		VaultID:         ns.ID,
		CredentialKey:   req.Key,
		AppID:           req.AppID,
		InstallationID:  req.InstallationID,
		PrivateKeyCT:    pkCT,
		PrivateKeyNonce: pkNonce,
		Permissions:     req.Permissions,
		Repositories:    req.Repositories,
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to save GitHub configuration")
		return
	}
	if s.githubDynamic != nil {
		s.githubDynamic.EvictVault(ns.ID)
	}

	// Validate by minting once + capture the app slug. A failure here is an
	// upstream/config problem (bad installation id, key not installed, GitHub
	// down) — surface it as 502 so the operator fixes the App setup.
	if s.githubDynamic == nil {
		jsonError(w, http.StatusServiceUnavailable, "GitHub resolver not available")
		return
	}
	slug, err := s.githubDynamic.Validate(ctx, ns.ID, req.Key)
	if err != nil {
		jsonError(w, http.StatusBadGateway, fmt.Sprintf("GitHub installation token mint failed during validation: %v", err))
		return
	}

	jsonOK(w, map[string]any{"connected": true, "identity": githubIdentity(slug)})
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

	cred, err := s.store.GetGitHubAppInstallation(ctx, ns.ID, key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("GitHub credential %q not found", key))
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to read GitHub credential")
		return
	}

	type statusResponse struct {
		Connected      bool    `json:"connected"`
		Identity       string  `json:"identity,omitempty"`
		AppID          string  `json:"app_id"`
		InstallationID string  `json:"installation_id"`
		ConnectedAt    *string `json:"connected_at,omitempty"`
		LastMintAt     *string `json:"last_mint_at,omitempty"`
		LastError      string  `json:"last_error,omitempty"`
	}
	resp := statusResponse{
		Connected:      cred.Connected(),
		Identity:       githubIdentity(cred.AppSlug),
		AppID:          cred.AppID,
		InstallationID: cred.InstallationID,
		LastError:      cred.LastMintError,
	}
	if cred.ConnectedAt != nil {
		t := cred.ConnectedAt.Format(time.RFC3339)
		resp.ConnectedAt = &t
	}
	if cred.LastMintAt != nil {
		t := cred.LastMintAt.Format(time.RFC3339)
		resp.LastMintAt = &t
	}
	jsonOK(w, resp)
}

// githubIdentity renders the bot identity for an app slug ("" -> "").
func githubIdentity(slug string) string {
	if slug == "" {
		return ""
	}
	return slug + "[bot]"
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

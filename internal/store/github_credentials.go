package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// GitHubAppCredential is the durable secret behind a dynamically-issued GitHub
// user-to-server token. The minted ghu_ access token is never stored here (it is
// held in memory by internal/github); only the client id/secret and the
// rotating refresh token are persisted, all DEK-encrypted.
type GitHubAppCredential struct {
	VaultID               string
	CredentialKey         string
	ClientID              string
	ClientSecretCT        []byte
	ClientSecretNonce     []byte
	Scopes                string
	RefreshTokenCT        []byte
	RefreshTokenNonce     []byte
	RefreshTokenExpiresAt *time.Time
	Identity              string // GitHub login captured at connect
	ConnectedAt           *time.Time
	LastMintAt            *time.Time
	LastMintError         string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// Connected reports whether a refresh token has been stored (i.e. the connect
// flow completed), so a token can be minted.
func (g *GitHubAppCredential) Connected() bool { return len(g.RefreshTokenCT) > 0 }

func (s *SQLiteStore) GetGitHubAppCredential(ctx context.Context, vaultID, key string) (*GitHubAppCredential, error) {
	var g GitHubAppCredential
	var scopes, identity sql.NullString
	var refreshExp, connectedAt, lastMintAt, lastMintErr sql.NullString
	var createdAt, updatedAt string

	err := s.db.QueryRowContext(ctx,
		`SELECT vault_id, credential_key, client_id, client_secret_ct, client_secret_nonce,
		   scopes, refresh_token_ct, refresh_token_nonce, refresh_token_expires_at,
		   identity, connected_at, last_mint_at, last_mint_error, created_at, updated_at
		 FROM github_app_credentials WHERE vault_id = ? AND credential_key = ?`,
		vaultID, key,
	).Scan(
		&g.VaultID, &g.CredentialKey, &g.ClientID, &g.ClientSecretCT, &g.ClientSecretNonce,
		&scopes, &g.RefreshTokenCT, &g.RefreshTokenNonce, &refreshExp,
		&identity, &connectedAt, &lastMintAt, &lastMintErr, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	g.Scopes = scopes.String
	g.Identity = identity.String
	g.LastMintError = lastMintErr.String
	g.RefreshTokenExpiresAt = parseNullableTime(refreshExp)
	g.ConnectedAt = parseNullableTime(connectedAt)
	g.LastMintAt = parseNullableTime(lastMintAt)
	g.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	g.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
	return &g, nil
}

func (s *SQLiteStore) ListGitHubAppCredentials(ctx context.Context, vaultID string) ([]GitHubAppCredential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT vault_id, credential_key, client_id, client_secret_ct, client_secret_nonce,
		   scopes, refresh_token_ct, refresh_token_nonce, refresh_token_expires_at,
		   identity, connected_at, last_mint_at, last_mint_error, created_at, updated_at
		 FROM github_app_credentials WHERE vault_id = ? ORDER BY credential_key`,
		vaultID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []GitHubAppCredential
	for rows.Next() {
		var g GitHubAppCredential
		var scopes, identity sql.NullString
		var refreshExp, connectedAt, lastMintAt, lastMintErr sql.NullString
		var createdAt, updatedAt string
		if err := rows.Scan(
			&g.VaultID, &g.CredentialKey, &g.ClientID, &g.ClientSecretCT, &g.ClientSecretNonce,
			&scopes, &g.RefreshTokenCT, &g.RefreshTokenNonce, &refreshExp,
			&identity, &connectedAt, &lastMintAt, &lastMintErr, &createdAt, &updatedAt,
		); err != nil {
			return nil, err
		}
		g.Scopes = scopes.String
		g.Identity = identity.String
		g.LastMintError = lastMintErr.String
		g.RefreshTokenExpiresAt = parseNullableTime(refreshExp)
		g.ConnectedAt = parseNullableTime(connectedAt)
		g.LastMintAt = parseNullableTime(lastMintAt)
		g.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
		g.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
		out = append(out, g)
	}
	return out, rows.Err()
}

// SetGitHubAppCredential upserts the OAuth client config (id/secret/scopes) for
// a key. On conflict it preserves the stored refresh token, identity, and
// connection state — reconnecting only updates the client config.
func (s *SQLiteStore) SetGitHubAppCredential(ctx context.Context, g *GitHubAppCredential) error {
	now := nowUTC()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO github_app_credentials
		   (vault_id, credential_key, client_id, client_secret_ct, client_secret_nonce, scopes, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(vault_id, credential_key) DO UPDATE SET
		   client_id = excluded.client_id,
		   client_secret_ct = excluded.client_secret_ct,
		   client_secret_nonce = excluded.client_secret_nonce,
		   scopes = excluded.scopes,
		   updated_at = excluded.updated_at`,
		g.VaultID, g.CredentialKey, g.ClientID, g.ClientSecretCT, g.ClientSecretNonce,
		nullableString(g.Scopes), now, now,
	)
	if err != nil {
		return fmt.Errorf("setting github app credential: %w", err)
	}
	return nil
}

// UpdateGitHubRefreshToken persists a (possibly rotated) refresh token. When
// identity is non-empty it is also stored. connected_at is set once. This is
// called both on connect (with identity) and on every mint rotation (without).
func (s *SQLiteStore) UpdateGitHubRefreshToken(ctx context.Context, vaultID, key string, refreshCT, refreshNonce []byte, refreshExpiresAt *time.Time, identity string) error {
	now := nowUTC()
	var expStr interface{}
	if refreshExpiresAt != nil {
		expStr = refreshExpiresAt.UTC().Format(time.DateTime)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE github_app_credentials SET
		   refresh_token_ct = ?, refresh_token_nonce = ?, refresh_token_expires_at = ?,
		   identity = CASE WHEN ? <> '' THEN ? ELSE identity END,
		   connected_at = COALESCE(connected_at, ?),
		   last_mint_at = ?, last_mint_error = NULL, updated_at = ?
		 WHERE vault_id = ? AND credential_key = ?`,
		refreshCT, refreshNonce, expStr, identity, identity, now, now, now, vaultID, key,
	)
	if err != nil {
		return fmt.Errorf("updating github refresh token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("github app credential %q not found", key)
	}
	return nil
}

// UpdateGitHubMintError records the last mint failure for operator visibility.
func (s *SQLiteStore) UpdateGitHubMintError(ctx context.Context, vaultID, key, errMsg string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE github_app_credentials SET last_mint_error = ?, updated_at = ?
		 WHERE vault_id = ? AND credential_key = ?`,
		errMsg, nowUTC(), vaultID, key,
	)
	return err
}

// DeleteGitHubAppCredential removes a GitHub credential's durable secret.
func (s *SQLiteStore) DeleteGitHubAppCredential(ctx context.Context, vaultID, key string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM github_app_credentials WHERE vault_id = ? AND credential_key = ?`,
		vaultID, key,
	)
	return err
}

// parseNullableTime parses a stored datetime() TEXT column into *time.Time.
func parseNullableTime(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t, err := time.Parse(time.DateTime, s.String)
	if err != nil {
		return nil
	}
	return &t
}

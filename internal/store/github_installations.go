package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// GitHubAppInstallation is the durable secret behind a dynamically-issued GitHub
// App INSTALLATION access token (server-to-server). The minted ghs_ token is
// never stored (held in memory by internal/github); only the App id, the
// installation id, the DEK-encrypted private key, and an optional permission/
// repository subset are persisted. There is no refresh token.
type GitHubAppInstallation struct {
	VaultID         string
	CredentialKey   string
	AppID           string // JWT issuer (numeric app id or client id)
	InstallationID  string
	PrivateKeyCT    []byte
	PrivateKeyNonce []byte
	Permissions     string // optional JSON subset, e.g. {"contents":"write"}
	Repositories    string // optional CSV of repo names
	AppSlug         string // captured from GET /app; identity is "<slug>[bot]"
	ConnectedAt     *time.Time
	LastMintAt      *time.Time
	LastMintError   string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Connected reports whether a private key is stored (connect completed).
func (g *GitHubAppInstallation) Connected() bool { return len(g.PrivateKeyCT) > 0 }

const githubInstallationCols = `vault_id, credential_key, app_id, installation_id,
	private_key_ct, private_key_nonce, permissions_json, repositories, app_slug,
	connected_at, last_mint_at, last_mint_error, created_at, updated_at`

// scanGitHubInstallation scans one row (from *sql.Row or *sql.Rows) into a
// GitHubAppInstallation. Shared by Get and List so the scan/parse logic — and
// its error path — exist in one place.
func scanGitHubInstallation(sc interface{ Scan(...any) error }) (*GitHubAppInstallation, error) {
	var g GitHubAppInstallation
	var perms, repos, slug, connectedAt, lastMintAt, lastMintErr sql.NullString
	var createdAt, updatedAt string
	if err := sc.Scan(
		&g.VaultID, &g.CredentialKey, &g.AppID, &g.InstallationID,
		&g.PrivateKeyCT, &g.PrivateKeyNonce, &perms, &repos, &slug,
		&connectedAt, &lastMintAt, &lastMintErr, &createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	g.Permissions = perms.String
	g.Repositories = repos.String
	g.AppSlug = slug.String
	g.LastMintError = lastMintErr.String
	g.ConnectedAt = parseNullableInstTime(connectedAt)
	g.LastMintAt = parseNullableInstTime(lastMintAt)
	g.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	g.UpdatedAt, _ = time.Parse(time.DateTime, updatedAt)
	return &g, nil
}

func (s *SQLiteStore) GetGitHubAppInstallation(ctx context.Context, vaultID, key string) (*GitHubAppInstallation, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+githubInstallationCols+` FROM github_app_installations WHERE vault_id = ? AND credential_key = ?`,
		vaultID, key,
	)
	return scanGitHubInstallation(row)
}

func (s *SQLiteStore) ListGitHubAppInstallations(ctx context.Context, vaultID string) ([]GitHubAppInstallation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+githubInstallationCols+` FROM github_app_installations WHERE vault_id = ? ORDER BY credential_key`,
		vaultID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []GitHubAppInstallation
	for rows.Next() {
		g, err := scanGitHubInstallation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

// SetGitHubAppInstallation upserts the App config + private key for a key. On
// conflict it preserves the captured app_slug and connected_at (those reflect a
// validated mint, not the config the operator just re-entered).
func (s *SQLiteStore) SetGitHubAppInstallation(ctx context.Context, g *GitHubAppInstallation) error {
	now := nowUTC()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO github_app_installations
		   (vault_id, credential_key, app_id, installation_id, private_key_ct, private_key_nonce,
		    permissions_json, repositories, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(vault_id, credential_key) DO UPDATE SET
		   app_id = excluded.app_id,
		   installation_id = excluded.installation_id,
		   private_key_ct = excluded.private_key_ct,
		   private_key_nonce = excluded.private_key_nonce,
		   permissions_json = excluded.permissions_json,
		   repositories = excluded.repositories,
		   updated_at = excluded.updated_at`,
		g.VaultID, g.CredentialKey, g.AppID, g.InstallationID, g.PrivateKeyCT, g.PrivateKeyNonce,
		nullableString(g.Permissions), nullableString(g.Repositories), now, now,
	)
	if err != nil {
		return fmt.Errorf("setting github app installation: %w", err)
	}
	return nil
}

// UpdateGitHubInstallationMeta records a successful mint: stores app_slug (when
// non-empty), sets connected_at once, stamps last_mint_at, and clears any error.
func (s *SQLiteStore) UpdateGitHubInstallationMeta(ctx context.Context, vaultID, key, appSlug string) error {
	now := nowUTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE github_app_installations SET
		   app_slug = CASE WHEN ? <> '' THEN ? ELSE app_slug END,
		   connected_at = COALESCE(connected_at, ?),
		   last_mint_at = ?, last_mint_error = NULL, updated_at = ?
		 WHERE vault_id = ? AND credential_key = ?`,
		appSlug, appSlug, now, now, now, vaultID, key,
	)
	if err != nil {
		return fmt.Errorf("updating github installation meta: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("github app installation %q not found", key)
	}
	return nil
}

// UpdateGitHubInstallationMintError records the last mint failure.
func (s *SQLiteStore) UpdateGitHubInstallationMintError(ctx context.Context, vaultID, key, errMsg string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE github_app_installations SET last_mint_error = ?, updated_at = ?
		 WHERE vault_id = ? AND credential_key = ?`,
		errMsg, nowUTC(), vaultID, key,
	)
	return err
}

// DeleteGitHubAppInstallation removes a credential's durable secret.
func (s *SQLiteStore) DeleteGitHubAppInstallation(ctx context.Context, vaultID, key string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM github_app_installations WHERE vault_id = ? AND credential_key = ?`,
		vaultID, key,
	)
	return err
}

func parseNullableInstTime(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t, err := time.Parse(time.DateTime, s.String)
	if err != nil {
		return nil
	}
	return &t
}

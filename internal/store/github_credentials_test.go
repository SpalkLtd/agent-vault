package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func ghTestStore(t *testing.T) (*SQLiteStore, string) {
	t.Helper()
	st, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	v, err := st.CreateVault(context.Background(), "test")
	if err != nil {
		t.Fatalf("create vault: %v", err)
	}
	return st, v.ID
}

func TestGitHubAppCredential_SetGetConflict(t *testing.T) {
	st, vaultID := ghTestStore(t)
	ctx := context.Background()

	// Not found before insert.
	if _, err := st.GetGitHubAppCredential(ctx, vaultID, "GITHUB_TOKEN"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}

	// Insert.
	if err := st.SetGitHubAppCredential(ctx, &GitHubAppCredential{
		VaultID: vaultID, CredentialKey: "GITHUB_TOKEN", ClientID: "cid1",
		ClientSecretCT: []byte("ct"), ClientSecretNonce: []byte("nonce"), Scopes: "repo",
	}); err != nil {
		t.Fatalf("set: %v", err)
	}

	g, err := st.GetGitHubAppCredential(ctx, vaultID, "GITHUB_TOKEN")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if g.ClientID != "cid1" || g.Scopes != "repo" || string(g.ClientSecretCT) != "ct" {
		t.Fatalf("unexpected row: %+v", g)
	}
	if g.Connected() {
		t.Fatalf("should not be connected before refresh token set")
	}

	// Add a refresh token, then re-Set (conflict): client config updates, refresh
	// token preserved.
	if err := st.UpdateGitHubRefreshToken(ctx, vaultID, "GITHUB_TOKEN", []byte("rct"), []byte("rn"), nil, "alice"); err != nil {
		t.Fatalf("update refresh: %v", err)
	}
	if err := st.SetGitHubAppCredential(ctx, &GitHubAppCredential{
		VaultID: vaultID, CredentialKey: "GITHUB_TOKEN", ClientID: "cid2", Scopes: "repo,read:org",
	}); err != nil {
		t.Fatalf("re-set: %v", err)
	}
	g, _ = st.GetGitHubAppCredential(ctx, vaultID, "GITHUB_TOKEN")
	if g.ClientID != "cid2" || g.Scopes != "repo,read:org" {
		t.Fatalf("conflict update failed: %+v", g)
	}
	if !g.Connected() || string(g.RefreshTokenCT) != "rct" || g.Identity != "alice" {
		t.Fatalf("refresh token/identity not preserved on conflict: %+v", g)
	}
}

func TestGitHubAppCredential_UpdateRefreshToken(t *testing.T) {
	st, vaultID := ghTestStore(t)
	ctx := context.Background()

	// Updating a non-existent row reports not found.
	if err := st.UpdateGitHubRefreshToken(ctx, vaultID, "GITHUB_TOKEN", []byte("x"), []byte("y"), nil, ""); err == nil {
		t.Fatalf("expected error updating missing row")
	}

	if err := st.SetGitHubAppCredential(ctx, &GitHubAppCredential{
		VaultID: vaultID, CredentialKey: "GITHUB_TOKEN", ClientID: "cid",
	}); err != nil {
		t.Fatalf("set: %v", err)
	}

	exp := time.Now().Add(180 * 24 * time.Hour)
	if err := st.UpdateGitHubRefreshToken(ctx, vaultID, "GITHUB_TOKEN", []byte("rct"), []byte("rn"), &exp, "alice"); err != nil {
		t.Fatalf("update: %v", err)
	}
	g, _ := st.GetGitHubAppCredential(ctx, vaultID, "GITHUB_TOKEN")
	if g.Identity != "alice" || g.ConnectedAt == nil || g.RefreshTokenExpiresAt == nil || g.LastMintAt == nil {
		t.Fatalf("update did not set fields: %+v", g)
	}
	firstConnected := *g.ConnectedAt

	// Rotation with empty identity preserves the identity and connected_at.
	if err := st.UpdateGitHubRefreshToken(ctx, vaultID, "GITHUB_TOKEN", []byte("rct2"), []byte("rn2"), nil, ""); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	g, _ = st.GetGitHubAppCredential(ctx, vaultID, "GITHUB_TOKEN")
	if g.Identity != "alice" {
		t.Fatalf("identity should be preserved on empty-identity rotation, got %q", g.Identity)
	}
	if !g.ConnectedAt.Equal(firstConnected) {
		t.Fatalf("connected_at should be stable across rotation")
	}
	if string(g.RefreshTokenCT) != "rct2" {
		t.Fatalf("refresh token not rotated: %q", g.RefreshTokenCT)
	}
}

func TestGitHubAppCredential_MintErrorAndList(t *testing.T) {
	st, vaultID := ghTestStore(t)
	ctx := context.Background()

	// Empty list.
	if rows, err := st.ListGitHubAppCredentials(ctx, vaultID); err != nil || len(rows) != 0 {
		t.Fatalf("expected empty list, got %v %v", rows, err)
	}

	for _, k := range []string{"GITHUB_TOKEN", "GH_SECOND"} {
		if err := st.SetGitHubAppCredential(ctx, &GitHubAppCredential{VaultID: vaultID, CredentialKey: k, ClientID: "cid"}); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}
	rows, err := st.ListGitHubAppCredentials(ctx, vaultID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d (%v)", len(rows), err)
	}

	if err := st.UpdateGitHubMintError(ctx, vaultID, "GITHUB_TOKEN", "boom"); err != nil {
		t.Fatalf("mint error: %v", err)
	}
	g, _ := st.GetGitHubAppCredential(ctx, vaultID, "GITHUB_TOKEN")
	if g.LastMintError != "boom" {
		t.Fatalf("expected last_mint_error=boom, got %q", g.LastMintError)
	}
}

func TestGitHubAppCredential_Delete(t *testing.T) {
	st, vaultID := ghTestStore(t)
	ctx := context.Background()
	if err := st.SetGitHubAppCredential(ctx, &GitHubAppCredential{VaultID: vaultID, CredentialKey: "GITHUB_TOKEN", ClientID: "cid"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := st.DeleteGitHubAppCredential(ctx, vaultID, "GITHUB_TOKEN"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.GetGitHubAppCredential(ctx, vaultID, "GITHUB_TOKEN"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows after delete, got %v", err)
	}
}

func TestGitHubAppCredential_DBErrors(t *testing.T) {
	st, vaultID := ghTestStore(t)
	ctx := context.Background()
	// Seed a row so Update targets an existing row before we close the DB.
	if err := st.SetGitHubAppCredential(ctx, &GitHubAppCredential{VaultID: vaultID, CredentialKey: "GITHUB_TOKEN", ClientID: "cid"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Close the DB so every subsequent query/exec returns an error.
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := st.GetGitHubAppCredential(ctx, vaultID, "GITHUB_TOKEN"); err == nil {
		t.Fatalf("expected Get error on closed DB")
	}
	if _, err := st.ListGitHubAppCredentials(ctx, vaultID); err == nil {
		t.Fatalf("expected List error on closed DB")
	}
	if err := st.SetGitHubAppCredential(ctx, &GitHubAppCredential{VaultID: vaultID, CredentialKey: "K", ClientID: "c"}); err == nil {
		t.Fatalf("expected Set error on closed DB")
	}
	if err := st.UpdateGitHubRefreshToken(ctx, vaultID, "GITHUB_TOKEN", []byte("a"), []byte("b"), nil, ""); err == nil {
		t.Fatalf("expected Update error on closed DB")
	}
	if err := st.UpdateGitHubMintError(ctx, vaultID, "GITHUB_TOKEN", "x"); err == nil {
		t.Fatalf("expected UpdateMintError error on closed DB")
	}
	if err := st.DeleteGitHubAppCredential(ctx, vaultID, "GITHUB_TOKEN"); err == nil {
		t.Fatalf("expected Delete error on closed DB")
	}
}

func TestParseNullableTime(t *testing.T) {
	if parseNullableTime(sql.NullString{Valid: false}) != nil {
		t.Fatalf("null → nil")
	}
	if parseNullableTime(sql.NullString{Valid: true, String: ""}) != nil {
		t.Fatalf("empty → nil")
	}
	if parseNullableTime(sql.NullString{Valid: true, String: "not-a-time"}) != nil {
		t.Fatalf("malformed → nil")
	}
	got := parseNullableTime(sql.NullString{Valid: true, String: "2024-01-02 03:04:05"})
	if got == nil || got.Year() != 2024 || got.Hour() != 3 {
		t.Fatalf("valid parse failed: %v", got)
	}
}

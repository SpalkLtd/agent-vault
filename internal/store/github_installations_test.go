package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func ghiStore(t *testing.T) (*SQLiteStore, string) {
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

func TestGitHubAppInstallation_SetGetConflict(t *testing.T) {
	st, vaultID := ghiStore(t)
	ctx := context.Background()

	if _, err := st.GetGitHubAppInstallation(ctx, vaultID, "GITHUB"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}

	if err := st.SetGitHubAppInstallation(ctx, &GitHubAppInstallation{
		VaultID: vaultID, CredentialKey: "GITHUB", AppID: "123", InstallationID: "456",
		PrivateKeyCT: []byte("ct"), PrivateKeyNonce: []byte("n"),
		Permissions: `{"contents":"write"}`, Repositories: "repo-a,repo-b",
	}); err != nil {
		t.Fatalf("set: %v", err)
	}

	g, err := st.GetGitHubAppInstallation(ctx, vaultID, "GITHUB")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if g.AppID != "123" || g.InstallationID != "456" || string(g.PrivateKeyCT) != "ct" ||
		g.Permissions != `{"contents":"write"}` || g.Repositories != "repo-a,repo-b" {
		t.Fatalf("unexpected row: %+v", g)
	}
	if !g.Connected() {
		t.Fatalf("should be connected (has private key)")
	}

	// Record a successful mint (sets slug + connected_at), then re-Set config and
	// confirm slug/connected_at survive the conflict update.
	if err := st.UpdateGitHubInstallationMeta(ctx, vaultID, "GITHUB", "spalk-agent"); err != nil {
		t.Fatalf("update meta: %v", err)
	}
	if err := st.SetGitHubAppInstallation(ctx, &GitHubAppInstallation{
		VaultID: vaultID, CredentialKey: "GITHUB", AppID: "123", InstallationID: "789",
		PrivateKeyCT: []byte("ct2"), PrivateKeyNonce: []byte("n2"),
	}); err != nil {
		t.Fatalf("re-set: %v", err)
	}
	g, _ = st.GetGitHubAppInstallation(ctx, vaultID, "GITHUB")
	if g.InstallationID != "789" || string(g.PrivateKeyCT) != "ct2" {
		t.Fatalf("conflict update failed: %+v", g)
	}
	if g.AppSlug != "spalk-agent" || g.ConnectedAt == nil {
		t.Fatalf("slug/connected_at should survive conflict: %+v", g)
	}
}

func TestGitHubAppInstallation_MetaAndMintError(t *testing.T) {
	st, vaultID := ghiStore(t)
	ctx := context.Background()

	// Meta on a missing row reports not found.
	if err := st.UpdateGitHubInstallationMeta(ctx, vaultID, "GITHUB", "x"); err == nil {
		t.Fatalf("expected error updating missing row")
	}

	_ = st.SetGitHubAppInstallation(ctx, &GitHubAppInstallation{
		VaultID: vaultID, CredentialKey: "GITHUB", AppID: "1", InstallationID: "2",
		PrivateKeyCT: []byte("ct"), PrivateKeyNonce: []byte("n"),
	})

	if err := st.UpdateGitHubInstallationMintError(ctx, vaultID, "GITHUB", "boom"); err != nil {
		t.Fatalf("mint error: %v", err)
	}
	g, _ := st.GetGitHubAppInstallation(ctx, vaultID, "GITHUB")
	if g.LastMintError != "boom" {
		t.Fatalf("expected last_mint_error=boom, got %q", g.LastMintError)
	}

	// A successful mint clears the error and is recorded.
	if err := st.UpdateGitHubInstallationMeta(ctx, vaultID, "GITHUB", ""); err != nil {
		t.Fatalf("meta: %v", err)
	}
	g, _ = st.GetGitHubAppInstallation(ctx, vaultID, "GITHUB")
	if g.LastMintError != "" || g.LastMintAt == nil {
		t.Fatalf("meta should clear error + set last_mint_at: %+v", g)
	}
}

func TestGitHubAppInstallation_ListAndDelete(t *testing.T) {
	st, vaultID := ghiStore(t)
	ctx := context.Background()

	if rows, err := st.ListGitHubAppInstallations(ctx, vaultID); err != nil || len(rows) != 0 {
		t.Fatalf("expected empty list, got %v %v", rows, err)
	}
	for _, k := range []string{"GITHUB", "GH_SECOND"} {
		_ = st.SetGitHubAppInstallation(ctx, &GitHubAppInstallation{
			VaultID: vaultID, CredentialKey: k, AppID: "1", InstallationID: "2",
			PrivateKeyCT: []byte("ct"), PrivateKeyNonce: []byte("n"),
		})
	}
	rows, err := st.ListGitHubAppInstallations(ctx, vaultID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d (%v)", len(rows), err)
	}

	if err := st.DeleteGitHubAppInstallation(ctx, vaultID, "GITHUB"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.GetGitHubAppInstallation(ctx, vaultID, "GITHUB"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows after delete, got %v", err)
	}
}

func TestParseNullableInstTime(t *testing.T) {
	if parseNullableInstTime(sql.NullString{Valid: false}) != nil {
		t.Fatalf("null → nil")
	}
	if parseNullableInstTime(sql.NullString{Valid: true, String: ""}) != nil {
		t.Fatalf("empty → nil")
	}
	if parseNullableInstTime(sql.NullString{Valid: true, String: "not-a-time"}) != nil {
		t.Fatalf("malformed → nil")
	}
	got := parseNullableInstTime(sql.NullString{Valid: true, String: "2024-01-02 03:04:05"})
	if got == nil || got.Year() != 2024 {
		t.Fatalf("valid parse failed: %v", got)
	}
}

func TestGitHubAppInstallation_DBErrors(t *testing.T) {
	st, vaultID := ghiStore(t)
	ctx := context.Background()
	_ = st.SetGitHubAppInstallation(ctx, &GitHubAppInstallation{
		VaultID: vaultID, CredentialKey: "GITHUB", AppID: "1", InstallationID: "2",
		PrivateKeyCT: []byte("ct"), PrivateKeyNonce: []byte("n"),
	})
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := st.GetGitHubAppInstallation(ctx, vaultID, "GITHUB"); err == nil {
		t.Fatalf("expected Get error on closed DB")
	}
	if _, err := st.ListGitHubAppInstallations(ctx, vaultID); err == nil {
		t.Fatalf("expected List error on closed DB")
	}
	if err := st.SetGitHubAppInstallation(ctx, &GitHubAppInstallation{VaultID: vaultID, CredentialKey: "K", AppID: "1", InstallationID: "2"}); err == nil {
		t.Fatalf("expected Set error on closed DB")
	}
	if err := st.UpdateGitHubInstallationMeta(ctx, vaultID, "GITHUB", "x"); err == nil {
		t.Fatalf("expected Meta error on closed DB")
	}
	if err := st.UpdateGitHubInstallationMintError(ctx, vaultID, "GITHUB", "x"); err == nil {
		t.Fatalf("expected MintError error on closed DB")
	}
	if err := st.DeleteGitHubAppInstallation(ctx, vaultID, "GITHUB"); err == nil {
		t.Fatalf("expected Delete error on closed DB")
	}
}

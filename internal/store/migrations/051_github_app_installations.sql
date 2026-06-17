-- Durable secret for GitHub App INSTALLATION credentials (server-to-server,
-- "Mode B"). The short-lived ghs_ installation access token is NOT stored here:
-- it is minted on demand (sign a JWT with the App private key, then POST to
-- /app/installations/{id}/access_tokens) and held only in memory by
-- internal/github. This table holds only what is needed to mint: the App id
-- (JWT issuer), the installation id, the DEK-encrypted private key PEM, and an
-- optional permission/repository subset. No parent credentials row and no
-- refresh token (installation tokens are mint-and-expire). app_slug is captured
-- from GET /app for display (identity "<slug>[bot]").
CREATE TABLE github_app_installations (
    vault_id          TEXT NOT NULL,
    credential_key    TEXT NOT NULL,
    app_id            TEXT NOT NULL,
    installation_id   TEXT NOT NULL,
    private_key_ct    BLOB,
    private_key_nonce BLOB,
    permissions_json  TEXT,
    repositories      TEXT,
    app_slug          TEXT NOT NULL DEFAULT '',
    connected_at      TEXT,
    last_mint_at      TEXT,
    last_mint_error   TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (vault_id, credential_key),
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
);

-- Durable secret for GitHub App user-to-server credentials. The short-lived
-- ghu_ access token is NOT stored here (it is minted on demand and held only in
-- memory by internal/github). This table holds only what is needed to mint:
-- the OAuth client id/secret and the rotating refresh token, all DEK-encrypted.
-- There is no parent credentials row — GITHUB_TOKEN resolves dynamically.
CREATE TABLE github_app_credentials (
    vault_id                 TEXT NOT NULL,
    credential_key           TEXT NOT NULL,
    client_id                TEXT NOT NULL,
    client_secret_ct         BLOB,
    client_secret_nonce      BLOB,
    scopes                   TEXT,
    refresh_token_ct         BLOB,
    refresh_token_nonce      BLOB,
    refresh_token_expires_at TEXT,
    identity                 TEXT NOT NULL DEFAULT '',
    connected_at             TEXT,
    last_mint_at             TEXT,
    last_mint_error          TEXT,
    created_at               TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at               TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (vault_id, credential_key),
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
);

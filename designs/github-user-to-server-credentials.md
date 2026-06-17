# Design: GitHub user-to-server credentials (dynamic, short-lived, human-attributed)

Status: **Draft / spec** — no code yet.
Scope: GitHub-specific. AWS/IAM is out of scope for v1 (see [§14](#14-future-aws-iam-not-in-v1)).

---

## 1. Summary

Add a credential that **dynamically issues short-lived GitHub user-to-server
access tokens** (`ghu_…`) on demand, so an agent proxied through Agent Vault can
call the GitHub API and push over HTTPS **without ever holding the GitHub App's
client secret or the user's refresh token**. Tokens act **as the individual
human** (native GitHub attribution); because a **GitHub App** is the actor,
GitHub records the app acting *on behalf of* that human.

### Architecture (one line)

A new **`DynamicCredentialResolver`** (`internal/github`) mints `ghu_` tokens
lazily at request time, caches them **in memory only**, and re-mints before
expiry — exactly the dynamic-secret model. The **durable secret** behind it
(client id/secret + a rotating refresh token) is stored encrypted in a small
dedicated table and acquired once via a browser connect flow. The resolver
persists only the **rotated refresh token**; the issued `ghu_` token is never
written to disk.

This means:
- `GITHUB_TOKEN` has **no static `credentials` row** — it resolves through the
  existing dynamic fallthrough seam (`internal/brokercore/credential.go:176-186`),
  the same path Infisical dynamic secrets use.
- The vault stays **`builtin` (SQLite)** and serves static creds for other
  domains (Stripe/Anthropic/…) concurrently. No new credential-store *kind*, no
  vault exclusivity.
- The `ghu_` token is **injection-only by construction** (ephemeral, memory-only)
  — it is never revealable.

### Attribution: reviewer-visible "human + AI", three stacked layers ([§9](#9-attribution-human--ai-three-stacked-layers))
1. **GitHub App on-behalf-of** — inherent to user-to-server tokens minted by a
   GitHub App. We **hard-require a GitHub App** (reject bare OAuth Apps).
2. **Commit `Co-authored-by` trailers** — the agent co-attributes commits; the
   surface the reviewer actually reads. **Convention only** (documented in the
   skill), no proxy-side enforcement.
3. **Agent Vault-side attribution** — our request log + UI tag every brokered
   GitHub call with the agent/session that minted it and the human identity.

---

## 2. Goals & non-goals

### Goals
- Agent obtains a valid GitHub token without reading the client secret or refresh
  token; tokens are short-lived (~8h) and act as the human; re-minted
  transparently before expiry.
- The `ghu_` token lives **only in memory**, never persisted.
- Both `gh` **and** raw `git push/fetch` over HTTPS get the token transparently
  via the existing MITM proxy — no wrapper or git credential helper
  ([§8](#8-injection--proxy-wiring)).
- Coexists with static + other credentials in the same builtin vault.
- Reviewers see "human + AI" provenance on the PR/commit.

### Non-goals (v1)
- GitHub App **installation** tokens (server-to-server, PEM-signed JWT, acts as
  the bot — the Infisical `/dynamic-secrets/github` model). We chose
  user-to-server for human attribution. A different credential; possible later.
- A stored App **private key (PEM)** — user-to-server does not use one
  ([§3](#3-what-is-and-isnt-stored)). **Open item** ([§15](#15-open-items)).
- AWS/IAM short-lived credentials ([§14](#14-future-aws-iam-not-in-v1)).
- A provider-agnostic abstraction — GitHub-specific now, but on the shared
  `DynamicCredentialResolver` seam so AWS can join later.
- Defending against the agent *obtaining a token* — that's the credential's job.
  The boundary is that the agent never obtains the **secret/refresh token**, and
  loses minting ability the moment its proxy access is revoked.

---

## 3. Why a `DynamicCredentialResolver` (and what is / isn't stored)

There are two layers, and they must not be conflated:

| Layer | What | Persisted? | Model |
|---|---|---|---|
| **Durable secret** | client id + client secret + rotating refresh token | **Yes**, encrypted (DEK) | dedicated table, set once via connect |
| **Issued value** | the `ghu_` access token | **No** — memory only | minted on demand by the resolver |

The earlier version of this doc reused the OAuth credential type
(`credential_oauth`) for *both* layers. That was wrong: that model persists the
**access token** in `credentials.ciphertext` and refreshes it in place — but for
a short-lived, human-acting, injection-only token, persisting the issued value
is a liability, not a feature. The refresh-token-persistence requirement
constrains only the *durable* layer; it says nothing about how `ghu_` is issued.

So issuance belongs on the **dynamic seam**, alongside Infisical dynamic secrets:

| | Infisical dynamic resolver | **GitHub resolver (new)** |
|---|---|---|
| Seam | `brokercore.DynamicCredentialResolver` | same |
| Issued value | lease fields, memory-only | `ghu_` token, memory-only |
| Cache + single-flight + renew-before-expiry | yes (`internal/infisical/dynamic.go`) | yes (same shape) |
| Needs the DEK? | **No** (values arrive plaintext from Infisical) | **Yes** — decrypts the durable secret, encrypts the rotated refresh token |
| Persists across mints | lease metadata (to revoke provisioned resources) | **only the rotated refresh token** |
| Upstream revoke on disconnect | yes (provisions real resources) | not required — `ghu_` just expires; revoke is optional best-effort |

### Why the vault is *not* GitHub-exclusive

An Infisical-*backed* vault is exclusive only because of incidental choices we do
not copy: one store row per vault (`vault_credential_stores` PK), the syncer
overwriting the whole `credentials` table, and static writes 409’ing. The GitHub
resolver copies none of that. Like Infisical *dynamic secrets* (as opposed to the
Infisical *store kind*), it rides the per-key fallthrough that fires when no
static row exists (`credential.go:176-186`). The vault remains `builtin`.

### What is and isn't stored

- **Stored (encrypted, DEK):** client id, client secret, rotating refresh token,
  `refresh_token_expires_at`, captured GitHub `identity` (login).
- **Not stored:** the `ghu_` access token (memory only), and — for v1
  user-to-server — **no App private key / PEM** (the PEM is only for installation
  tokens). The user has referenced an "App private key"; v1 assumes none. See
  [§15](#15-open-items).

---

## 4. Token model (user-to-server)

- The resolver holds a **rotating refresh token** for the human, obtained once
  via connect ([§7](#7-one-time-setup-connect-flow)).
- To mint: exchange the refresh token at GitHub's token endpoint
  (`grant_type=refresh_token`, `client_id`, `client_secret`) for a fresh `ghu_`
  access token **and a new refresh token** (single-use rotation).
- Lifetimes (confirm against current GitHub docs at build time): access
  `expires_in` ≈ **8h** (in-memory cache TTL); `refresh_token_expires_in` ≈
  **6 months** (re-connect cadence).
- Effective access = App installation permissions **∩** the human's own access —
  never more than either. Pair with branch rulesets so a leaked token still
  can't merge to protected branches.

---

## 5. Data model

No reuse of `credential_oauth`. New table for the **durable secret only**:

```sql
-- internal/store/migrations/0XX_github_app_credentials.sql
CREATE TABLE github_app_credentials (
  vault_id                  TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  key                       TEXT NOT NULL,                 -- e.g. GITHUB_TOKEN
  client_id                 TEXT NOT NULL,
  client_secret_ct          BLOB NOT NULL,                 -- DEK-encrypted
  client_secret_nonce       BLOB NOT NULL,
  refresh_token_ct          BLOB NOT NULL,                 -- DEK-encrypted, rotates
  refresh_token_nonce       BLOB NOT NULL,
  refresh_token_expires_at  TEXT,
  identity                  TEXT NOT NULL DEFAULT '',      -- GitHub login (GET /user)
  connected_at              TEXT,
  last_mint_at              TEXT,
  last_mint_error           TEXT,
  created_at                TEXT NOT NULL,
  updated_at                TEXT NOT NULL,
  PRIMARY KEY (vault_id, key)
);
```

- **No persisted access token.** No lease-metadata table (nothing to revoke
  upstream; `ghu_` expiry is the backstop).
- Store surface (new): `GetGitHubAppCredential(vaultID, key)`,
  `ListGitHubAppCredentials(vaultID)`, `SetGitHubAppCredential(...)` (connect),
  `UpdateGitHubRefreshToken(vaultID, key, ct, nonce, expiresAt)` (post-mint
  rotation), `UpdateGitHubMintError(...)`.

---

## 6. Issuance flow (the resolver)

`internal/github.Resolver` implements
`brokercore.DynamicCredentialResolver.Resolve(ctx, vaultID, key)`:

1. `GetGitHubAppCredential(vaultID, key)`. **Not found → `ok=false`** (not a
   GitHub credential; caller keeps its not-found error / tries other resolvers).
2. Check the in-memory cache `{accessToken, expiresAt}` for `vaultID|key`. If
   `> refreshSkew` (~5m) remaining → return cached token.
3. Otherwise mint, **single-flighted** (`oauth.Refresher`, keyed `vaultID|key` —
   the same primitive the existing OAuth refresh uses; required for correctness
   because the refresh token rotates):
   a. Decrypt client secret + refresh token with the DEK.
   b. `oauth.Refresh(...)` against `https://github.com/login/oauth/access_token`
      (`grant_type=refresh_token`, scope separator `,`, `Accept: application/json`).
   c. **Persist the rotated refresh token first** (encrypt → `UpdateGitHubRefreshToken`).
      If this write fails, **fail the mint** — never serve a token whose new
      refresh token wasn't durably saved (source spec §6; matches existing
      persist-before-serve in `maybeRefreshOAuth`).
   d. Cache `{ghu_ token, now+expires_in}` in memory; record `last_mint_at`.
4. Return the cached `ghu_` token (caller memoizes per request via
   `credential.go:170` so auth + substitutions decrypt/mint once).

Properties this gives, for free or near-free:
- **Restart:** in-memory cache cold → first request mints from the persisted
  refresh token; no human interaction.
- **Single-flight:** N concurrent requests during a cold/expiring cache → one
  exchange. Reuses `internal/oauth/refresher.go`.
- **Revoked/expired refresh token:** map `oauth.TokenError`
  (`internal/oauth/oauth.go:49-67`) to a distinct, actionable error
  ("re-run `agent-vault credential github connect …`"); set `last_mint_error`.
- **Identity** captured at connect; mint need not re-fetch.

### Wiring (multiple resolvers)

Today `brokercore.StoreCredentialProvider.Dynamic` is a single resolver, wired in
`server.go` (`lateDynamicResolver` → `s.infisicalDynamic`). Add a **composite**
that consults GitHub then Infisical, each returning `ok=false` for keys that
aren't theirs (disjoint: GitHub keys come from `github_app_credentials`,
Infisical from `cs.Kind==infisical`). First `ok=true` (or first real error) wins.

---

## 7. One-time setup (connect flow)

Reuse the browser authorization-code + PKCE flow and `internal/oauth`. Only the
*storage target* differs: write the durable secret to `github_app_credentials`
(not `credential_oauth`). A GitHub preset fills endpoints so the operator doesn't
hand-type them.

```bash
agent-vault credential github connect \
  --vault=default --key=GITHUB_TOKEN \
  --client-id=Iv1.xxxx --client-secret=xxxx \
  --scopes="repo,read:org"            # comma-separated for GitHub
# opens https://github.com/login/oauth/authorize?...; operator consents;
# callback exchanges the code; refresh token stored DEK-encrypted; identity
# captured from GET https://api.github.com/user.
```

- **Hard-require a GitHub App.** If the callback returns **no `refresh_token`**,
  the App lacks "expiring user tokens" (or it's an OAuth App) → fail fast with a
  clear error. This also protects attribution layer 1 ([§9](#9-attribution-human--ai-three-stacked-layers)).
- The redirect URI must match one registered on the GitHub App.
- Implementation choice: a dedicated `POST /v1/credentials/github/connect`
  (+ callback) keyed to the new table, or generalize the existing
  `handleOAuthConnect`/`handleOAuthCallback` (`internal/server/handle_oauth.go`)
  with a `provider` discriminator and a pluggable storage target. Prefer a
  dedicated handler to keep `credential_oauth` semantics clean.

---

## 8. Injection / proxy wiring

Agent Vault's MITM proxy already makes `gh` and `git`-over-HTTPS share one token
source — both traverse the proxy — so we inject at the proxy, no tool shims.

Two services in the vault, both referencing `GITHUB_TOKEN`:

| Service | Host | Auth injected |
|---|---|---|
| GitHub API | `api.github.com` | `Authorization: Bearer <GITHUB_TOKEN>` |
| git-over-HTTPS | `github.com` | `Authorization: Basic base64("x-access-token:<GITHUB_TOKEN>")` |

`GITHUB_TOKEN` resolves via the dynamic fallthrough — there is no static row to
match first. Raw **SSH git** bypasses the HTTP proxy entirely → known
out-of-scope gap (document it, mirroring the source spec §8 caveat).

---

## 9. Attribution: human + AI (three stacked layers)

The reviewer sees provenance on the **PR/commit** (layer 2); the others back it
up in GitHub's audit log and in our own logs.

### Layer 1 — GitHub App on-behalf-of (inherent, **hard-required**)
A GitHub App minting user-to-server tokens means GitHub records the app acting
**on behalf of** the human (audit log + several API surfaces). We **reject
OAuth Apps at connect** (no app identity, no `refresh_token` for expiring user
tokens) so this layer always holds.

### Layer 2 — commit `Co-authored-by` (reviewer-visible, **convention only**)
The agent adds a co-author trailer so the commit/PR visibly shows human + AI,
e.g. `Co-authored-by: Agent Vault Bot <bot@…>`. Commits form locally before any
push, so the proxy cannot rewrite them — this is **documented in
`cmd/skill_cli.md` as agent guidance, with no proxy-side enforcement** (decided).

### Layer 3 — Agent Vault-side attribution (our audit trail)
The request log already records the agent/session per proxied call
(`internal/requestlog/`). For GitHub calls also surface the **human identity**
(`github_app_credentials.identity`) and a per-mint audit line (timestamp,
identity, resulting `expires_at`, success/fail, agent/session) — **never** the
token, secret, or refresh token (redact). UI shows the credential as
`identity@github (via <agent>)`.

---

## 10. Threat model

| Asset | Exposure to agent | Worst case if agent fully compromised |
|---|---|---|
| Client secret | **None** — DEK-encrypted, broker-only | Cannot be exfiltrated |
| Refresh token | **None** — DEK-encrypted, broker-only, memory-decrypted only at mint | Cannot be exfiltrated |
| App private key | **Not used / not stored** (user-to-server) | n/a |
| `ghu_` access token | Injected onto proxied requests; **memory-only, never persisted, never revealable** | While proxy access exists, traffic carries a short-lived token bounded by App-perms ∩ user-access ∩ branch rulesets; minting stops when the agent's session/token is revoked |

Reveal policy ([§15](#15-open-items) decided): the `ghu_` token is **never
revealable** (injection-only by construction). The **durable secrets** (client
secret / refresh token; and any future App private key) **may** be revealable to
a **vault member+ operator** per the user's direction — note this deviates from
the current OAuth client-secret sentinel-masking, so it's a deliberate policy
call to confirm in implementation.

---

## 11. Config / API / CLI surface

- **Env vars:** none at instance level (client id/secret are per-credential at
  connect). *(CLAUDE.md: if any env var is added, update `.env.example`,
  `docs/self-hosting/environment-variables.mdx`, `docs/reference/cli.mdx`.)*
- **HTTP:** `POST /v1/credentials/github/connect` + callback;
  `GET /v1/credentials/github/status`. Credentials list (`GET /v1/credentials`)
  shows `GITHUB_TOKEN` as a row tagged `type: dynamic`/`github` with `identity`
  and connection status — **no minting required to enumerate** (unlike Infisical,
  the key name is known from config), and value never shown.
- **CLI:** `agent-vault credential github connect|status`.
  *(CLAUDE.md: update flag tables in `docs/reference/cli.mdx`.)*

---

## 12. Failure modes

| Condition | Behavior |
|---|---|
| Token endpoint unreachable, cached `ghu_` still valid | Serve cached token (skew window) |
| Token endpoint unreachable, cache expired | Resolve fails → request errors; `last_mint_error` surfaced |
| GitHub 429 on exchange | Transient (`IsPermanentError`=false); back off; surface error |
| Concurrent requests, cold/expiring cache | Single-flight: one exchange shared (`oauth.Refresher`) |
| Rotated refresh-token write fails | Fail the mint; do not serve; keep old refresh token |
| Broker restart | Cache cold; first request mints from persisted refresh token |
| Refresh token revoked/expired | Distinct error → re-run `credential github connect`; set `last_mint_error` |
| App lacks expiring user tokens / is an OAuth App | Connect fails fast (no `refresh_token`) |

---

## 13. Implementation checklist

- [ ] Migration: `github_app_credentials` table.
- [ ] Store: `GetGitHubAppCredential`, `ListGitHubAppCredentials`,
      `SetGitHubAppCredential`, `UpdateGitHubRefreshToken`, `UpdateGitHubMintError`.
- [ ] `internal/github`: `Resolver` implementing `brokercore.DynamicCredentialResolver`
      — in-memory cache, single-flight via `oauth.Refresher`, persist-before-serve
      rotation, identity capture, error mapping. Takes the DEK.
- [ ] Composite `DynamicCredentialResolver` in `server.go` (GitHub then Infisical);
      keep the `lateDynamicResolver` late-binding pattern.
- [ ] Connect handler + callback (dedicated), GitHub preset, hard-require App
      (reject when no `refresh_token`), capture identity via `GET /user`.
- [ ] Verify `internal/oauth/oauth.go` sends `Accept: application/json`.
- [ ] CLI: `credential github connect|status`.
- [ ] Credentials list: enumerate `GITHUB_TOKEN` (no mint), value never shown.
- [ ] UI: render GitHub row as `identity@github (via <agent>)`.
- [ ] Service presets/docs: `api.github.com` (Bearer) + `github.com` (Basic x-access-token).
- [ ] `cmd/skill_cli.md`: GitHub credential usage + `Co-authored-by` trailer convention.
- [ ] Docs: `docs/learn/credentials.mdx`, `docs/learn/credential-stores.mdx`
      (dynamic-secrets framing), `docs/reference/cli.mdx`, a GitHub guide; scan `docs/`.
- [ ] Tests: rotation single-flight; persist-before-serve failure; revoked-token
      re-connect; no-refresh-token connect rejection; injection for both services;
      `ghu_` never persisted / never revealed.

---

## 14. Future: AWS / IAM (not in v1)

GitHub-specific now, but on the **shared `DynamicCredentialResolver` seam** — so
AWS (`aws-vault`-style short-lived IAM creds via `AssumeRole`/`GetSessionToken`
against a named profile) becomes another resolver in the composite. AWS STS has
**no rotating refresh token** (mint-and-expire, nothing durable to persist), so
it's an even more natural fit for this seam than GitHub. Keeping providers
concrete-but-on-one-seam is what lets AWS join without re-plumbing brokercore.

---

## 15. Resolved decisions & open items

**Resolved:**
1. `ghu_` tokens are **never revealable** (injection-only by construction).
   Durable secrets **may** be revealable to member+ operators (deviates from
   current sentinel-masking — confirm in implementation).
2. Co-author attribution is **convention only** (skill-documented), no
   proxy-side enforcement.
3. **One `GITHUB_TOKEN` per vault**, like any other service credential (the
   per-key model supports more, but the standard is one).
4. **Hard-require a GitHub App**; reject OAuth Apps at connect.
5. **No App private key (PEM) in v1.** The credential is **client id/secret +
   rotating refresh token** only. (Terminology: the "client id/secret + refresh
   tokens" flow is provided by a **GitHub App with expiring user tokens** — a
   bare OAuth App issues a single non-expiring `gho_` token with *no* refresh
   token, so it cannot back this model and is rejected per decision 4.)

**Open items:** none.
```

# Design: GitHub App installation credentials (Mode B — server-to-server)

Status: **Implemented** (backend + CLI + docs) on `feat/github-app-installation-credentials`.
This is the **alternative to Mode A** (user-to-server). It exists because an
empirical ruleset test showed Mode A's privilege fence doesn't hold; Mode B's
does. Scope: GitHub-specific.

---

## 1. Why this exists (the empirical finding)

We tested how GitHub rulesets resolve the actor for each token type against a
throwaway repo (`SpalkLtd/ruleset-actor-test`) with a protected `master`
(require-PR + required-check, admin-role bypass):

- **Mode A (user-to-server, `ghu_`)** — a direct commit to `master` **succeeded**;
  the audit log recorded `action: protected_branch.policy_override`,
  `actor: Prendo93`, `programmatic_access_type: GitHub App user-to-server token`,
  *"because Prendo93 is an admin"*. So Mode A **gates as the human** and inherits
  their privileges (admin bypass). The "exclude the App from the bypass list"
  fence **does not hold**. (Negative control: with no bypass, the same write was
  `409`.)
- **Mode B (installation, `ghs_`)** — per current GitHub docs, an installation
  token is **server-to-server**, "API requests made by an app installation are
  attributed to the app", and success "depends solely on the app's granted
  permissions, not on any user's access level". Rulesets can name a **GitHub App**
  in the bypass list (always / PR-only). So Mode B **gates as the App** — the
  include/exclude-the-App fence **does hold**.

**Trade-off:** Mode B gains a clean, human-independent privilege fence; it loses
*native* per-human attribution (actions show as `spalk-agent[bot]`). Attribution
is layered back via Agent Vault's request log + `Co-authored-by` trailers.

| | Mode A (`ghu_`, user-to-server) | **Mode B (`ghs_`, installation) — this** |
|---|---|---|
| Gates as | the human (inherits their bypass) | the **App** (its own perms + bypass membership) |
| Fence | rulesets **no-bypass for everyone** | exclude/include the **App** in bypass (even PR-only) |
| Attribution | human (native) | bot (layer per-human in AV logs + trailers) |
| Durable secret | client secret + rotating refresh token | **App private key (PEM)** — no rotation |
| Setup | browser OAuth consent | **non-interactive** (paste App id + installation id + PEM) |

---

## 2. Architecture

A `brokercore.DynamicCredentialResolver` (`internal/github`) mints **installation
access tokens on demand**: sign a JWT with the App private key → `POST
/app/installations/{id}/access_tokens` → `ghs_` token (~1h). The token is cached
**in memory only** and re-minted before expiry. The only durable secret is the
**App private key**, stored DEK-encrypted. **No refresh token, nothing rotates** —
even simpler than Mode A.

- `GITHUB` resolves through the existing dynamic fallthrough seam
  (`credential.go`), so the vault stays **builtin** and serves other domains
  concurrently. Composite resolver (`server.go` `lateDynamicResolver`): GitHub
  then Infisical.
- Token is **injection-only** (never persisted, never revealed); listed as
  `type: github`.

## 3. Data model

`github_app_installations` (migration 051): `vault_id`, `credential_key`,
`app_id`, `installation_id`, `private_key_ct/_nonce` (DEK), optional
`permissions_json` + `repositories` (token scoping), `app_slug` (captured from
`GET /app`; identity `<slug>[bot]`), `connected_at`, `last_mint_at`,
`last_mint_error`. No access token, no refresh token.

## 4. Mint flow (`internal/github`)

1. `Resolve(vaultID, key)` → load row; not configured → `ok=false`; no PEM →
   "not connected" error.
2. In-memory cache check (skew 5m); else single-flight (`oauth.Refresher`):
3. Decrypt PEM → `signJWT` (RS256, iss=app_id, exp ≤ 10m, PKCS#1/PKCS#8) →
   `POST /app/installations/{id}/access_tokens` (optional permission/repo scoping
   body) → cache `{ghs_, expires_at}`; stamp `last_mint_at`, clear error.
4. On failure record `last_mint_error`; return error (no token served).

`Connect` validation mints once + captures `app_slug` (`GET /app`).

## 5. Surface

- **HTTP**: `POST /v1/credentials/github/connect` (`app_id`, `installation_id`,
  `private_key`, optional `permissions`/`repositories`) — validates by minting,
  502 on mint failure, 400 on bad PEM; `GET /v1/credentials/github/status`.
- **CLI**: `agent-vault vault credential github connect
  --app-id --installation-id --private-key-file [--permissions --repositories]`
  and `... github status`.
- **Injection**: wire `GITHUB` into two services — `api.github.com` (Bearer) and
  `github.com` (Basic `x-access-token`) — covering `gh` and `git`-over-HTTPS.
- **Least privilege**: `--permissions`/`--repositories` scope the minted token
  below the installation's full grant.

## 6. Threat model

The agent never holds the **App private key** (DEK-encrypted, broker-only) and
loses minting the moment proxy access is revoked. The minted `ghs_` is
memory-only, injection-only, ~1h. Effective power = the App installation's
permissions ∩ any `--permissions` subset, fenced server-side by rulesets that
include/exclude the App. **Operator guidance:** install the App with **least
privilege** (e.g. Contents: Write, not admin) and add/omit it from protected-
branch bypass to control direct pushes — this fence is empirically sound for
Mode B (unlike Mode A).

## 7. Attribution (bot + human, layered)

- **GitHub side**: actions attribute to the **App/bot** (`<slug>[bot]`).
- **Per-human**: Agent Vault's request log records the agent/session that minted
  each call; agents add `Co-authored-by` trailers so the human is visible on the
  commit/PR. (Documented in `cmd/skill_cli.md`.) This is the inverse of Mode A,
  where the human is native and the bot is layered.

## 8. Testing — TDD red/green throughout

Every unit was written test-first (red) then implemented (green):
JWT signing (`signJWT`, PKCS#1/#8, verify against pubkey), store CRUD + DB-error
paths, resolver mint/cache/single-flight/scoping/eviction/validate, and the
connect/status handlers (validation, auth, external-store, mint-failure, faults).
A typed-nil `*bytes.Reader` bug and an `ed25519.GenerateKey` arg-order bug were
both caught red by tests before fix. Error tests assert the **specific** failure
(wrapped substrings / `jsonError` bodies / redirect messages).

Coverage: **all reachable statements covered**; residual is genuinely
unreachable defensive code (`json.Marshal` of trivial maps, `rsa.Sign` with a
valid key, `fetchAppSlug` request errors the same-host mint preempts, the
`NOT NULL` List-scan guard).

## 9. Deferred

- Web UI rendering of the GitHub row.
- Auto-created service presets (documented; operator wires the two services).
- Resolving `installation_id` from org/repo at connect (operator supplies it).

## 10. Implementation checklist

- [x] Migration `051_github_app_installations.sql`; store CRUD + meta/mint-error.
- [x] `internal/github`: RS256 JWT, installation-token mint, cache, single-flight,
      scoping, `Validate` (slug capture), `Enumerate`, `EvictVault`.
- [x] Composite resolver wiring; connect/status handlers + routes; credentials
      list `type: github` (value never shown).
- [x] CLI `credential github connect|status`.
- [x] Docs: `docs/learn/credentials.mdx`, `docs/reference/cli.mdx`,
      `cmd/skill_cli.md` (bot attribution + `Co-authored-by`).
- [x] Tests (TDD): jwt, store, resolver, handlers; full suite + vet green.

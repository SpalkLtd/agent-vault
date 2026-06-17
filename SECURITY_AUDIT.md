# Security Audit — Agent Vault

**Date:** 2026-06-17
**Scope:** Full codebase (`~31k` LOC, 21 internal packages) — credential brokering, MITM proxy, KEK/DEK crypto, software CA, OAuth, proposals, container isolation.

## Method

A multi-agent audit run as a `Map → Find → Verify → Synthesize` workflow (37 agents total):

1. **Map** — attack-surface + threat-model orientation.
2. **Find** — 11 expert finders, one per security dimension (authn/session, authz/RBAC, proposal integrity, crypto-at-rest, credential leakage, MITM/SSRF, netguard egress, injection, web/API, OAuth, DoS/rate-limit).
3. **Verify** — every candidate finding independently re-checked by **two adversarial verifiers**: one for code-correctness (re-reads the cited code, defaults to skeptical), one for real-world exploitability (builds the concrete attack path against the threat model).
4. **Synthesize** — consolidation + a completeness critic that names what was missed.

The top findings were then re-verified by hand against live code, including **running the netguard logic** to empirically confirm the SSRF gaps.

**Result:** 12 candidate findings → **11 confirmed, 1 disputed, 0 refuted.** Every finding carries a verbatim `file:line` citation.

## Threat model

Adversaries, in priority order (used to judge exploitability):

| | Adversary | Must not be able to |
|---|---|---|
| A1 | Malicious/compromised AI agent (talks to broker API + proxy) | See raw credentials, edit creds/services directly, escalate role, bypass proposal approval |
| A2 | Low-privilege actor (instance `no-access`, vault `proxy`) | Perform member/admin/owner actions, read other vaults |
| A3 | Network attacker abusing the MITM proxy | SSRF to internal/metadata endpoints, escape container egress |
| A4 | At-rest attacker with disk/volume access | Recover credentials, CA key, or DEK |
| A5 | Secret leakage | Obtain credentials via logs/telemetry/responses/diffs |

---

## Findings

### 🔴 HIGH — SSRF to broker localhost via IPv6 unspecified address `::`

**`internal/netguard/netguard.go:105-124`**

The private/reserved blocklist (`privateRanges`) includes IPv4 `0.0.0.0/32` but **omits IPv6 `::/128`**. On Linux/macOS a TCP connect to `::` routes to `[::1]` (loopback) exactly the way `0.0.0.0` routes to IPv4 loopback. Because `isBlockedIP(::, allowPrivate=false, nil)` returns `false`, a proxy-role agent (lowest privilege) can send an absolute-form forward request `POST http://[::]:14321/... HTTP/1.1` through the proxy and reach the broker's **own control-plane API and any localhost-bound service** — defeating the default-on (`AGENT_VAULT_ALLOW_PRIVATE_RANGES=false`) loopback fence. The IPv4 equivalent *is* blocked, making this a clear asymmetric gap.

**Adversary:** A1 (malicious agent) / A3 (network attacker with proxy access). No special config; works in the default network-exposed deployment.

**Exploit chain (verified):** `forward.go:103` (`host = r.URL.Hostname()` → `"::"`) → `isValidHost("::")` returns true (`brokercore.go:55-65`) → unmatched-host policy defaults to passthrough → outbound dial uses `netguard.SafeDialContext` (`proxy.go:84`), which does not block `::`.

**Empirically confirmed:**
```
isBlockedIP(0.0.0.0, allowPrivate=false) = true
isBlockedIP(::,      allowPrivate=false) = false   ← the bug
```

**Also affects** `ws://`/`wss://` upstreams: `dialWebSocketUpstream` (`internal/mitm/websocket.go:161`) uses the same `p.upstream.DialContext`.

**Fix:** Add `parseCIDR("::/128")` to `privateRanges`. More robustly, replace the hand-maintained list with `ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()` plus the IMDS/CGN literals, so new unspecified/reserved forms are covered without enumeration.

---

### 🟠 MEDIUM — Cloud-metadata SSRF guard is incomplete (AWS ECS + Alibaba reachable)

**`internal/netguard/netguard.go:95-100, 137-160`** *(two independent finders converged here)*

The netguard docstring (line 18) and the operator docs promise cloud metadata endpoints are *"blocked regardless of this setting."* In reality only `169.254.169.254` and `fd00:ec2::254` are in the unconditional `alwaysBlocked` set. `isBlockedIP` short-circuits with `if allowPrivate { return false }` **before** consulting `privateRanges`. So when an operator sets `AGENT_VAULT_ALLOW_PRIVATE_RANGES=true` (documented, common for reaching internal upstreams in container/dev/PaaS deploys):

- **AWS ECS/EKS task-role credential endpoint `169.254.170.2`** (target of `AWS_CONTAINER_CREDENTIALS_*`, serves live signed IAM creds) — reachable.
- **Alibaba Cloud IMDS `100.100.100.200`** (RAM STS creds) — reachable.

Both fall only in `privateRanges` (`169.254.0.0/16` and `100.64.0.0/10`), which is skipped under `allowPrivate`.

**Adversary:** A1 / A3. Precondition: `AGENT_VAULT_ALLOW_PRIVATE_RANGES=true` + the corresponding cloud platform.

**Empirically confirmed (`allowPrivate=true`):**
```
169.254.169.254 blocked = true    (AWS/GCP/Azure IMDS — correctly protected)
169.254.170.2   blocked = false   (AWS ECS task-role creds — reachable)
100.100.100.200 blocked = false   (Alibaba IMDS — reachable)
```

**Fix:** Move the full metadata/credential set into `alwaysBlocked` (before the `allowPrivate` short-circuit): add `169.254.170.2/32`, `100.100.100.200/32`; consider blocking all of `169.254.0.0/16` unconditionally (no legitimate upstream is link-local). Correct the docstring/docs to match actual coverage. Also evaluate the NAT64-mapped form `64:ff9b::a9fe:a9fe` which evades the IPv4 CIDR match.

*(A third finder reported the Alibaba-only subset of this as a separate LOW; it is the same root cause and is folded in here.)*

---

### 🟠 MEDIUM — MITM CONNECT tunnels have no concurrency cap (authenticated DoS)

**`internal/mitm/connect.go:50-156`**

`handleConnect` authenticates, then hijacks the connection and serves an `http.Server` over a one-shot listener for the tunnel lifetime. The only establishment-time rate check is a **read-only** `TierAuth` peek, and `TierAuth` records budget **only on auth failure**. A CONNECT with a *valid* proxy token therefore consumes zero rate-limit budget. The `TierProxy` token-bucket + per-scope concurrency semaphore (`EnforceProxy`) is enforced only inside `forwardRequest` — i.e. per *in-tunnel request* — and never bounds the number of simultaneously-open tunnels. There is no `netutil.LimitListener`, no max-connection cap, and the global in-flight cap (`TierGlobal`) is wired only onto the control-plane server (`server.go:775`), **not** the MITM proxy (`cmd/server.go:196`).

**Adversary:** A1 / A2 with any valid proxy-role token (the lowest vault role). Open thousands of concurrent CONNECT tunnels; each pins an fd + goroutine + TLS state → proxy resource exhaustion, degrading credential-injection availability for all tenants.

*(Verifier correction: an idle tunnel that never sends headers is reaped at ~`ReadHeaderTimeout` (10s) / `ReadTimeout` (60s), not the 2m `IdleTimeout` the finder claimed. The core defect — unbounded concurrent tunnel count — stands.)*

**Fix:** Acquire a per-`(actor,vault)` and/or per-IP concurrency slot at establishment (before `Hijack()`), released when `ConnState` reaches `StateClosed`; wrap the proxy listener in `netutil.LimitListener` or add a global in-flight semaphore analogous to `TierGlobal`.

---

### 🟡 LOW

#### Proxy-role actor can enumerate all human emails + vault roles
**`internal/server/handle_vaults.go:269-316`** — `handleVaultUserList` is gated only by `requireVaultAccess` (admits any vault role, including `proxy` and scoped-session agents). It returns every active human user's raw email + vault role, plus pending-invite emails. This is inconsistent with the sibling `handleListScopedSessions`, which deliberately requires member+ precisely because emails are *"more identifying than what a proxy-only caller should see."* Recon/PII disclosure for A1/A2. **Fix:** gate at `requireVaultMember`.

#### OAuth `token_url`/`authorization_url` accept plaintext `http://`
**`internal/server/handle_oauth.go:557-560`** — `isValidHTTPURL` accepts `http://`. A member-configured plaintext `token_url` causes the `client_secret`, auth code, refresh token, and issued access token to be sent in cleartext, recurring on every unattended refresh (`brokercore/credential.go:290-298`). Requires member misconfig + network attacker (A3/A5). **Fix:** require `https://` (allow loopback for dev override only).

#### Synchronous SMTP send has no conversation deadline
**`internal/notify/notify.go:112-141`** — Only the initial dial has a 10s timeout; the EHLO/STARTTLS/AUTH/MAIL/RCPT/DATA exchange has no `SetDeadline`. On unauthenticated endpoints (`/register`, `/resend-verification`, `/forgot-password`) a slow/half-open relay blocks the request goroutine and holds a `TierGlobal` in-flight slot (cap 512) until OS TCP timeout. Distributed-IP DoS amplifier (A1/A3). **Fix:** set a deadline for the whole SMTP conversation, or send async via a bounded worker pool.

#### 7-day proposal TTL not enforced on the approve path
**`internal/server/handle_proposals.go:411-414, 635`** — Expiry is lazy (only `handleAdminProposalList` calls `ExpirePendingProposals`; no background sweep). The approve handler only checks `Status != "pending"` and never compares `CreatedAt`. A proposal older than 7 days that was never surfaced via the list endpoint stays approvable. Hygiene gap — approval still requires a member+ human, so not agent-exploitable. **Fix:** enforce TTL at apply time.

#### OAuth token-exchange error reflected into redirect URL
**`internal/server/handle_oauth.go:232-234`** — On exchange failure, the verbatim upstream token-endpoint response body is `Sprintf`'d into the user-facing 302 `message=` param → lands in browser history, Referer, intermediary logs. Conditional on a member-configured reflective/hostile endpoint (A5). **Fix:** return a generic message to the browser; log the detailed `TokenError` server-side only.

---

### ⚪ INFO

#### A member/admin-role agent can self-approve its own proposals
**`internal/server/server.go:710-737`** — `requireProposalReview` blocks only `proxy`-role actors; any member/admin actor (including an agent) passes, and the approve handler never compares the approving actor against the proposal's creator. The "agents cannot self-approve" invariant rests **entirely** on agents defaulting to `proxy` (`handle_agents.go`). If a human ever grants an agent member/admin vault role, that agent can create and immediately approve+apply a proposal with no human in the loop. Safe by default; reported as defense-in-depth hardening. **Fix:** reject approval when approver == creator, and/or gate `requireProposalReview` on `actor.Type == "user"`.

#### Verification/password-reset codes written to server stderr
**`internal/server/handle_auth.go:55-62, 405-411`** — When SMTP is unconfigured or a send fails, the 6-digit codes are printed to stderr as the intended operator fallback. They never appear in API responses, are short-lived (15m TTL) and guess-capped (10 attempts). Only relevant if log streams are aggregated to a SIEM (A5). **Fix (optional):** gate the stderr dump behind an explicit dev/operator flag.

---

### ⚖️ DISPUTED — No `Cache-Control: no-store` on credential-reveal responses
**`internal/server/respond.go:10-14`** — Verifiers split 1/1. Factually accurate: the reveal path emits plaintext credential values via `jsonOK`, which sets no cache headers; only the SPA handler sets `no-store`. However, the endpoint is member+ gated (agents blocked), Bearer-auth responses are not cacheable by compliant shared caches (RFC 7234), and the adversary does not control the cache. Real defense-in-depth hardening, not an adversary-reachable flaw. **Recommendation:** add `Cache-Control: no-store` to credential-reveal responses regardless.

---

## Coverage gaps (recommended follow-up)

The completeness critic flagged these subsystems as audited only shallowly or not at all. A second targeted pass is recommended:

1. **WebSocket credential substitution** (`internal/mitm/websocket.go`) — frames > 1 MB stream through *without* substitution (`maxWSSubstitutionPayload`); check whether an agent can shape payloads to observe/leak the injected credential across frame boundaries, and the frame-parsing/masking surface.
2. **Infisical integration** (`internal/infisical/`) — an entire credential-source subsystem (dynamic-secret leases, machine-identity auth, secret sync) with zero findings. Check lease-value leakage via errors, orphan-lease revocation, and whether its outbound client is subject to netguard.
3. **Proposal merge content boundary** (`internal/proposal/merge.go`, `validate.go`) — can a crafted proposal smuggle role/grant changes, target a different vault, or set a service `Host` to an internal address that later bypasses netguard?
4. **At-rest crypto lifecycle** (`internal/crypto/`, `internal/auth/auth.go`, `internal/store/sqlite.go`) — GCM nonce uniqueness across all `*_nonce` columns, passwordless DEK-plaintext file permissions, the password-change re-wrap path.
5. **Rate-limiter as DoS amplifier** (`internal/ratelimit/registry.go`, `key.go`) — the per-key registry is an unbounded map keyed partly on attacker-controlled email/IP; check eviction.

---

---

# Round 2 — Deep dive (5 under-covered subsystems)

A second `Find → Verify → Synthesize` workflow (49 agents, 2 finders × complementary angles per subsystem) targeting the gaps from Round 1. **19 candidates → 11 confirmed, 1 disputed, 7 refuted.** The 7 refutations included a *latent* WS netguard-bypass (unreachable in prod), a claimed int64-overflow (the guard is present and correct), and a claimed proposal scope-escape (correctly prevented) — i.e. the adversarial verifiers killed several plausible-but-wrong findings.

### 🔴 HIGH (critical-class) — Proposal merge silently relocates a credential-injecting substitution onto an attacker-changed host, invisible in the approval diff

**`internal/proposal/merge.go:55-62`**

The merge "exists" branch rebuilds a service entirely from the proposal (`toBrokerService(p)` — Host, Path, Port, Auth) but, when the proposal omits `Substitutions`, **re-attaches the existing service's substitutions** to the new host:
```go
case exists:
    next := toBrokerService(p)
    if len(p.Substitutions) == 0 {
        next.Substitutions = merged[idx].Substitutions   // ← carried onto attacker's Host
    }
    merged[idx] = next
```
Substitutions inject *decrypted credential values* into the outbound request to the service Host (`brokercore/credential.go:225-241`, applied even for `passthrough` auth, matched by `Host`). The approval UI renders **only the proposal's own stored services JSON** (`handle_proposals.go:95, :320` → `json.RawMessage(cs.ServicesJSON)`; `ProposalPreview.tsx:248`), so a proposal that omits substitutions shows the reviewer **no credential injection**. The apply path (`handle_proposals.go:528-536`) runs `MergeServices` → `ApplyProposal` with **no re-validation**.

**Exploit (verified end-to-end against live code):** A proxy-role actor (the minimum role to create proposals — A1/A2) submits a `set` proposal reusing an existing credential-injecting service's Name (e.g. `twilio`), changing `Host` to an attacker-reachable host, `auth: passthrough`, and **no substitutions**. Create-time validation passes (no subs declared). The reviewer approves a diff showing only a host/auth change. At apply, the existing `TWILIO_AUTH_TOKEN` substitution is re-attached to the attacker host; the agent then sends a request through the proxy and the broker injects the decrypted token into the request to the attacker host — **a raw credential exfiltrated past human approval**, defeating the two core invariants.

**Severity note:** Verifiers split critical/high. The mitigating factor is the reviewer *does* see the host change (just not the rider credential); the precondition is an existing substitution-based credential + name reuse. Rated **HIGH, critical-class** — with a plausible-looking host (subdomain/typosquat) this is a clean approval bypass.

**Fix:** (a) when a `set` changes Host/Path/Port/Auth, require substitutions to be re-declared explicitly (drop the implicit-preserve for full replacements); **or** (b) render the *effective post-merge* service (with preserved substitutions + credential keys + destination host) in the approval UI. Additionally, re-run `proposal.Validate` / `broker.Validate` / `ValidateCredentialRefs` on the **merged** result inside `handleAdminProposalApprove`.

### 🟠 HIGH — Sliding-window rate limiter ignores `maxKeys` under distinct-key sprays (limiter-as-DoS)

**`internal/ratelimit/sliding.go:98-104` (and `138-144`)** *(both ratelimit finders converged)*

The sliding-window limiter (the algorithm backing `TierAuth` — the **unauthenticated** surface: login, register, forgot/reset, verify, **and the no-auth invite-token / approval-token endpoints**) only evicts a key when its *most recent* attempt is already outside the window:
```go
if l.maxKeys > 0 && len(l.attempts) > l.maxKeys {
    for k, v := range l.attempts {
        if len(v) == 0 || v[len(v)-1].Before(cutoff) { delete(l.attempts, k) }
    }
}
```
Under a fresh-key spray every key's last attempt is `now` (always `After(cutoff)`), so **nothing is ever evicted** — `maxKeys` (default 10000) is a no-op. The token-bucket (`bucket.go:121-137`) and keyed-semaphore (`semaphore.go:147-159`) both have an *unconditional* fallback eviction; the sliding window is the only one lacking it, despite its comment claiming otherwise.

Keys are attacker-controlled and unauthenticated: `ipt:<ip>:<sha256(token)>` from `GET /v1/users/invites/{token}/details` and `GET /v1/proposals/approve-details?token=` (`server.go:914,924`, `key.go:35-43`). Varying the token mints unlimited never-evicted entries. **Empirically confirmed:** with `maxKeys=100`, 100 000 distinct keys left a 100 000-entry map (1000× overshoot), and per-request cost grows O(n) as the map balloons (CPU amplification on top of memory). Throttled but not bounded by the global RPS ceiling.

**Severity note:** one verifier said medium (growth is throttle-bounded to ~tens of MB at default RPS, not instant OOM); the other said high (unauthenticated, nullifies a safety cap, CPU amplification). Rated **HIGH**.

**Fix:** add the same unconditional fallback eviction the sibling limiters have (evict oldest-by-recent-timestamp until `len ≤ maxKeys`), in both `allow()` and `check()`. Also validate token shape and cap the `email:` key length before recording.

### 🟡 LOW

- **WebSocket return leg has no credential scrubbing** — `internal/mitm/websocket.go:305-323`. Substitution is asymmetric: the client→upstream goroutine injects the credential (`copyWSFramesWithSubstitution`), but the upstream→client goroutine is a blind byte copy (`copyWithIdleTimeout`). If an approved upstream **reflects/echoes** a frame the agent sent (common for chat/realtime APIs), the field the proxy rewrote to the real credential is echoed back and the agent (A1) receives it. Conditional on a reflecting upstream; consistent with the broker's existing HTTP-body trust model, but a long-lived WS to an echo endpoint is a far more natural exfil channel. **Fix:** document that WS/body substitution must target non-reflecting upstreams (surface in approval UI); optionally scrub resolved values back to placeholders on the inbound leg.
- **Apply path performs no re-validation of merged services** — `internal/server/handle_proposals.go:528-536`. The enabling weakness behind the HIGH merge finding; independently a defense-in-depth gap. **Fix:** run `broker.Validate` + `ValidateCredentialRefs` on the merged config before `ApplyProposal`.
- **AES-256-GCM used with no AAD binding** — `internal/crypto/crypto.go:29, 45`. `Seal`/`Open` pass `nil` additionalData, and the single DEK encrypts *every* at-rest category (credentials, OAuth tokens/secrets, sentinel, CA root key). Nothing binds a ciphertext to its row/column/purpose, so all `(ciphertext, nonce)` pairs are interchangeable: an A4 attacker who can *write* the store (without the DEK) can relocate any blob into any slot and it decrypts as a valid credential. Confidentiality intact; per-location integrity is not. **Fix:** add an AAD parameter and bind `domain ‖ vault_id ‖ key ‖ column` at every call site.
- **`-wal`/`-shm` sidecar files not chmod-corrected on Open** — `internal/store/sqlite.go:78-101`. Open forces the main `.db` to `0600` but leaves pre-existing WAL/SHM sidecars untouched; a `-wal` left at `0644` (prior run / restored backup) survives and contains the same credential ciphertexts and the `master_key` row (incl. `dek_plaintext` in passwordless mode). Empirically confirmed (A4). **Fix:** `os.Chmod` the `-wal`/`-shm` files to `0600` after Open.
- **`clientIP` returns attacker-controlled `X-Forwarded-For` verbatim** — `internal/server/handle_auth.go:578-587`. With `AGENT_VAULT_TRUSTED_PROXIES` set, the right-most XFF entry is used unparsed as the `ip:` limiter key and session `LastIP`, letting an attacker mint unlimited `ip:` keys (amplifies the HIGH limiter finding) and rotate past the per-IP login throttle. **Fix:** `net.ParseIP`-validate the selected hop, fall back to `RemoteAddr`.

### ⚪ INFO

- **WebSocket substitution is fail-open** — `internal/mitm/websocket.go:429-462`. Fragmented (FIN=0), compressed (RSV1), non-text, or >1 MB frames stream through with the literal placeholder, never substituted; an agent fully controls these bits. **No leakage** (substitution is outbound-only; the bypass produces no secret bytes) — the only effect is an agent sabotaging its *own* request's auth. Reported as a robustness/fail-closed policy question. *(See residual gap below: a `permessage-deflate` handshake sets RSV1 on every frame → connection-wide bypass.)*
- **Infisical outbound HTTP bypasses netguard** — `internal/infisical/client.go:94-117, 272-278`. The Infisical SDK transport and the project-slug `http.Client` use default transports (no `SafeDialContext`), unlike every other outbound path. Destination is operator/owner-controlled (not adversary-chosen), so it's defense-in-depth, but a typo'd `INFISICAL_URL` → metadata/internal IP isn't caught, and redirects toward private IPs are followed. **Fix:** wire `netguard.SafeDialContext` into the slug client; validate `INFISICAL_URL`'s resolved IP at startup.
- **Proposal content validated only at create time, not at apply** — `internal/server/handle_proposals.go:528`. Not a scope-escape (no authority fields cross the boundary; stale cred refs fail closed at proxy time), but a benign create-vs-apply TOCTOU. Optional hardening.

### ⚖️ DISPUTED — Plaintext DEK persists in freed SQLite pages / WAL after master-password set

**`cmd/master_password.go:68-85`, `internal/store/sqlite.go:80`** — In passwordless mode the 32-byte DEK is stored verbatim in `master_key.dek_plaintext`. `master-password set` clears it with a plain `UPDATE`, but SQLite is opened `journal_mode=wal` with **no `secure_delete` pragma** and there is no `VACUUM`, so the old plaintext DEK can remain carved in freed b-tree pages / the `-wal` file indefinitely (the single `master_key` row rarely sees page reuse). Verifiers split (the residue's reachability requires A4 disk access *and* the row to actually be freed/reused). The Round-2 completeness critic strengthens it: the **`master-password remove`** path (`cmd/master_password.go:211-214`) *writes* a fresh plaintext DEK and never `WipeBytes` the in-memory copy — strictly worse, and an undisputed missing-wipe bug. **Fix:** enable `PRAGMA secure_delete`, `VACUUM` after the master-key transition, and `crypto.WipeBytes` the in-memory DEK copy on the remove path.

### Residual gaps (Round 2 completeness critic — recommended for a Round 3 if desired)

1. **`permessage-deflate` → connection-wide WS substitution bypass** — the handshake `Sec-Websocket-Extensions` is copied through (`websocket.go:48`); if the upstream negotiates compression, every text frame is RSV1-set and substitution is disabled for the *whole* connection (not just per-frame). Check whether the proxy strips `permessage-deflate` when subs are present (it appears not to).
2. **CA root key shares the AAD-less DEK across trust domains** — `internal/ca/soft.go:185,234`; the CA-key blob and credential blobs are mutually substitutable, and the on-disk CA key file is outside the SQLite at-rest analysis.
3. **Limiter `check()` peek path mutates the map** — `sliding.go:112-147`; the MITM pre-gate `Check()` inserts an empty slice for a fresh key (grow vector) while never appending, so a spoofed-XFF spray through the proxy port grows the map under `max` permanently.
4. **Infisical: stale-but-valid secrets served when sync fails** (`sync.go:184-248`, `dueAt` bumps `last_synced_at` on failure) and **dynamic-secret name-enumeration oracle** via longest-prefix `matchDynamicKey` (`dynamic.go:191`).
5. **Intra-proposal multi-op-same-name ordering** — the diff is rendered per-element, not as the applied fold (`merge.go:38-68` vs the diff renderer); the twin of the HIGH merge finding on the ordering axis.

---

# Round 3 — Residual-gap verification (final)

A focused workflow (12 agents) testing the 5 residual hypotheses from Round 2 as confirm-or-refute. **3 candidates → 3 confirmed, 0 disputed; 3 of the 5 hypotheses cleanly refuted.**

**Cleanly refuted (no finding):**
- *permessage-deflate disables WS substitution connection-wide* — the proxy's handling does not produce the claimed connection-wide bypass / adversary benefit.
- *Limiter `check()` peek path mutates the map* — not a second unbounded-growth vector beyond the Round-2 `allow()` finding.
- *Infisical stale-secret serving + dynamic-secret name-enumeration oracle* — no exploitable staleness or enumeration leak.

### 🟠 MEDIUM — CA root key is extractable via the credential-reveal endpoint (nil-AAD confused deputy)

**`internal/crypto/crypto.go:29,45` · `internal/ca/soft.go:185,234` · `internal/server/handle_credentials.go:154,188-193`**

A concrete escalation built on the Round-2 nil-AAD finding. The CA root ECDSA private key is sealed with the **same** `crypto.Encrypt` under the **same** DEK (`soft.go:234`; `ca.New(masterKey,…)` at `cmd/server.go:191`, where `masterKey` is `MasterKey.Key()` = the DEK) as credential rows — confirmed by inspection. Because GCM uses `nil` AAD, a CA-key `(ciphertext, nonce)` blob and a credential blob are byte-for-byte interchangeable. An attacker with **A4 raw store write** + an **authenticated vault member** account can copy the `ca.key.enc` blob into a `credentials` row and call `GET /credentials?reveal=true`; the reveal handler decrypts with the DEK and returns `string(plaintext)` verbatim — i.e. the **DER-encoded CA root private key**, a key no API ever exposes. With it the attacker mints leaf certs every agent trusts → full MITM impersonation of all upstreams.

**Severity note (high→medium):** verifiers downgraded because (1) it needs *both* DB-write and a member account (no API injects chosen ciphertext — both create and proposal paths encrypt server-side), and (2) in *passwordless* mode an A4 attacker already has the plaintext DEK on the same volume and can decrypt the CA key directly, making the oracle redundant. It is a genuine, non-redundant escalation specifically in **password-protected** mode (on-disk DEK is KEK-wrapped, so the live server's in-memory DEK via the reveal oracle is the only at-rest route to the CA key). The converse (forging the CA by swapping a blob in) does **not** work — `x509.ParseECPrivateKey` fails and the CA load errors out.

**Fix:** add domain-separating AAD to `crypto.Encrypt/Decrypt` (or HKDF per-purpose subkeys) — bind the CA key with `"agent-vault/ca-root-key/v1"` and credentials with `"agent-vault/credential"‖vaultID‖key`. GCM then rejects any blob opened in the wrong slot. (This also closes the Round-2 "blob interchangeability" LOW generally — a single mechanical change to two functions + ~15 callers.)

### 🟡 LOW — Apply-time proposal re-normalization isn't re-validated → two-op same-name fold diverges from the rendered diff

**`internal/server/handle_proposals.go:520-528`**

Duplicate names *within* a proposal are blocked at **create** (`validate.go:66-69`, empirically confirmed). But **apply** re-runs `normalizeProposalServices` against *current* vault state and calls `MergeServices` **without** re-running `Validate`. If an intervening privileged mutation makes one stored entry's Name stale, `adoptByHost` (`handle_services.go:121-132`) rebinds it to the existing service at the same `(Host,Path,Port)`, producing two same-Name entries; `MergeServices` folds them last-write-wins and splices the first op's substitutions onto the survivor. The approval UI renders the per-element stored slice, so the approver never sees the folded `(token, substitution)` pairing. **Empirically reproduced end-to-end** by the finder. **Impact is bounded** (hence not the HIGH merge class): `adoptByHost` only collides entries at the *identical* host, so the credential still flows only to the already-approved upstream — an approval-integrity/diff-fidelity defect, not credential disclosure or cross-host exfil, and it requires an independent privileged mutation racing an admin approval (not agent-controllable). **Fix:** re-run `proposal.Validate` (or a duplicate-name check) on the re-normalized services at apply, 409 on collision; render the approval UI from the merged fold.

### ⚪ INFO — CA key file & SQLite store lack secure-delete/zeroization

**`internal/ca/soft.go:376-390` · `internal/store/sqlite.go:80`** — `writeAtomic` replaces the CA key file without overwriting old blocks; the DSN enables WAL but not `secure_delete`, so rotated CA-key and credential ciphertext lingers in free pages. Informational only — residue is undecryptable ciphertext without the DEK; relevant as forward-secrecy hardening after a future DEK compromise (A4). **Fix:** `PRAGMA secure_delete`, overwrite-before-rename on CA rotation.

---

## Final coverage assessment

After three rounds (98 agents total), the completeness critic's verdict — which I concur with:

- **Well-covered priority adversaries:** A1 (malicious agent — no raw creds, no direct edits, proposal-gated; the HIGH merge exfil was the key break), A2 (RBAC/escalation), A4 (at-rest — incl. the nil-AAD findings), A5 (leakage — the request-log/telemetry paths were checked and are metadata-only/clean by design).
- **The one real residual gap — A3 strong-isolation:** `internal/isolation/` (the iptables egress lockdown for `container` mode — `assets/init-firewall.sh`, `entrypoint.sh`, the gateway/forwarder, and the content-hash image cache) was **never opened** in any round. Rounds 1–2 covered SSRF/netguard on the *cooperative* proxy path, not the iptables enforcement that backs the "non-cooperative isolation" promise. Worth a dedicated pass: rule-ordering/default-policy races at container start, `host.docker.internal` gateway as an escape path, and image-cache poisoning.
- **Minor note (not a finding):** telemetry ships `agent_name` (command basename) and `vault` name in cleartext to the telemetry endpoint (`internal/telemetry/`) — low-sensitivity, but worth a glance at opt-out behavior if vault names are considered sensitive.

Everything else is at diminishing returns. **Recommended next step (if continuing): one focused pass on `internal/isolation/`.**

---

# Final pass — Container isolation egress enforcement (`internal/isolation/`)

The A3 strong-isolation gap. A workflow (41 agents, 6 finders) attacking the "non-cooperative isolation" promise as a malicious agent inside the container. **17 candidates → 6 confirmed, 7 disputed, 4 refuted.** Most disputed/info results are *positive soundness confirmations* — the isolation core largely holds (see below).

### 🟠 MEDIUM — Image cache trusts any local tag → pre-seeded weaker image defeats isolation (cache poisoning)

**`internal/isolation/image.go:57-60, 80-82`** *(two finders converged)*

`EnsureImage` derives a deterministic tag `agent-vault/isolation:<12-hex asset-hash>` and decides whether to build solely via `imageExists` — which is just `docker image inspect <tag>` succeeding. **Confirmed by inspection:** there is no label/RepoDigest/provenance check binding the cached image *content* to the embedded assets. The tag is not a secret (it's hashed from assets shipped in the binary and hard-pinned in `image_test.go`). Any actor who can reach the same Docker daemon before the victim's first container run — a **co-tenant on a shared daemon, a prior CI step, or the malicious agent itself during an earlier `host`-mode session** — can `docker tag evil agent-vault/isolation:<hash>`. The next `vault run --isolation=container` skips the build and runs the planted image, whose `entrypoint.sh` can simply no-op `init-firewall.sh` → fully open egress (internet, `169.254.169.254`, host services), completely defeating the isolation promise. No race needed; the planted tag persists.

The content-hash naming gives false assurance: the hash binds the *name* to the assets, but nothing binds the *cached content* to the assets it claims to represent. **Compounding (from disputed/info findings):** the hash is truncated to 48 bits, and every build also applies a second mutable `:latest` alias — both widen the poisoning surface.

**Severity:** MEDIUM — requires local docker-daemon access to plant the image (on a single-user laptop the daemon is already in the trust boundary; the real scenarios are shared/CI daemons and the cross-mode agent-plant). **Fix:** bake `LABEL agent-vault.assets-sha256=<full-hash>` into the Dockerfile and require `docker image inspect` to report that exact full-length label (rebuild on mismatch); or build unconditionally and rely on Docker's layer cache; use the full 32-byte hash; drop the `:latest` alias.

### 🟡 LOW

- **Forwarder binds `0.0.0.0` on Docker Desktop (macOS/Windows) → host-LAN exposure** — `internal/isolation/gateway.go:24-32`. `HostBindIP` returns `0.0.0.0` on darwin/windows, so the relay listeners fronting the broker REST API **and** the MITM proxy are reachable from the host's LAN, not just the container. The relays are raw TCP with no source filtering; unauthenticated endpoints (`/health`, `/v1/status`, register/login) and a proxy-token-guessing oracle are exposed to a LAN-adjacent attacker during a run (ephemeral port, trivially scannable). Not a container-egress escape (a valid vault scope still needs a token), but it widens exposure beyond "exactly the container." **Fix:** bind `127.0.0.1` on Docker Desktop and rely on gateway forwarding; require `Proxy-Authorization` on the HTTP relay too.
- **All container egress is laundered as `127.0.0.1`, defeating the proxy's auth-failure rate limit for the contained agent** — `internal/isolation/forwarder.go:111-131`. The forwarder dials the broker over loopback (load-bearing, to keep `isLoopbackPeer()` true), so a malicious agent's proxy-auth guesses and REST calls arrive as loopback and are **exempt from the `TierAuth` budget** (`connect.go:55,164`) and bucketed under a single `ip:127.0.0.1` key. The mode treats the workload as fully malicious, yet the rate-limiter explicitly exempts it — removing the anti-brute-force/DoS layer against exactly the adversary the mode contains. Token entropy makes a real cross-vault guess infeasible, hence low. **Fix:** have the forwarder inject a per-container marker (or relay to a non-exempt internal listener) so container traffic is still rate-limited.
- **Vault token + proxy basic-auth readable via `docker inspect`** — `internal/isolation/docker.go:131-133`. Secrets are passed as `-e` env, which Docker persists in the container config; any host user in the `docker` group can read the live vault-scoped token. Single-vault scope and a privileged audience keep it low. **Fix:** pass secrets via a `0600` `--env-file` (removed after start) or a tmpfs bind-mount like the CA.

### ✅ Verified sound (positive confirmations)

The audit explicitly **confirmed** several isolation invariants hold — worth recording:

- **Privilege drop is correct** (`docker.go:121-127`): `--cap-drop ALL` + minimal transient `--cap-add` + `--security-opt no-new-privileges`; `gosu` drops to unprivileged `claude` with an **empty effective capability set**. The agent cannot regain `NET_ADMIN` or re-run the firewall to widen it (re-exec EPERMs at the first `iptables` call). Guarded by an integration test.
- **No startup egress race** (`entrypoint.sh:4-34`): the firewall runs to completion as root under `set -euo pipefail` (failure aborts the container, not launches it unfiltered) **before** `exec gosu claude`. No code path bypasses the firewall-then-drop sequence.
- **No secrets baked into the image** (`Dockerfile`): the image is content-addressed over static assets only; `docker history` reveals nothing secret. The CA is bind-mounted **read-only** (cert only, no key).
- **Env scoped to exactly one vault** (`env.go:42-99`): only the single-vault scoped token + that vault name are injected; no cross-vault or instance-admin token, and host env is not inherited.

### Residual hardening notes (disputed, info-level)

- **conntrack `RELATED` accepted on OUTPUT** (`init-firewall.sh:28`): the historical egress-escape primitive (helper-created expectations). Not exploitable today — no CT helper is assigned and modern kernels default `nf_conntrack_helper=0` — but only `ESTABLISHED` is needed to admit proxy replies. Tighten to `ESTABLISHED` only.
- **INPUT chain left default-ACCEPT** (`init-firewall.sh:22-26`): correct for egress-escape (an open INPUT doesn't let the agent *originate* connections past the OUTPUT DROP, and the container is alone on a per-invocation bridge), but a default-DROP INPUT would be tighter defense-in-depth.

---

## Summary

Across all five passes: no *unconditional* agent-gets-raw-credentials or no-human-approval break exists, but Round 2 found a **HIGH credential-exfiltration-past-approval** path in the proposal merge (the most serious finding overall — it defeats the human-in-the-loop boundary via a deceptive diff) and a **HIGH unauthenticated limiter DoS**. The Round-1 SSRF egress gaps remain the other priority. No agent-gets-raw-credentials or approval-bypass break was found in the core paths audited — the proposal, RBAC, and crypto invariants largely hold. The real exposure is **SSRF egress control** (the HIGH `::` bypass and the MEDIUM metadata gaps share one root cause: a hand-maintained IP blocklist), plus an **unbounded-concurrency DoS** on the MITM proxy.

| Severity | R1 | R2 | R3 | Isolation | Total |
|---|---|---|---|---|---|
| High | 1 | 2 | 0 | 0 | 3 |
| Medium | 2 | 0 | 1 | 1 | 4 |
| Low | 5 | 5 | 1 | 3 | 14 |
| Info | 2 | 3 | 1 | 1 | 7 |
| Disputed | 1 | 1 | 0 | 7 | 9 |
| Refuted / cleanly refuted | 0 | 7 | 3 | 4 | 14 |

*139 agents across 5 passes. 28 confirmed findings; 14 candidate findings refuted by adversarial verification.*

**Top priorities (unchanged):** (1) HIGH proposal-merge credential exfiltration past approval; (2) HIGH IPv6 `::` SSRF; (3) HIGH unauthenticated limiter DoS; (4) MEDIUM crypto AAD domain separation (one fix closes two findings incl. CA-key extraction); (5) MEDIUM metadata-SSRF gaps + MITM concurrency DoS + **isolation image-cache poisoning**.

**Coverage:** all priority adversaries (A1–A5) now have substantive coverage, including the container-isolation egress enforcement that backs the strong-isolation promise. The isolation core (privilege drop, startup ordering, secret handling, egress lockdown) was **verified sound**; the gaps are cache-poisoning, Docker-Desktop LAN binding, and rate-limit laundering — all hardening rather than a core egress break.

**Top priorities:** (1) HIGH proposal-merge credential exfiltration past approval (`merge.go:55-62`) — defeats the human-in-the-loop boundary; (2) HIGH IPv6 `::` SSRF to broker localhost (`netguard.go:105-124`); (3) HIGH unauthenticated sliding-window limiter DoS (`sliding.go:98-104`); (4) MEDIUM metadata-SSRF gaps + MITM concurrency DoS.

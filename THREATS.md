# THREATS.md

How I believe TrustVault can be broken, what I did, and what I knowingly left. Each mitigated entry names the test that proves it (`test/*.test.js`) so you can delete the check and watch the test fail (`npm run mutation` does that for 37 of them).

Principle: **the server decides, from the database, on every request, inside the same transaction as the action.** Nothing about access is cached, signed into a token, or held in a link.

Status: ✅ closed and tested · 🟡 reduced, residual risk stated · ⛔ knowingly accepted

---

## A. Things I did NOT close (read these first)

**A1 ⛔ The master key and the database live in the same trust zone.**
Files are AES-256-GCM encrypted with per-version keys wrapped by `FILE_MASTER_KEY`. That defeats a stolen database dump, a stolen backup, and a SQL-injection read. It does **not** defeat someone who has both the database *and* the application's environment variables (a compromised host account, or a hosting-dashboard admin). Fixing that needs a KMS/HSM where the app can *use* a key but never read it. I did not build it; it is the first thing I would add. Also: there is no key rotation (the wrapped-key column makes it possible, the tooling is not written).

**A2 ⛔ An administrator can take over a user by resetting their password.**
Admins cannot read content and cannot grant themselves access (only owners grant). But `POST /admin/users/:id/reset-password` hands the admin a working password for any account, including an owner's, and they could then sign in as that owner. I kept it because an admin who cannot recover accounts makes the product unusable. Controls that remain: the action is audited as `admin.password_reset`, appears in the overview's "recent sensitive changes", **ends all of that user's sessions** (so the real owner notices immediately), and anything the admin then does appears in the trail under the *owner's* name but from the admin's IP. That is *detective*, not preventive. Proper fix: reset by emailed single-use link, or two-person approval.

**A3 ⛔ A person who legitimately has read access can copy the file.**
No web system stops someone downloading a file they were allowed to read and passing it on. What TrustVault gives you is the proof: who, when, which version, from which IP, with the SHA-256 of what they received. Watermarking and "view-only" rendering are not built.

**A4 ⛔ No multi-factor authentication, no e-mail, no SSO.** Password + lockout + IP throttle only. Accounts are created by an admin with a one-time password. A phished password is a full compromise of that user's documents.

**A5 ⛔ Malware in uploads.** There is no antivirus. Mitigations: strict type allow-list, magic-byte match, macro-enabled Office refused (`vbaProject.bin`), HTML/SVG/script types refused, files only ever served as `attachment` with `nosniff` and a sandbox CSP. A malicious but well-formed PDF/DOCX would still be stored and offered for download.

**A6 ⛔ File size capped at 4 MB, buffered in memory.** Chosen because Vercel's body limit is ~4.5 MB and it keeps the encryption path simple. Large files need streaming + chunked authenticated encryption.

**A7 ⛔ The audit key and the audit table share a host.** See D6: someone with the database *and* `AUDIT_HMAC_KEY` can rewrite history consistently. The `AUDIT_ANCHOR` log lines (kept by the platform log drain, outside the database) are the independent check, but nothing here forces you to retain or compare them.

**A8 ⛔ Denial of service.** Only login is rate-limited. An authenticated user can hammer any endpoint; an attacker can lock a *known* account for 15 minutes by failing logins (accepted: the alternative is unlimited guessing); and failed logins/refusals write audit rows, so a flood grows the table (bounded for logins by the per-IP limit, not for refusals).

**A9 ⛔ Every owner can enumerate users by prefix** (people picker: ≥3 characters, 10 results, active only). Needed to share to "named people". Viewers cannot call it.

**A10 ⛔ New grantees see the whole version history** of a document, not just the current version. Simpler and arguably correct for audit papers; a per-version ACL would be finer.

---

## B. Access to documents

| # | Threat | What I did | Test |
|---|---|---|---|
| B1 | **IDOR**: change the id in the URL to read another user's file | One decision function, `resolveAccess()`; every document route calls `authorize()` inside its transaction. | `isolation`: *cannot touch a document… on any route* (11 routes × 2 users + new-version upload) |
| B2 | **Missing check on a rarely-used route** (versions, activity, grants, restore, suggest) | Same `authorize()` everywhere; the test loops over *every* document route. | same |
| B3 | **Existence oracle**: 403 vs 404 reveals which ids exist | No-access → `404` with a body identical to "missing" and "malformed id". | `isolation`: *indistinguishable from does not exist* |
| B4 | **Listing/search/count leaks** metadata of other people's files | The access rule is in the SQL `WHERE`; nothing is fetched then filtered. `%`/`_` escaped in `ILIKE`; parameters only. Categories endpoint, `scope=shared/mine/all` covered. | `isolation`: *list and search never reveal*, *scopes*, *SQL-injection* |
| B5 | **Admin as a backdoor** | Admin role has *no* implicit document access; admin endpoints return metadata only, never bytes. | `isolation`: *administrators cannot read…* |
| B6 | **Role escalation through a grant**: viewer given `edit` | Viewer role is a ceiling (`effectiveLevel`), enforced at grant time *and* at read time (so lowering a role later neutralises old edit grants). | `grants`: *viewer role is capped at read* |
| B7 | **Mass assignment**: `PATCH {owner_id, deleted_at, current_version}` | Only `name/category/description` are read from the body. | `isolation`: *mass assignment* |
| B8 | **Shareable/bearer download links** that outlive access | None exist. Downloads need the session cookie and a live grant; a copied URL is useless to anyone else. | `grants`: *no bearer download links* |
| B9 | **Deleted document still reachable** (grantee, or via an old URL) | Soft-deleted = invisible to everyone but the owner's trash view; not even the owner can download from trash. Purge destroys the bytes. | `grants`: *soft delete…*, *retention purge…* |
| B10 | **Path traversal / stored-file exposure** | There are no files on disk and no static upload directory; bytes live encrypted in the database and are addressed by UUID only. | n/a by construction; `upload`: *filenames are sanitised* |
| B11 | **Someone with the database swaps ciphertext** between documents to read B's content as A | GCM AAD binds `document id : version` to both the data key and the file. Even with the stored SHA-256 also copied, decryption fails and is audited as `doc.integrity_failure`. | `upload`: *stored bytes are ciphertext… cannot be swapped* |
| B12 | **HEAD / method tricks** to skip the GET check | Express routes HEAD to the same handler, so the same `authorize()` + audit run. (A HEAD download is logged as a download although no body is sent: over-logging, deliberate.) | `hardening`: *HEAD goes through the same authorisation* |
| B13 | **Inconsistent decision under concurrency**: a download racing a revoke | Revoke, grant, delete and download lock the document row, and access is then evaluated in a **separate, later statement**. (My first version did lock + decision in one statement; under READ COMMITTED a queued download kept a stale view of the grant and was served after the revoke committed. Found by the real-Postgres race test, fixed, see PROMPTS.md entry 4.) After a revoke commits, no later request can succeed. A request already past its authorisation when the revoke commits is serialised *before* it and is audited before it. | `concurrency.pg`: *download racing a revocation* (15 rounds × 20 parallel downloads, real Postgres; fails reliably on the old code) |
| B14 | **Owner transfer abuse** | Admin can only transfer documents whose owner is *deactivated*, to an active owner-role user, with a reason; audited and surfaced. | `grants`: *admin can only transfer…* |

## C. Taking access away

| # | Threat | What I did | Test |
|---|---|---|---|
| C1 | **Revoked user keeps access** (cached decision, token, open session) | There is nothing to expire: the decision is recomputed per request. The same live session fails on its very next request. | `grants`: *REVOCATION IS IMMEDIATE* |
| C2 | **Expired grants linger** | `expires_at` is part of the same SQL predicate, so expiry needs no job. | `grants`: *expired grants stop working* |
| C3 | **Leaver's session lives on** | Deactivation sets `active=false` *and* revokes session rows (two independent controls). The session query also requires `active`. | `grants`: *deactivating a user…*, *session validity re-checks…* (each control tested alone) |
| C4 | **Privilege change not applied** | Role change and password reset/change revoke sessions; password change keeps only the current one. | `grants`: *changing a role forces re-login* |
| C5 | **Stolen session after logout** | Server-side session table; logout revokes the row. 8 h absolute and 30 min idle lifetimes. | `grants`/`isolation` (forged cookies) |

What revocation *cannot* do: un-send a file already downloaded (A3).

## D. Audit trail

| # | Threat | What I did | Test |
|---|---|---|---|
| D1 | **Edit a row** (hide who downloaded) | DB trigger rejects `UPDATE/DELETE/TRUNCATE`; and each row is HMAC-chained so an edit breaks verification at that row. | `audit`: *database itself refuses…*, *even an attacker who disables the triggers…* |
| D2 | **Delete a row / reorder** | Gap-free `seq` + `prev_hash` chain: verification names the broken entry. | same |
| D3 | **Forge a row or recompute hashes** | Hash is HMAC with `AUDIT_HMAC_KEY`, which the database never holds; SHA-256 recomputation fails. | same (case 3, 5) |
| D4 | **Truncate the tail** | `audit_head` holds the latest seq/hash; mismatch is detected. Resetting the head too is only caught via the `AUDIT_ANCHOR` log lines (A7). | same (case 4) |
| D5 | **Action without a record, or record without action** | Audit insert is in the same transaction as the action; if it fails the action rolls back. | `audit`: *an action cannot commit without its audit row* |
| D6 | **Concurrent writers fork the chain** | Appends lock the single `audit_head` row. | `audit`: *concurrent actions…*; `concurrency.pg` (40 parallel writers, real Postgres) |
| D7 | **Refused attempts not recorded** | Every denial (wrong role, no access, insufficient level, failed login) is an `outcome=denied` row with actor, route, needed/had level, IP. | `audit`, `isolation`: *every refusal… is in the audit trail* |
| D8 | **Log injection** | `detail` is canonical JSON of structured fields, never concatenated text; filenames are sanitised first. | `upload`: *filenames are sanitised* |
| D9 | **Who reads the audit trail** | Admins (all) and owners (their own documents only). No one can write to it except the application. | `audit`: *owners see the activity…* |

## E. Identity, sessions, web

| # | Threat | What I did | Test |
|---|---|---|---|
| E1 | **Password guessing** | scrypt (N=32768), 12+ char policy, per-account lockout (5 → 15 min), per-IP throttle computed from the audit table (works across serverless instances). | `audit`: *lockout…* |
| E2 | **User enumeration** by response or timing | One `401` body for every failure; unknown/locked/inactive accounts burn the same scrypt work. | `audit`: *same body for unknown user and locked* |
| E3 | **Session fixation / theft** | New random 256-bit token each login, previously presented session revoked; only a SHA-256 of the token is stored; `HttpOnly`, `SameSite=Strict`, `Secure` + `__Host-` in production. | `grants` |
| E4 | **CSRF** | Per-session token in a custom header + `Origin` check + `SameSite=Strict`. | `isolation`: *cross-origin writes…* |
| E5 | **XSS** | UI uses `textContent` only; strict CSP (`script-src 'self'`, no inline); uploads served as attachments with `nosniff` and `sandbox`. | `upload`: *never serves HTML*; `scripts/ui-smoke.js` (zero CSP violations) |
| E6 | **Clickjacking / sniffing / caching** | `frame-ancestors 'none'`, `nosniff`, `Cache-Control: no-store` on all API responses, HSTS in production, no CORS. | `upload`: *security headers* |
| E7 | **Forged/garbage cookies** | Token looked up by hash; anything else is `401`. | `isolation` |
| E8 | **Admin self-lockout / last admin removed** | Cannot deactivate or change your own account (tested). A last-active-admin guard also exists, but it is defence in depth: an acting admin is by definition active, so it is only reachable through a race. | `hardening`: *admins cannot lock themselves out* |
| E9 | **Unauthenticated cron endpoint** | Needs `Bearer CRON_SECRET`, compared in constant time; disabled (404) when unset. Only the *unset / wrong token* paths are tested, not a successful authorised run. | `hardening`: *cron endpoint is invisible…* |

## F. Uploads

| # | Threat | What I did | Test |
|---|---|---|---|
| F1 | Executable / script / HTML / SVG upload | Extension allow-list (10 types). | `upload`: *disallowed types* |
| F2 | Renamed file (`.exe` → `.pdf`) | Magic bytes must match the extension; OOXML must be a zip with the right part folder and no macro project. | `upload`: *content must match* |
| F3 | Zip bomb / giant file / empty file | 4 MB hard limit enforced while streaming into memory, 1 file, field and part limits; Office files are never unpacked by the server. | `upload`: *empty, missing, oversize* |
| F4 | Header injection / traversal in filenames | Path stripped, control characters and quotes removed, leading dots removed; header uses RFC 5987 encoding. | `upload`: *filenames are sanitised* |
| F5 | Client-supplied Content-Type trusted | Never stored; MIME is chosen by the server from the extension. | `upload` |

## G. The AI advisor

| # | Threat | What I did | Test |
|---|---|---|---|
| G1 | **The machine widens access on its own** | The advisor has no code path that writes a grant; it only reads. Only `PUT /grants` (owner-only) can create access. | `upload`: *only suggests, never grants* |
| G2 | **Suggests too much** | Always proposes `read`, never `edit`. Owner may still choose otherwise: recorded as `overridden`. | same |
| G3 | **Forged / replayed suggestion id** to justify a grant | A suggestion id is accepted only if it belongs to *this owner and this document* and actually contained that user. | same (bogus + replay cases) |
| G4 | **No record of who decided** | `ai.suggest` (what was proposed), `grant.add` with `viaSuggestion`, and `ai.suggestion.accepted` (human, final permission, overridden?) are all audited. | same |
| G5 | **Document content leaks to a third party** | The advisor is local and rule-based (history of the owner's own grants). No content or names leave the system. I chose this over an LLM call precisely to avoid sending confidential metadata to a model provider. | by construction |

---

## H. Other things I considered

- **SQL injection:** every query is parameterised; the only interpolated values are integers I parse and clamp (`LIMIT`) and fixed column lists. Tested with hostile filter input.
- **Replay of an old CSRF token across sessions:** tokens are per-session.
- **UUID case/format tricks:** ids are validated by regex and compared as Postgres `uuid`.
- **Open redirect / SSRF:** the app makes no outbound requests and issues no redirects.
- **Dependency risk:** four runtime dependencies (`express`, `helmet`, `multer`, `pg`); `npm audit` is clean at time of writing.
- **Cold-start migration race on serverless:** guarded by a Postgres advisory lock.
- **Time-of-check/time-of-use between "may I upload a version?" and the upload itself:** the pre-check avoids buffering for strangers; the authoritative locked check runs inside the writing transaction (`versions` route).
- **Not covered by any automated test** (honest list): the last-admin guard body (E8, effectively unreachable), a *successful* cron purge through HTTP (the purge function itself is tested directly), and the `Secure` / `__Host-` cookie attributes, which only exist when `NODE_ENV=production` and which I verified by reading the code, not by a test. I have also **not** attacked the deployed system from outside; everything here was tested in-process against the real HTTP stack.

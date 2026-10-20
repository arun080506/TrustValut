# API reference

Base path `/api`. JSON in and out, except uploads (`multipart/form-data`, field `file`) and downloads (raw bytes).

**Authentication:** an `HttpOnly; SameSite=Strict` session cookie (`__Host-` prefixed and `Secure` in production) set by `POST /auth/login`. The cookie holds a random token; only its SHA-256 is stored server-side, so a database leak does not yield usable sessions.
**CSRF:** every non-GET request must send the `X-CSRF-Token` returned by `/auth/login` or `/auth/me`. A cross-origin `Origin` header on a write is refused.
**Errors:** `{ "error": "<code>", "message": "..." }`.
**Access-denied convention:** if you have **no** access to a document, the answer is `404 not_found`, byte-identical to a document that does not exist (and to a malformed id). `403 forbidden` is returned only when you can already see the document but lack the needed level. Every refusal is written to the audit trail.

Legend: **any** = any signed-in user · **O** = owner role · **A** = admin role · **V** = viewer role.
Document levels: `owner` (the document's owner) ⊃ `edit` ⊃ `read`. A *viewer*-role user is capped at `read`.

## Auth

| Method & path | Who | Notes |
|---|---|---|
| `POST /auth/login` `{email,password}` | public | Returns `{user, csrfToken}`. Same `401 invalid_credentials` for unknown user, wrong password, locked or deactivated. 5 failures lock the account 15 min; 30 failures per IP per 10 min → `429`. New session token every login. |
| `GET /auth/me` | public | `{user,csrfToken}`, or `{user:null}` when signed out. |
| `POST /auth/logout` | any | Revokes this session server-side. |
| `POST /auth/password` `{current,next}` | any | `next` 12–128 chars. Revokes all *other* sessions. |

## Documents

`:id` must be a UUID. "Level" is the minimum the caller needs on that document.

| Method & path | Who / level | Notes |
|---|---|---|
| `GET /documents` | any | Search. Query: `q` (name), `owner` (name/email), `category`, `from`, `to` (`YYYY-MM-DD`), `scope` (`mine`\|`shared`), `trash=1`, `limit` ≤100, `offset`. Access rule is inside the SQL `WHERE`, so unreachable documents are never selected. Admins get *their own* list here, not everyone's. |
| `GET /documents/categories` | any | Categories of documents you can reach. |
| `POST /documents` | **O** | multipart: `file`, optional `name`, `category`, `description`. Max 4 MB. Allowed: pdf, png, jpg/jpeg, txt, csv, md, docx, xlsx, pptx; content must match the extension. `201 {id}`. |
| `GET /documents/:id` | read | Metadata + version list. |
| `PATCH /documents/:id` | edit | `{name?,category?,description?}`. Unknown fields (e.g. `owner_id`) are ignored. |
| `GET /documents/:id/download?version=n` | read | Authorises and audits in one transaction **before** decrypting. `Content-Disposition: attachment`, `nosniff`, `no-store`, sandbox CSP. |
| `POST /documents/:id/versions` | edit | multipart `file`. Never overwrites; old versions remain. |
| `DELETE /documents/:id` | owner | Soft delete: hidden from everyone (including the owner's downloads) at once. |
| `POST /documents/:id/restore` | owner | From trash. |
| `GET /documents/:id/grants` | owner | Active grants. |
| `PUT /documents/:id/grants` | owner | `{userId, permission:"read"\|"edit", expiresAt?, suggestionId?}`. Viewers can only receive `read`. Expiry ≤ 1 year. |
| `DELETE /documents/:id/grants/:userId` | owner | Revokes; effective on the next request. History is kept. |
| `POST /documents/:id/suggest-access` | owner | Rule-based suggestions (always `read`). Changes nothing. Audited as `ai.suggest`. |
| `GET /documents/:id/activity` | owner | Last 200 audit entries for this document, including refused attempts. |

## Users

| Method & path | Who | Notes |
|---|---|---|
| `GET /users/directory?q=` | **O**, **A** | People picker. ≥3 characters, active users only, max 10, fields `id,name,email,role`. Viewers: `403`. |

## Administration (all require **A**; others get `403` and a logged `access.denied`)

Admin routes never return file bytes.

| Method & path | Notes |
|---|---|
| `GET /admin/summary` | Counts, "worth noticing" alerts (≥5 refusals/h by one person, ≥10 downloads/10 min, ≥5 failed logins/h from one IP), recent sensitive admin actions. |
| `GET /admin/documents?q=` | All document metadata and live grant counts. |
| `GET /admin/documents/:id/grants` | Full grant history including revoked/expired. |
| `DELETE /admin/documents/:id/grants/:userId` `{reason?}` | Emergency revoke. Audited `admin.grant_revoke`. |
| `POST /admin/documents/:id/transfer` `{newOwnerId, reason}` | Only when the current owner is **deactivated**; new owner must be an active *owner*-role user. Audited. |
| `GET /admin/audit` | Filters: `actor`, `action` (prefix), `outcome` (`allowed`\|`denied`), `doc`, `from`, `to`, `before` (seq), `limit` ≤200. |
| `GET /admin/audit/verify` | Recomputes the whole HMAC chain: `{ok,count,...}` or `{ok:false,brokenAt,reason}`. |
| `GET /admin/users` | All users with live session counts. |
| `POST /admin/users` `{email,name,role}` | Returns a one-time temporary password. |
| `POST /admin/users/:id/deactivate` | Revokes all that user's sessions in the same transaction. Not yourself; not the last admin. |
| `POST /admin/users/:id/activate` | |
| `POST /admin/users/:id/role` `{role}` | Forces re-login. Not yourself; not the last admin. |
| `POST /admin/users/:id/revoke-sessions` | |
| `POST /admin/users/:id/reset-password` | One-time temporary password; revokes sessions. See THREATS.md A2. |

## Other

| Method & path | Who | Notes |
|---|---|---|
| `GET /health` | public | `{ok:true}` after a `SELECT 1`. |
| `GET /cron/purge` | `Authorization: Bearer $CRON_SECRET` | Retention purge. Disabled (404) when `CRON_SECRET` is unset. |

## Audit actions

`auth.login`, `auth.login_failed`, `auth.logout`, `auth.password_change`, `doc.upload`, `doc.version`, `doc.update`, `doc.download`, `doc.delete`, `doc.restore`, `doc.purge`, `doc.integrity_failure`, `grant.add`, `grant.change`, `grant.revoke`, `ai.suggest`, `ai.suggestion.accepted`, `access.denied`, `admin.user_create`, `admin.user_activate`, `admin.user_deactivate`, `admin.user_role`, `admin.session_revoke`, `admin.password_reset`, `admin.grant_revoke`, `admin.doc_transfer`.
Each entry stores: sequence, UTC time, actor id + email, action, `allowed`/`denied`, document, target user, IP, canonical-JSON detail, previous hash, HMAC.

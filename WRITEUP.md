# Vaultora Write-up

## What I built

Vaultora is a security-first document-sharing platform built with **Node 24, Express and PostgreSQL**, with no frontend build step. The same codebase is designed to deploy to Render and Vercel.

Owners upload files; each file is encrypted at rest. Owners grant named people `read` or `edit` access, optionally with an expiry, and can revoke that access at any time.

Administrators manage accounts and security metadata but **cannot open document contents**.

Every upload, download, change, deletion, permission change, sign-in and **refused attempt** is written to a hash-chained, HMAC-protected audit trail.

The project also includes:

- document versions;
- soft delete and retention purge;
- session management;
- password reset;
- an "anything worth noticing" panel;
- an access advisor;
- automated authorization/isolation tests;
- real PostgreSQL concurrency tests;
- mutation testing of security controls.

The repository documents the use of AI during development in `PROMPTS.md` and the threat model in `THREATS.md`.

---

# My permission model, in my own words

**Per-document grants, no folders, no groups, no inheritance.**

A document has exactly one owner.

Anyone else reaches it only through a row in `grants` containing `read` or `edit` permission that is:

- not revoked;
- not expired;
- associated with an active user.

The access decision is implemented by `resolveAccess()` in `src/authz.js`.

For normal authorization checks, the server obtains the document lock first and then evaluates access in a **fresh database statement**. This distinction matters for concurrent revoke/download behavior under PostgreSQL `READ COMMITTED`.

So:

- there is no token, cache or permanent link that can outlive a revocation;
- access is recomputed from current database state;
- no-access is intentionally indistinguishable from a missing/malformed document identifier where appropriate;
- the **role is a ceiling**: a `viewer` can never exceed `read`;
- **admins are outside the document data path**.

Administrators can govern users, sessions, metadata, grants and audit records, but they have no implicit ability to read document bytes.

They can emergency-revoke access and can transfer documents only when the existing owner has been deactivated.

---

## Why not folders?

The brief's first failure story is effectively:

> Given access to one file, can the user accidentally receive access to forty?

Inheritance is exactly where that type of mistake becomes possible.

I therefore chose a simpler permission model where every effective document permission is explicit.

The trade-off is that sharing many documents can require multiple grants.

The advisor exists partly to reduce that administrative burden.

Groups and folders could be added later, but they would require an explicit "effective access" explanation so owners can see exactly **why** someone has access.

---

# Storage and encryption

## Files

Document versions use **AES-256-GCM**.

Each version has a random encryption key.

The version key is wrapped using:

`FILE_MASTER_KEY`

The encrypted content and wrapped key are cryptographically bound to:

`document id : version`

This prevents a database attacker from simply swapping ciphertext and keys between document versions without detection.

Before a download is decrypted:

1. the request is authenticated;
2. authorization is evaluated;
3. the access event is audited;
4. the current access decision is enforced;
5. the encrypted content is decrypted;
6. the SHA-256 integrity value is checked.

The download response is also configured so documents are treated as attachments rather than browser-rendered content.

---

# Audit trail

Security-sensitive operations are written to the audit trail, including refused operations.

The audit design has multiple layers.

### Database protection

The database rejects:

- `UPDATE`;
- `DELETE`;
- `TRUNCATE`

against audit records.

### Cryptographic chain

Each audit record contains a cryptographic relationship to the previous record:

`HMAC(AUDIT_HMAC_KEY, previous_hash | fields)`

This makes modification, deletion or reordering detectable.

### Concurrency

The audit head is protected with database locking so concurrent writers cannot independently advance the chain.

### External anchor

`AUDIT_ANCHOR` log entries provide an off-database copy of the chain head.

### Honest limitation

The audit design is not claimed to protect against an attacker who controls **both the database and the audit HMAC key**, and who can also remove the external anchor logs.

That residual risk is documented in `THREATS.md`.

---

# Immediate revocation

Revocation is one of the most important security properties in Vaultora.

The application does not rely on:

- cached permissions;
- long-lived authorization tokens;
- permanent download links;
- client-side permission state.

After a grant is revoked, subsequent access decisions use the current database state.

The concurrent revoke/download case is specifically tested against real PostgreSQL.

The initial implementation had a subtle concurrency flaw: a statement could wait for a document lock while retaining a statement snapshot containing an old grant state.

That meant a queued download could potentially observe a grant that had already been revoked.

The fix was to separate:

1. document locking;
2. fresh authorization evaluation.

The regression test was strengthened from a single race to repeated rounds against real PostgreSQL.

This is documented in `PROMPTS.md`.

---

# Role model

## Administrator

Administrators can:

- manage users;
- activate/deactivate users;
- revoke sessions;
- reset passwords;
- inspect document metadata;
- inspect grants;
- perform emergency revocation;
- transfer documents from deactivated owners;
- inspect the audit trail;
- verify audit integrity.

### Important boundary

**Administrators cannot read document contents.**

This is deliberate.

Security administration and document-reading authority are separate capabilities.

---

## Owner

Owners can:

- upload documents;
- read their documents;
- create grants;
- change grants;
- revoke grants;
- edit documents;
- manage versions;
- soft-delete documents;
- restore documents.

---

## Viewer

Viewers can:

- read explicitly shared documents.

Viewers cannot:

- upload documents;
- create grants;
- change permissions;
- increase their own access;
- transfer ownership;
- access private documents.

---

# Upload security

Uploads are validated rather than trusting the filename or browser-provided MIME type.

Validation includes:

- extension;
- declared content type;
- file content / magic bytes;
- filename safety;
- maximum size.

Supported formats include:

- PDF;
- PNG;
- JPG/JPEG;
- TXT;
- CSV;
- Markdown;
- DOCX;
- XLSX;
- PPTX.

The upload tests also cover hostile filenames and malformed cases.

Downloads use security-oriented response headers including:

- `Content-Disposition`;
- `X-Content-Type-Options`;
- `Cache-Control`;
- restrictive CSP.

---

# AI advisor

The product includes an access advisor.

The advisor can **suggest** who an owner may want to share a document with.

It cannot grant access.

The implementation deliberately uses a **local rule-based advisor** rather than sending confidential document names and people to an external model.

The advisor:

- has no write path to `grants`;
- only proposes `read`;
- binds suggestions to the intended owner/document/user;
- requires human acceptance;
- audits the suggestion;
- audits the resulting grant;
- records the final permission and overrides.

The advisor is therefore an assistant rather than an authorization authority.

---

# AI usage during development

AI was used extensively during development with Claude Code / Sonnet 5.5.

However, AI output was not treated as proof of correctness.

`PROMPTS.md` documents the development process and the cases where AI-generated implementation or reasoning was wrong.

Important examples include:

### Database adapter error

AI initially assumed PGlite and node-postgres exposed the same affected-row property.

They did not.

The mismatch caused successful revocations to roll back in the test environment.

A failing revocation test exposed the issue.

---

### Security tests that were too weak

The initial mutation run found **5 of 37 security mutations surviving**.

The normal test suite was green, but removing certain controls did not cause the tests to fail.

The missing coverage was then added.

---

### False concurrency confidence

A PGlite `Promise.all()` test looked concurrent but was effectively serialized through a single connection.

The concurrency test was moved to real PostgreSQL.

---

### Revocation race

The initial lock design did not correctly account for PostgreSQL statement snapshots under `READ COMMITTED`.

Repeated real-PostgreSQL testing exposed the race.

The authorization sequence was redesigned and tested repeatedly.

---

### Tautological filename assertion

An AI-generated assertion could not meaningfully fail for the vulnerability being tested.

The test was rewritten with direct assertions.

---

### CSP violation

The AI-generated UI used inline styles and a `javascript:` link even though the application's CSP prohibited them.

The browser smoke test caught the issue.

---

## The development principle

The most useful repeated instruction was:

> **"Remove control X and tell me which test fails. If none, that is the bug."**

This turned security review into a falsifiable process.

The goal was not to ask:

> "Does this code look secure?"

The stronger question was:

> "If I remove this security control, does a test prove that something important breaks?"

---

# Security testing

Vaultora uses several complementary test layers.

## Standard tests

```bash
npm test
```

These exercise the application against the local test environment.

---

## Real PostgreSQL

```bash
npm run test:pg
```

The real PostgreSQL suite is important for:

- transaction behavior;
- locking;
- concurrent requests;
- isolation;
- production database semantics.

Concurrency claims are not based solely on PGlite.

---

## Mutation testing

```bash
npm run mutation
```

The mutation harness removes individual security controls and requires the relevant tests to fail.

The harness covers **37 security controls**.

Examples include:

- active-session checks;
- session revocation;
- shared-document filtering;
- GCM document/version binding;
- audit-head locking.

This provides evidence that the security tests actually depend on the controls they claim to protect.

---

## UI smoke testing

```bash
npm run ui:smoke
```

The UI smoke test uses headless Chromium and checks for:

- console errors;
- CSP violations;
- authentication behavior;
- role-specific UI failures.

---

# Threat model

`THREATS.md` documents both mitigated threats and residual risks.

Covered threat areas include:

- IDOR;
- missing route authorization;
- existence oracles;
- list/search metadata leakage;
- administrator privilege abuse;
- role escalation;
- mass assignment;
- bearer download links;
- deleted-document access;
- path traversal;
- ciphertext swapping;
- HTTP method tricks;
- concurrent revoke/download races;
- owner-transfer abuse;
- session revocation;
- audit tampering;
- audit concurrency;
- authentication and session threats;
- web security threats.

The document also records risks that are knowingly accepted.

That includes:

- same trust zone for database and master key;
- no MFA/SSO;
- legitimate readers can copy document contents;
- no antivirus scanning;
- 4 MB upload limitation;
- no automated key rotation;
- limited external audit retention;
- denial-of-service limitations;
- user enumeration through the people picker;
- version-history visibility to newly granted users.

---

# What I deliberately did not build

The following are deliberate scope decisions rather than unfinished security requirements:

- folders/groups/inheritance;
- external accounts;
- unauthenticated public links;
- MFA/SSO/email authentication;
- antivirus scanning;
- files above the current upload limit;
- KMS-held keys;
- automated key rotation;
- in-browser document previews;
- notifications;
- per-version permissions;
- legal hold.

The reasons and residual risks are documented in `THREATS.md`.

---

# Deployment

Vaultora is designed as one Node/Express codebase.

### Render

The Render deployment is the current recommended evaluation environment.

Live URL:

`https://trustvalut.onrender.com`

### Vercel

The

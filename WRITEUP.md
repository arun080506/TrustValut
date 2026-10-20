# TrustVault write-up

## What I built

A document-sharing platform in Node 22 / Express / PostgreSQL with no build step, deployable unchanged to Render (long-running service) and Vercel (serverless function), both backed by Postgres.

Owners upload files; each file is encrypted at rest; owners grant named people `read` or `edit`, optionally with an expiry, and take it back at any moment. Administrators manage accounts and watch activity but cannot open files. Every upload, download, change, deletion, permission change, sign-in and **refused attempt** is written to a hash-chained, HMAC-signed, append-only audit trail that the admin screen verifies on every load. All ten required features are implemented, plus versions, soft delete with retention purge, one-time-password onboarding, session management, an "anything worth noticing" panel, and an access advisor.

53 automated tests (50 on the in-process database, all 53 on a real PostgreSQL server). A mutation harness removes 37 individual controls and requires the suite to fail.

## My permission model, in my own words

**Per-document grants, no folders, no groups, no inheritance.**

A document has exactly one owner. Anyone else reaches it only through a row in `grants` (`read` or `edit`) that is not revoked and not expired. The decision, `resolveAccess()` in `src/authz.js`, is a single SQL join recomputed on **every** request inside the same transaction as the action, with the document row locked. So:

- there is no token, cache or link that can outlive a revocation. "Immediately" costs one indexed lookup per request and a row lock on writes;
- no access looks identical to "does not exist" (404);
- the **role is a ceiling**: a `viewer` can never exceed `read` even if an `edit` row exists;
- **admins are outside the data path.** They govern users and see metadata, grants and the audit trail, but have no implicit access to bytes. They can emergency-revoke a grant, and take over a document only when its owner is already deactivated.

**Why not folders?** The brief's first failure story is "given a folder to see one file, can now see forty." Inheritance is exactly where that happens, and a permission model that is obviously correct on a page beats a richer one with a hole. The cost is that sharing many files means many grants; the advisor exists partly to take the edge off that. Groups and folders would be the next step, with an explicit "effective access" explanation screen so owners can see *why* someone has access.

## Storage and the audit trail

- **Files:** AES-256-GCM, a random key per version, wrapped by `FILE_MASTER_KEY`; both ciphertext and wrapped key are bound to `document id : version`, so rows cannot be swapped by someone with database write access. Download decrypts only after the authorisation + audit transaction has committed, and re-checks the SHA-256.
- **Audit:** the database refuses UPDATE/DELETE/TRUNCATE; independently, each row is `HMAC(AUDIT_HMAC_KEY, prev_hash | fields)` with the key held outside the database, so even someone who disables the triggers cannot edit, delete, reorder or forge entries without verification naming the broken row. `AUDIT_ANCHOR` log lines give an off-database copy of the chain head. The honest limit: someone holding both the database and the key (and able to scrub logs) can rewrite history. That is THREATS A1/A7.

## AI

*In the build:* used throughout (see PROMPTS.md). It was most dangerous exactly where predicted: it produced a revoke that silently rolled back on the test engine, a test suite that stayed green with five controls deleted, a concurrency test that could not fail, and, most seriously, a lock design in which a revoked user's queued download could still be served after the revoke committed. Each was caught by making the tests prove themselves (mutation testing, a real Postgres run, looping a race test) rather than by reading the code, and PROMPTS.md records each.

*In the product:* a local, rule-based advisor. It suggests who an owner may want to share a document with, based on the owner's own prior grants. It has no write path to permissions, only ever proposes `read`, and the suggestion, the human's grant and the final decision (including overrides) are all audited. I deliberately did not send document names or people to an external model.

## What I deliberately did not build

Folders/groups/inheritance (above) · sharing with people outside the company (no external accounts, no expiring public links: a link that works without sign-in contradicts "the wrong person can never read the file", so I left it out rather than half-do it) · MFA/SSO/email · virus scanning · files over 4 MB · KMS-held keys and key rotation · in-browser previews (downloads only, never inline) · notifications · per-version permissions · legal hold. Reasons and residual risk for each are in THREATS.md section A.

## What is unfinished or unproven

- **Not deployed by me.** I had no access to your Render or Vercel accounts, so the live URLs, the seed data on a hosted database and the demo video are for you to produce. The configs (`render.yaml`, `vercel.json`) and the production boot path are written and the production start-up refusal is checked, but I have not seen either platform run the app. Expect small platform-specific fixes on first deploy (most likely the Vercel rewrite or cold-start time).
- **No history across a week.** One session, no commits yet.
- **No external attack.** Everything was tested in-process against the real HTTP stack and a real PostgreSQL server, never against a hosted instance.
- The admin password-reset takeover path (THREATS A2) is the weakest design point and the first thing I would redesign.
- The advisor is intentionally simple; it learns nothing beyond counting co-sharing.
- No pagination UI (the API supports `limit`/`offset`); the admin document list is capped at 200.

## Where to look in an interview

*"Where is the decision made when someone downloads a file?"* `src/routes/documents.js`, the `/:id/download` handler: `authorize(tx, req, 'read', …)` → `resolveAccess()` in `src/authz.js`. If that line were removed: the `isolation` suite fails 14 tests (`npm run mutation -- authz`), and the first thing a non-granted user would get is the file.

# PROMPTS.md

> **Read this first.** The brief asks for a week of dated entries with commit links. This repository was produced in a **single working session on 2026-10-19**. I have not fabricated a week of history or invented commit hashes. The entries below document what actually happened: what I asked the AI to do, what it produced, what was wrong, how I detected the problem, and how I verified the correction.
>
> The repository now contains the resulting implementation and its tests. Where a historical commit hash is not explicitly available from the contemporaneous record, I deliberately do **not** manufacture one. The implementation and test evidence are the source of truth.

## AI tool used

**Claude (Claude Code, Sonnet 5.5)** was used as a coding, design and testing assistant.

AI was used for:
- initial architecture and implementation;
- database and API code;
- security tests;
- mutation testing;
- concurrency testing;
- UI implementation;
- documentation drafts.

The AI was **not treated as an authority**. Security-sensitive suggestions were challenged with tests, mutation testing, real PostgreSQL runs and adversarial cases.

The most useful standing instruction I reused was:

> **"Remove control X and tell me which test fails. If none, that is the bug."**

This changed the workflow from "does the implementation look correct?" to "does a test actually depend on this security control?"

---

## Original brief given to the AI

The one-line version of the original brief was:

> Build Vaultora: Express + Postgres, one codebase deployable to Render and Vercel. Per-document grants, three roles, server-side authorisation on every route, immediate revocation, a tamper-evident audit trail including refused attempts, encrypted file storage, upload validation, an admin view, an advisor that suggests but never grants, and automated tests proving users cannot reach each other's documents. Then write THREATS.md honestly.

The important constraints were:

- three roles: Admin, Owner and Viewer;
- permissions are per document rather than global;
- authorization is decided server-side;
- revocation must take effect immediately;
- administrators can manage security metadata but cannot read document contents;
- denied attempts must be auditable;
- stored documents must be encrypted;
- uploads must be validated;
- the advisor may suggest access but can never grant access;
- tests must prove isolation rather than merely exercise successful paths.

---

# Entry 1 — 2026-10-19 · Access control · revocation that quietly did not revoke

### Asked

Write a database adapter so the same SQL works with node-postgres in production and PGlite in tests, then implement grant/revoke routes.

### AI produced

The revoke route performed an update and checked:

`done.rowCount`

### What was wrong

PGlite reports the number of changed rows as `affectedRows`, whereas node-postgres reports it as `rowCount`.

Therefore a successful revoke in the test database appeared to have changed no rows.

The route entered its "nothing changed" branch, returned an error and rolled the transaction back.

The dangerous part was that the production driver would have behaved differently.

### How I caught it

The test:

`REVOCATION IS IMMEDIATE`

failed on the revoke request itself with:

`404 !== 200`

The same underlying problem also affected administrative emergency revocation.

I treated the failure as evidence that the security control had not actually executed, rather than dismissing it as a test-environment problem.

### Fix

I normalized the database adapter so both drivers expose the expected affected-row value.

I then ran the test suite against a **real PostgreSQL server** using:

`npm run test:pg`

This was important because an authorization test against a different database implementation is not sufficient evidence for the production database path.

### Lesson

> A security test running against a different database engine proves the behavior of that engine, not necessarily the production engine.

---

# Entry 2 — 2026-10-19 · Authorization / audit · tests that passed with the control removed

### Asked

Write tests proving that:

- users cannot reach other users' documents;
- revoked access stops working;
- audit records cannot be silently modified;
- role and session controls are enforced.

I then added a mutation harness:

`scripts/mutation-check.js`

Its job is to temporarily remove one security control at a time and require the tests to fail.

### AI produced

The initial suite reported:

**43 green tests**

and appeared to cover the important authorization and audit paths.

### What was wrong

The first mutation run found **5 of 37 security mutations that survived**.

That meant five controls could be removed without making the suite fail.

The surviving controls were:

1. `u.active = true` in the session query;
2. session revocation during user deactivation;
3. the grant filter used by the `shared` document scope;
4. AES-GCM binding of ciphertext to `document id : version`;
5. the audit-head `FOR UPDATE` lock.

This was significant because the normal test suite was green while the security coverage was incomplete.

### How I caught it

The mutation harness caught the problem.

The AI's implementation and test summary looked complete, but the stronger question was:

> "What happens if I delete the control?"

Five controls had no test capable of proving they mattered.

### Fix

I added tests that isolate each control.

Examples:

- set a user inactive while leaving the session row intact;
- separately remove session revocation;
- assert that `scope=shared` actually applies its grant restriction;
- for ciphertext swapping, swap the **ciphertext, wrapped key and checksum together**, so the checksum cannot accidentally detect the tampering before AES-GCM AAD does;
- test audit-head serialization separately.

The mutation suite was then rerun.

### Lesson

> A green security suite is not enough. A control is only meaningful if removing it causes an appropriate test to fail.

---

# Entry 3 — 2026-10-19 · Audit trail · a concurrency claim PGlite cannot prove

### Asked

Prove that:

- concurrent audit writers cannot corrupt the hash chain;
- audit sequence numbers remain gap-free;
- a download racing a revoke is correctly serialized.

### AI produced

A concurrency test using `Promise.all()` against PGlite.

### What was wrong

PGlite uses a single connection in this test configuration.

Therefore the supposedly concurrent requests were effectively serialized by the test driver.

The test could pass even if the database row lock protecting the audit head was removed.

### How I caught it

The mutation test:

> `audit: chain is not serialised (no head lock)`

survived.

I then asked a more fundamental question:

> **Which database engine could actually make this test fail?**

That exposed the limitation.

### Fix

Concurrency tests that depend on real database concurrency were moved to a **real PostgreSQL server**.

`npm run test:pg`

starts the throw-away PostgreSQL test environment.

The concurrency tests are skipped with an explicit reason when real PostgreSQL is unavailable rather than silently claiming concurrency coverage.

### Lesson

> `Promise.all()` does not prove database concurrency. The test environment must provide independent database connections and real transaction contention.

---

# Entry 4 — 2026-10-19 · Authorization · a revoked user's download was served after revoke committed

### Asked

Make document download and grant revocation safe when they happen concurrently.

### AI produced

The initial design locked the document and evaluated the grant in one SQL statement.

The intended design was:

- download takes a document lock;
- revoke takes the corresponding update lock;
- therefore revoke and download serialize.

### What was wrong

That reasoning was incomplete under PostgreSQL `READ COMMITTED`.

The statement could wait for the document row lock and then continue using the statement snapshot for the joined grant row.

As a result, a queued download could still see the old grant as live after the revoke had committed.

That could produce the unacceptable sequence:

1. revoke commits;
2. download continues;
3. revoked user receives the file;
4. the download is audited after the revoke.

### How I caught it

The first race test passed once.

I did **not** accept that as proof.

I ran the real PostgreSQL test repeatedly and found downloads being served after the revoke.

The original race test failed intermittently, demonstrating that one successful run was not sufficient evidence.

### Fix

`resolveAccess()` was changed to:

1. take the document lock in one statement;
2. perform the authorization check in a **second, fresh SQL statement**.

The second statement obtains a fresh `READ COMMITTED` snapshot and therefore observes the committed revocation.

The test was also strengthened from a single race to **15 rounds**.

The fixed version was run repeatedly.

### Lesson

> A concurrency test that passes once proves very little. Make the buggy version fail reliably, then make the fixed version survive repeated runs.

---

# Entry 5 — 2026-10-19 · Tests · an assertion that could not fail

### Asked

Create a test for hostile filenames including:

- path traversal;
- CR/LF;
- NUL;
- quotes.

### AI produced

The first assertion contained logic equivalent to:

`condition ? expected : stored`

### What was wrong

The assertion was effectively a tautology.

If the expected condition was false, the assertion expected the actual value itself.

It could therefore never detect the problem it was supposed to test.

There was also a second problem: sending an actual NUL byte inside the multipart filename caused the HTTP request to be malformed before the application reached the intended assertion.

### How I caught it

The malformed NUL case failed first.

While fixing that failure, I inspected the assertion and discovered that the assertion itself could not fail meaningfully.

### Fix

The test was rewritten to:

- test six hostile filenames independently;
- assert directly on the stored sanitized filename;
- reject path separators;
- reject control characters;
- reject quotes;
- reject leading-dot names;
- inspect `Content-Disposition`;
- verify that CR/LF cannot inject headers;
- handle the NUL case separately and verify that no file is stored.

A later failure involving `....txt` exposed a test expectation problem rather than an application vulnerability: the server correctly rejected the extension-less result.

### Lesson

> A test is security evidence only if it can actually fail for the vulnerability it claims to cover.

---

# Entry 6 — 2026-10-19 · UI · code my own CSP forbids

### Asked

Build a no-build single-page UI for the three roles.

### AI produced

The UI initially contained:

- inline `style="..."` attributes;
- a `javascript:` link.

### What was wrong

The application CSP explicitly uses:

`script-src 'self'`

and:

`style-src 'self'`

Therefore the UI's own inline code violated the security policy.

### How I caught it

`scripts/ui-smoke.js` runs the UI in headless Chromium and fails on console errors.

The smoke test detected the CSP violations.

It also exposed a separate issue where the signed-out `/auth/me` probe returned `401`, generating a console error.

### Fix

I changed:

- inline styles → CSS classes;
- `javascript:` navigation → a normal button;
- signed-out `/auth/me` → `{user:null}` with HTTP 200.

### Lesson

> Security headers need integration tests. It is easy to write a restrictive policy and then accidentally build a UI that violates it.

---

# Entry 7 — 2026-10-19 · Design decision I deliberately overrode · the AI advisor

### AI suggestion

The brief allows an AI advisor to suggest who should receive document access.

The obvious implementation would be to send document titles, users or other confidential metadata to an external LLM.

### My decision

I deliberately **did not** use an external LLM for authorization suggestions.

Instead, Vaultora uses a local rule-based advisor over the owner's own grant history.

The reason is security:

> Sending confidential document information and user relationships to a third-party model would introduce another confidentiality boundary that the application does not need.

### Structural guarantees

The advisor:

- has no write path to `grants`;
- can only propose `read`;
- cannot grant access;
- cannot increase an existing permission;
- binds a suggestion to the relevant owner/document/user;
- audits the suggestion;
- audits acceptance;
- records the final human-selected permission.

The advisor therefore remains an assistant rather than an authorization authority.

### Lesson

> The safest AI feature is sometimes the one where the AI is deliberately given less authority.

---

# Independent verification performed

The following checks were not accepted merely because the AI said they worked.

### Audit-chain tampering

I manually altered audit rows inside tests with the normal verification triggers disabled and verified that HMAC-chain verification detects the tampering cases.

### Concurrent audit writers

The audit chain was tested using **40 parallel writers on separate PostgreSQL connections**.

This is deliberately different from the PGlite test environment.

### Revocation race

The download/revoke race was repeated using the real PostgreSQL environment and the strengthened multi-round test.

### Mutation testing

The security mutation harness removes individual controls and requires the relevant tests to fail.

This provides evidence that the tests are actually connected to the security controls rather than merely exercising happy paths.

---

# What the AI got wrong

The important failures were not hidden:

| Area | AI assumption | What was actually wrong | How it was caught |
|---|---|---|---|
| Revocation | DB adapters behaved identically | `affectedRows` vs `rowCount` | failing revocation test |
| Authorization coverage | tests were comprehensive | 5/37 mutations survived | mutation testing |
| Concurrency | PGlite `Promise.all()` proved concurrency | single connection serialized requests | surviving mutation |
| Revocation race | one locked statement was sufficient | joined grant snapshot could be stale | repeated real-PG race |
| Filename testing | assertion checked sanitization | assertion was tautological | test review after failure |
| CSP | UI was working | UI violated its own CSP | browser smoke test |
| AI advisor | external LLM was natural choice | unnecessary confidentiality exposure | human security design decision |

This is the evidence I consider most important in the AI section: **the AI was useful, but its output was repeatedly treated as something to challenge rather than something to trust.**

---

# Evidence hierarchy

When AI output conflicted with stronger evidence, I used this order:

1. failing security test;
2. mutation test;
3. real PostgreSQL behavior;
4. repeated concurrency test;
5. HTTP-level integration behavior;
6. source-code inspection;
7. AI explanation.

The AI explanation was never treated as proof by itself.

---

# What I have deliberately not claimed

I have **not** claimed that Vaultora is unbreakable.

Known residual risks are documented in `THREATS.md`.

Examples include:

- the master key and database remain in the same trust zone;
- there is no MFA/SSO;
- a legitimate reader can still copy content after receiving it;
- antivirus scanning is not implemented;
- large-file streaming is limited;
- external audit retention is not independently enforced;
- denial-of-service resistance is bounded;
- an owner can enumerate users through the people picker;
- a newly granted user can see the document's existing version history.

These are documented limitations rather than hidden weaknesses.

---

# What I have not verified

I have **not** claimed that an external penetration test was performed.

I did not run a dedicated penetration-testing platform against the deployed service.

I did run the application-level HTTP tests, real PostgreSQL tests, mutation checks, browser smoke tests and `npm audit`.

The distinction matters:

> Passing automated tests is evidence of the tested properties. It is not evidence that every possible vulnerability has been discovered.

---

# Final evaluator checklist

An evaluator should be able to see the following without trusting an AI-generated claim:

- **Authorization:** every protected document operation checks access server-side.
- **Isolation:** users cannot access documents they are not granted.
- **Revocation:** removing a grant immediately prevents later access.
- **Concurrency:** revoke/download behavior is tested against real PostgreSQL.
- **Roles:** Admin, Owner and Viewer permissions are enforced server-side.
- **Admin boundary:** administrators manage security metadata but cannot read document contents.
- **Encryption:** stored document versions are encrypted and integrity protected.
- **Audit:** successful and refused security-relevant actions are recorded.
- **Tamper evidence:** audit-chain modification is detectable.
- **Upload security:** filenames, content type and dangerous upload cases are tested.
- **AI advisor:** suggestions cannot directly grant access.
- **Threat model:** known attacks and accepted risks are documented in `THREATS.md`.
- **AI usage:** the development process openly records where AI was wrong and how those errors were caught.
- **Honesty:** no fabricated development history or fabricated commit hashes are presented.

## Final principle

> **AI wrote a significant amount of the code. AI did not get the final say on whether the security properties were true.**
>
> The implementation was repeatedly challenged by mutation, integration, concurrency and adversarial tests, and the failures were kept in this document instead of being erased from the history of the work.

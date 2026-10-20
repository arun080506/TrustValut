# PROMPTS.md

> **Read this first.** The brief asks for a week of dated entries with commit links. This repository was produced in a **single working session on 2026-10-19**, so every entry below carries that one date, and the "fixed in" lines say `commit: <add hash>` because **no commits had been made when this was written**. Fill those in from your own history. I have not invented a week of history and the file does not pretend there is one. What follows is what actually happened: what the AI was asked, what it produced, what was wrong, and how it was caught.

Tool used: Claude (Claude Code, Sonnet 5.5) for design, code and tests. Entries 1 to 4 are about authorisation / audit; they are the ones that matter.

---

## Reusable instructions (the standing context I give the tool)

See [CLAUDE.md](CLAUDE.md) in this repo. Honest note on its history: I wrote it at the **end** of the session, distilled from the corrections below. It was not loaded during the build. The one-line version of the original brief that drove the build:

> Build TrustVault: Express + Postgres, one codebase deployable to Render and Vercel. Per-document grants, three roles, server-side authorisation on every route, immediate revocation, a tamper-evident audit trail including refused attempts, encrypted file storage, upload validation, an admin view, an advisor that suggests but never grants, and automated tests proving users cannot reach each other's documents. Then write THREATS.md honestly.

The most useful prompt pattern, reused several times: **"Remove control X and tell me which test fails. If none, that is the bug."**

---

## Entry 1: 2026-10-19 · Access control · revocation that quietly did not revoke

**Asked:** write a database adapter so the same SQL runs on node-postgres in production and PGlite (in-process Postgres) in tests, then write the grant/revoke routes.

**Produced:** an adapter that passed queries straight through. The revoke route did `UPDATE grants SET revoked_at = now() … ; if (!done.rowCount) throw 404 'no_active_grant'`.

**Wrong:** PGlite reports changed rows as `affectedRows`; node-postgres reports `rowCount`. On PGlite `rowCount` was `undefined`, so a *successful* revoke hit the "nothing changed" branch and threw inside the transaction, which **rolled the revocation back**. The caller got a 404 and the grant stayed live. In production (node-postgres) it would have worked, so the test database was lying about the most important behaviour in the product. The AI had not mentioned that the two drivers differ.

**How caught:** the test `REVOCATION IS IMMEDIATE` failed with `404 !== 200` on the revoke call itself (and `admin emergency revoke` failed the same way). I read the failure as "the control did not run" rather than "flaky test".

**Fixed:** normalise `rowCount` in the PGlite adapter (`src/db.js`), then re-ran the whole suite on a **real** PostgreSQL server (`npm run test:pg`) so the production driver path is exercised too. commit: `<add hash>`

**Lesson recorded:** an access-control test that runs on a different database engine than production is only evidence about the engine it ran on.

---

## Entry 2: 2026-10-19 · Authorisation / audit · tests that passed with the control removed

**Asked:** "Write tests proving one user cannot reach another's documents, and that the audit trail can't be quietly altered." Then I wrote `scripts/mutation-check.js`: delete one control at a time in a temp copy and require the suite to fail.

**Produced:** 43 green tests that read as thorough (isolation across every route, revocation, tamper cases).

**Wrong:** 5 of the first 37 mutations **survived**, i.e. the controls had no test behind them:

1. the `u.active = true` check in the session query (deactivated users' live sessions);
2. deactivation revoking session rows;
3. the `shared` list scope's grant filter;
4. the GCM binding of ciphertext to `document id : version`. My "swap" test copied the blob and key but *not* the checksum, so the SHA-256 check caught it and the AAD binding was never needed to pass;
5. the audit-head `FOR UPDATE` lock (survived because of Entry 3).

**How caught:** the mutation run, not review. The suite was green; the AI's own summary said coverage was complete.

**Fixed:** tests that exercise each control **in isolation** (e.g. set `active=false` while leaving the session row alone, then the reverse; swap ciphertext *and* key *and* checksum so only the AAD can stop it) and a `scope=shared` assertion. Re-ran: 4 of 5 killed. commit: `<add hash>`

---

## Entry 3: 2026-10-19 · Audit trail · a concurrency claim PGlite cannot test

**Asked:** prove the audit chain stays gap-free and valid under concurrent writers, and that a download racing a revoke is serialised.

**Produced:** a "concurrent actions keep a valid chain" test using `Promise.all` against PGlite.

**Wrong:** PGlite is a single connection, so the requests were serialised by the driver and the test would pass **with the row lock deleted**. The mutation `audit: chain is not serialised (no head lock)` survived. The AI had presented the test as proof of the locking design.

**How caught:** the surviving mutation again; I then asked "which engine could ever fail this test?"

**Fixed (partly; see Entry 4, which this test later exposed):** `test/concurrency.pg.test.js` runs only against a real server (skipped, with the reason printed, otherwise, so it cannot silently pass). Applying the head-lock mutation to a real-Postgres run makes 2 of its 3 tests fail. `npm run test:pg` starts a throw-away embedded Postgres. commit: `<add hash>`

---

## Entry 4: 2026-10-19 · Authorisation · a revoked user's download served *after* the revoke committed

**Asked:** (same as Entry 3) serialise a download against a concurrent revoke. The AI's design: take a row lock on the document inside `resolveAccess()` with `SELECT … LEFT JOIN grants … FOR SHARE OF d`, and have revoke take `FOR UPDATE OF d`. It reported this as correct.

**Produced / wrong:** one statement did both jobs, "lock the document" and "evaluate the grant". Under READ COMMITTED, a statement that waits for a row lock re-checks only the *locked* row; the joined `grants` row stays as it was in the snapshot the statement started with. So a download that queued behind a revoke still saw the grant as live, was served, and was then audited with a sequence number *after* the revoke. The record said a revoked user downloaded the file. This is the exact failure the brief calls out ("taking access away works immediately").

**How caught:** not by review. My first version of the race test passed by luck. I ran the real-Postgres suite once more at the end and it failed (`9 !== 0` downloads served after the revoke). I then looped the test: it failed about 1 run in 7. The diagnosis above is the standard READ COMMITTED lock-wait behaviour, and I confirm it empirically rather than by citation: after the fix below, 10 consecutive runs of a 15-round version of the test pass, and restoring the single-statement version in a scratch copy fails on round 0 or 1 in 3 of 3 runs.

**Fixed:** `resolveAccess()` now takes the lock in its own statement and evaluates access in a **second, fresh statement**, which sees the committed revocation. The test was changed from one race to 15 rounds so one lucky pass is no longer evidence. commit: `<add hash>`

**Lesson recorded:** a concurrency test that passes once proves nothing; loop it, and make sure the *buggy* version fails reliably before trusting the fixed version.

---

## Entry 5: 2026-10-19 · Tests · an assertion that could not fail

**Asked:** a test that hostile filenames (`../../etc/passwd`, CR/LF, NUL, quotes) are sanitised.

**Produced:** one upload with `'../../etc/pass\u0000wd\r\n"x.txt'`, then:
`assert.equal(stored, 'passwd"x.txt'.replace('"','') === stored ? 'passwdx.txt' : stored)`

**Wrong:** two bugs. (a) the assertion is a tautology (if the first branch is false the expected value *is* `stored`), so it could never fail; (b) a NUL byte makes the multipart request itself malformed, so the server correctly answered 400 and the test errored before reaching the assertion at all.

**How caught:** the run failed on (b); reading the line to fix it exposed (a).

**Fixed:** a loop over six hostile names asserting the *stored* name contains no path separators, control characters, quotes or leading dot, that the download's `Content-Disposition` has no CR/LF and no injected `Set-Cookie`, plus a separate NUL case that must store nothing. A follow-up failure (`....txt` → extension-less → correctly refused 415) was my test being wrong, not the server. commit: `<add hash>`

---

## Entry 6: 2026-10-19 · UI · code my own CSP forbids

**Asked:** a no-build single-page UI for the three roles.

**Produced:** working-looking JS that used two inline `style="…"` attributes and a `javascript:void(0)` link.

**Wrong:** the app's own CSP (`script-src 'self'; style-src 'self'`) blocks both. Reading the code, nothing looked broken.

**How caught:** `scripts/ui-smoke.js` drives the UI in headless Chromium for all three roles and fails on any console error. It also found a `401` in the console from the signed-out `/auth/me` probe, which I changed to return `{user:null}`.

**Fixed:** classes instead of inline styles, a button instead of the `javascript:` link, `/auth/me` returns 200 when signed out. commit: `<add hash>`

---

## Entry 7: 2026-10-19 · Design choice I overrode · the AI advisor

**Asked (my direction, not a bug):** the brief says AI may suggest access but never widen it. The default move is an LLM call over document text and names.

**I chose instead:** a local rule-based advisor over the owner's own grant history. Reason: sending confidential titles/people to a third-party model to decide who may see a confidential file is itself an exposure. Structural guarantees: it has no write path to `grants`; it only ever proposes `read`; a suggestion id is accepted only for the owner/document/user it was issued for; `ai.suggest`, the grant, and `ai.suggestion.accepted` (with human, final permission, overridden?) are all audited. This is what `THREATS.md` section G tests.

---

## Where I checked something and it held

- HMAC-chain verification catching all five tampering cases with the triggers disabled (`audit.test.js`): checked by hand-editing rows inside the test, not by trusting the code.
- Gap-free audit sequence under 40 parallel writers on separate connections (real Postgres), repeated runs.

**A correction to an earlier draft of this file:** it said the document-row lock ordering in `resolveAccess` had been verified by a 20-downloads-against-one-revoke race. That claim was premature: the test had passed once by luck and the lock design was in fact broken (Entry 4). I left the lesson in rather than deleting the mistake.

## What I have not verified

I have **not** attacked the deployed instances from outside, and I did not run a dependency/penetration scanner beyond `npm audit`. Everything is tested in-process against the real HTTP stack.

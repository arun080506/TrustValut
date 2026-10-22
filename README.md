# TrustVault

Secure document sharing where the wrong person cannot read a file, and you can prove who did.

Node 22 · Express · PostgreSQL · no build step · one codebase that deploys to **Render** and **Vercel**.

| | |
|---|---|
| Live URL (Render) | `https://trustvalut.onrender.com`|
| Docs | [API.md](API.md) · [THREATS.md](THREATS.md) · [PROMPTS.md](PROMPTS.md) · [WRITEUP.md](WRITEUP.md) |

## Demo accounts (seeded when `SEED_DEMO=true`)

| Role | Email | Password |
| Administrator — Arun | `arun.admin@trustvault.demo` | `Arun-Demo-2026!` |
| Document owner — Sree | `sree.owner@trustvault.demo` | `Sree-Demo-2026!` |
| Document owner — Yaswanth | `yaswanth.owner@trustvault.demo` | `Yaswanth-Demo-2026!` |
| Viewer — Pavan | `pavan.viewer@trustvault.demo` | `Pavan-Demo-2026!` |
| Viewer — Sasank | `sasank.viewer@trustvault.demo` | `Sasank-Demo-2026!` |

Seed layout: Sree owns *Salary letter* (nobody else), *Acme customer contract* (Pavan: read), *FY26 audit workpapers* (Yaswanth: edit).
Yaswanth owns *Partner drawings* (Sasank: read) and *Regulator submission* (nobody else).
Good first checks: sign in as Pavan and confirm you see only the Acme contract; as Sree remove Pavan's access and watch Pavan's next click fail; as Arun open **Audit trail → Refused only**.

> The demo passwords are public by design. **Never run `SEED_DEMO=true` against a system holding real documents.** On startup, demo seeding migrates the six previous demo emails—including the former Sai owner login—and reconciles these exact demo accounts to the published names, emails and passwords. Changed credentials revoke active sessions and are recorded in the audit trail.

## Roles

| | Admin | Owner | Viewer |
|---|---|---|---|
| Upload documents | – | yes | – |
| Read / download a document | only if granted | own + granted | only if granted |
| Edit metadata, upload versions | only if granted *edit* | own + granted *edit* | never (capped at read) |
| Delete / restore, grant & revoke | – | own documents only | – |
| See who accessed a document | – | own documents | – |
| Manage users, sessions, passwords | yes | – | – |
| See all document metadata, grants, audit trail | yes | – | – |
| Emergency-revoke a grant | yes (audited) | – | – |

**Administrators cannot read file contents.** They govern access; they do not hold it. The full permission model is in [WRITEUP.md](WRITEUP.md).

## Run it locally

```bash
npm install
npm run dev          # in-process Postgres (PGlite) + demo data, http://localhost:3000
npm test             # 53 tests (3 need a real server, see below)
```

Needs Node ≥ 20. No database server required for dev/test.

```bash
npm run test:pg      # the same suite against a REAL PostgreSQL server (embedded, throw-away).
                     # Postgres refuses to run as root; in a root container use:
                     #   runuser -u nobody -- env HOME=/tmp PATH="$PATH" npm run test:pg
npm run ui:smoke     # drives the real UI in headless Chromium; fails on any CSP/console error
npm run mutation     # removes each security control in turn and proves the tests fail (see below)
```

## Deploy

You need a PostgreSQL database in both cases. Secrets come from `npm run keys`.

**Important, read once:** `FILE_MASTER_KEY` encrypts every file. If you lose it, every stored file is permanently unreadable. Keep a copy somewhere that is not the hosting dashboard. `AUDIT_HMAC_KEY` signs the audit chain; if it changes, old entries no longer verify.

### Render (web service + Postgres, one click)

1. Push this repo to GitHub.
2. Render dashboard → **New → Blueprint** → select the repo. `render.yaml` creates the web service, a free Postgres database, generates both keys, and sets `SEED_DEMO=true`.
3. When it is live, open `/api/health` (should return `{"ok":true}`), then sign in with a demo account.
4. For real use: set `SEED_DEMO` to `false` and create real users from the admin screen (delete or deactivate the demo accounts first).

Render's free Postgres expires after 30 days; use a paid instance for anything lasting. The purge cron job in `render.yaml` needs a paid cron plan; without it run `npm run purge` yourself or use the Vercel cron.

### Vercel (serverless) + Neon / Supabase / any Postgres

1. Create a Postgres database (e.g. Neon, free). Copy its connection string (it must include `sslmode=require`).
2. Vercel → **Add New → Project** → import the repo. Framework preset: *Other*. No build command.
3. Environment variables (Production): `NODE_ENV=production`, `DATABASE_URL`, `FILE_MASTER_KEY`, `AUDIT_HMAC_KEY`, `CRON_SECRET`, `SEED_DEMO=true` (demo only).
4. Deploy. The schema is created automatically on the first request (guarded by a Postgres advisory lock so concurrent cold starts are safe).

Vercel limits request bodies to about 4.5 MB, so the default upload cap is 4 MB. `vercel.json` registers a daily cron for the retention purge, authenticated with `CRON_SECRET`.

### From a clean clone, by hand (any host with Node and Postgres)

```bash
git clone <repo> && cd trustvault && npm ci --omit=dev
npm run keys                       # copy the output into your environment
export NODE_ENV=production DATABASE_URL=postgres://... FILE_MASTER_KEY=... AUDIT_HMAC_KEY=...
npm run migrate                    # optional: the server also migrates at boot
npm run seed                       # optional demo data (empty database only)
npm start
```

In production the app **refuses to start** if `DATABASE_URL`, `FILE_MASTER_KEY` or `AUDIT_HMAC_KEY` is missing, so it can never silently run with a development key.

## Database

`db/schema.sql` is the whole schema and is idempotent (runs on every boot). Tables: `users`, `sessions`, `documents`, `document_versions` (encrypted bytes), `grants`, `ai_suggestions`, `audit_log`, `audit_head`.

## Operating it

| Task | How |
|---|---|
| Verify the audit trail | Admin → Overview shows it on every load; or `npm run audit:verify` (exit 1 if altered) |
| Offboard someone | Admin → Users → **Deactivate** (kills their sessions at once). Their documents stay; use Admin → Documents → transfer endpoint (see API.md) |
| Revoke a leaver's access to a document | Owner: document → *Remove*. Admin: Documents → Grants → *Emergency revoke* |
| Retention purge | `npm run purge` (or the Render / Vercel cron). Destroys bytes, keeps metadata and audit |
| Rotate `AUDIT_HMAC_KEY` / `FILE_MASTER_KEY` | Not supported in-place (see THREATS.md, accepted risk A1) |

Log lines starting `AUDIT_ANCHOR <seq> <hash>` are printed on every audit write. Keep your platform's log drain: it is an independent copy of the chain head that catches someone deleting the newest rows *and* resetting the head.

## "Take one authorisation check out and run the tests"

`npm run mutation` does it for you: 37 mutations, each deleting or weakening exactly one control (the grant lookup, the permission comparison, the revoked/expired filters, the viewer ceiling, CSRF, the session `active` check, the audit HMAC check, the DB triggers, the GCM binding, magic-byte validation…), then runs the suite on the mutated copy and requires failure. Result of the last run: **36/37 caught on PGlite**. The survivor is the audit-head row lock, which only a real multi-connection server can race; `npm run test:pg` kills it. (That same real-server test also found, and now guards, a genuine revocation race: see PROMPTS.md entry 4.)

## Layout

```
src/authz.js          THE document access decision (one function, read it first)
src/routes/documents  every document route; authorize() is called inside each transaction
src/audit.js          hash-chained, HMAC-signed, append-only audit log
src/crypto.js         scrypt passwords; AES-256-GCM per-version keys bound to document id + version
src/validate.js       upload allow-list: extension + magic bytes + server-chosen MIME
src/suggest.js        access advisor (read-only; cannot grant)
db/schema.sql         schema + append-only triggers
test/                 53 tests: isolation, grants/revocation, audit tamper, uploads, hardening, concurrency
scripts/              migrate, seed, keys, audit verify, purge, mutation-check, test-pg, ui-smoke
api/index.js          Vercel entry (same Express app)
```

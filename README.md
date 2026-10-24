# Vaultora

Secure document sharing where the wrong person cannot read a file, and you can prove who did.

Node 24 · Express · PostgreSQL · no build step · one codebase designed to deploy to **Render** and **Vercel**.

| Live URL (Render) |
|---|
| `https://trustvalut.onrender.com` |

| Docs |
|---|
| [API.md](API.md) · [THREATS.md](THREATS.md) · [PROMPTS.md](PROMPTS.md) · [WRITEUP.md](WRITEUP.md) |


## Demo accounts

Demo accounts are seeded when `SEED_DEMO=true`.

| Role | Email | Password |
|---|---|---|
| Administrator — Arun | `arun.admin@trustvault.demo` | `Arun-Demo-2026!` |
| Document owner — Sree | `sree.owner@trustvault.demo` | `Sree-Demo-2026!` |
| Document owner — Yaswanth | `yaswanth.owner@trustvault.demo` | `Yaswanth-Demo-2026!` |
| Viewer — Pavan | `pavan.viewer@trustvault.demo` | `Pavan-Demo-2026!` |
| Viewer — Sasank | `sasank.viewer@trustvault.demo` | `Sasank-Demo-2026!` |

### Seed layout

- Sree owns **Salary letter** — nobody else has access.
- Sree owns **Acme customer contract** — Pavan has read access.
- Sree owns **FY26 audit workpapers** — Yaswanth has edit access.
- Yaswanth owns **Partner drawings** — Sasank has read access.
- Yaswanth owns **Regulator submission** — nobody else has access.


> The demo passwords are public by design. **Never run `SEED_DEMO=true` against a system holding real documents.**

## Roles

| | Admin | Owner | Viewer |
|---|---|---|---|
| Upload documents | – | yes | – |
| Read / download a document | only if explicitly granted | own + explicitly granted | only if explicitly granted |
| Edit metadata, upload versions | only if granted *edit* | own + granted *edit* | never (capped at read) |
| Delete / restore, grant & revoke | – | own documents only | – |
| See who accessed a document | – | own documents | – |
| Manage users, sessions, passwords | yes | – | – |
| See all document metadata, grants, audit trail | yes | – | – |
| Emergency-revoke a grant | yes (audited) | – | – |

**Administrators cannot read file contents.** They govern access; they do not hold document-reading access.

The full permission model is documented in [WRITEUP.md](WRITEUP.md).

## Run it locally

Requirements: **Node 24**.

No database server is required for local development or the standard test suite because development and test mode use PGlite.

```bash
npm install
npm run dev
npm test
```

The development server runs at:

```text
http://localhost:3000
```

### Additional tests

```bash
npm run test:pg
npm run ui:smoke
npm run mutation
```

`npm run test:pg` runs the test suite against a real PostgreSQL server using an embedded throw-away database.

`npm run ui:smoke` drives the real UI in headless Chromium and checks for CSP or console errors.

`npm run mutation` removes or weakens security controls one at a time and verifies that the tests fail when those controls are missing.

## Deploy

Production deployments require a PostgreSQL database and the required security secrets.

Secrets can be generated using:

```bash
npm run keys
```

### Important security note

`FILE_MASTER_KEY` encrypts every stored file. If this key is lost, the stored encrypted files are permanently unreadable.

Keep a secure copy of the production key outside the hosting dashboard.

`AUDIT_HMAC_KEY` protects the integrity of the audit trail and should also be backed up securely.

## Render

Render is the currently working production deployment.

The project includes a `render.yaml` Blueprint for the web service and PostgreSQL database.

1. Push the repository to GitHub.
2. Open the Render dashboard.
3. Select **New → Blueprint**.
4. Select the GitHub repository.
5. Render creates the web service and PostgreSQL database using `render.yaml`.
6. The required security keys are generated through the deployment configuration.
7. `SEED_DEMO=true` is enabled for the demo environment.

After deployment, check:

```text
https://trustvalut.onrender.com/api/health
```

The expected response is:

```json
{"ok":true}
```

Then sign in using one of the demo accounts listed above.

For real use, set:

```text
SEED_DEMO=false
```

and create real users from the administrator interface.

Render's free PostgreSQL plan is intended for temporary/demo use. For a long-running production system, use an appropriate paid database plan.

## Vercel

The application is designed to use the same Express application on Vercel through the dedicated:

```text
api/index.js
```

entrypoint.

The Vercel deployment is configured separately from the normal server startup used by Render.

The frontend loads on Vercel, but some authenticated API requests currently have a Vercel-specific runtime issue. This deployment is still being fixed.

**Render is the currently working production deployment and should be used for evaluation.**

The Vercel issue does not affect the working Render deployment.

## From a clean clone, by hand

Any host with Node 24 and PostgreSQL can run the application using:

```bash
git clone <repo>
cd vaultora
npm ci --omit=dev
npm run keys
```

Set the production environment variables:

```bash
export NODE_ENV=production
export DATABASE_URL=postgres://...
export FILE_MASTER_KEY=...
export AUDIT_HMAC_KEY=...
```

Then run:

```bash
npm run migrate
npm run seed
npm start
```

`npm run migrate` is optional because the server also performs the required schema migration at startup.

`npm run seed` is optional and should only be used when demo data is wanted.

In production the application refuses to start if `DATABASE_URL`, `FILE_MASTER_KEY`, or `AUDIT_HMAC_KEY` is missing. This prevents the application from silently running with development keys.

## Database

`db/schema.sql` contains the complete database schema and is designed to be safely applied during application startup.

Main tables include:

- `users`
- `sessions`
- `documents`
- `document_versions`
- `grants`
- `ai_suggestions`
- `audit_log`

Document versions contain encrypted file bytes.

The database also contains protections for the append-only audit trail.

## Operating the application

| Task | How |
|---|---|
| Verify the audit trail | Admin → Overview shows the audit status on every load, or run `npm run audit:verify` |
| Offboard someone | Admin → Users → **Deactivate**; their sessions are revoked immediately |
| Transfer a leaver's documents | Use the administrator document transfer functionality described in `API.md` |
| Revoke a user's document access | Owner: document → **Remove**; Admin: Documents → Grants → **Emergency revoke** |
| Retention purge | Run `npm run purge` or configure the appropriate scheduled job |
| Rotate `AUDIT_HMAC_KEY` / `FILE_MASTER_KEY` | Not currently supported in-place; see `THREATS.md`, accepted risk A1 |

Audit writes print log lines beginning with:

```text
AUDIT_ANCHOR <seq> <hash>
```

These provide an independent copy of the latest audit-chain head in the platform logs.

## Security model

Vaultora is designed around server-side authorization.

The important security properties are:

- Document access is checked on the server.
- Users cannot access another user's documents merely by changing an ID in a request.
- Grants are checked for the specific document and user.
- Read and edit permissions are enforced separately.
- Viewers cannot escalate themselves to edit access.
- Revoked access is checked again when the document is requested.
- User deactivation invalidates their active sessions.
- File contents are encrypted at rest.
- Each document version has its own encryption key.
- Encryption uses AES-256-GCM.
- Passwords are protected using scrypt.
- Uploads are checked using extension, magic bytes, and server-selected MIME type.
- Audit entries are hash chained and HMAC signed.
- Refused access attempts are recorded.
- Administrators can manage access and audit information but cannot read document contents.

## AI access advisor

Vaultora includes a read-only access advisor.

The advisor can suggest access decisions based on available information, but it **cannot grant access**.

Actual authorization remains under the application's normal server-side permission checks.

## AI usage

Claude AI was used as a coding and development assistant during the project.

I used AI for:

- Planning the application architecture and security model.
- Generating and improving parts of the code.
- Debugging deployment and runtime issues.
- Writing and improving tests.
- Reviewing authorization and security controls.
- Improving documentation and deployment instructions.

I did not blindly accept generated code. I tested the changes, checked the behavior locally and on the deployed application, and changed or rejected suggestions when they did not work correctly.

One example was an Express export/import issue during deployment. An AI-generated change used a different module export style than the server expected, which caused the application to fail. I identified the mismatch from the error, corrected the import/export, and tested the application again.

AI was used as a development assistant, while the final implementation and testing were reviewed and verified by me.

## "Take one authorisation check out and run the tests"

The project includes mutation testing through:

```bash
npm run mutation
```

The mutation script removes or weakens security controls one at a time, including controls around:

- Grant lookup
- Permission comparison
- Revoked and expired grants
- Viewer permission ceiling
- CSRF protection
- Authentication
- Document ownership
- Audit logging
- Upload validation
- Session handling

The purpose is to demonstrate that the security tests fail when important authorization controls are removed.

## Testing

The test suite covers areas including:

- Document isolation
- Document grants
- Access revocation
- Permission levels
- Session revocation
- Audit integrity
- Audit tampering
- Encrypted document storage
- Upload validation
- Authentication hardening
- Authorization controls
- Concurrency behavior

Run the main test suite with:

```bash
npm test
```

For real PostgreSQL behavior:

```bash
npm run test:pg
```

For the real browser UI:

```bash
npm run ui:smoke
```

For security mutation testing:

```bash
npm run mutation
```

## Project layout

```text
src/authz.js
    Main document access decision.

src/routes/documents
    Document routes. Authorization is checked inside the relevant transactions.

src/audit.js
    Hash-chained, HMAC-signed, append-only audit log.

src/crypto.js
    Password hashing and AES-256-GCM document encryption.

src/validate.js
    Upload validation using extension, magic bytes, and server-selected MIME type.

src/suggest.js
    Read-only access advisor that cannot grant permissions.

db/schema.sql
    Database schema and append-only audit protections.

test/
    Security, isolation, grants, revocation, audit, upload,
    hardening, and concurrency tests.

scripts/
    Migration, seed, key generation, audit verification,
    purge, mutation testing, PostgreSQL testing, and UI smoke testing.

api/index.js
    Vercel entrypoint using the same Express application.
```

## Current deployment status

### Working

- Render production deployment
- Login and authentication
- Document upload and management
- Document sharing
- Read and edit permissions
- Access revocation
- Server-side authorization
- Audit trail
- Refused-access recording
- Document encryption
- Security tests

### Still being fixed

- Vercel authenticated API runtime issue

The Render deployment is the current live version for evaluation.

## Project documentation

Additional technical documentation:

- [API.md](API.md) — API routes and behavior
- [THREATS.md](THREATS.md) — security threats and accepted risks
- [PROMPTS.md](PROMPTS.md) — development prompts and security requirements
- [WRITEUP.md](WRITEUP.md) — architecture and permission model

## Final note

Vaultora was built to demonstrate that secure document sharing is not only about hiding files from unauthorized users. The application also needs to prove who had access, enforce revocation, record refused attempts, and prevent administrators from bypassing document-level access controls.

The main application is currently running on Render and is available at:

`https://trustvalut.onrender.com`

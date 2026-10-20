'use strict';
/**
 * "Take one authorisation check out of the code and run the tests. If they still pass,
 * they were not testing anything."  This script does exactly that, automatically.
 *
 * For each mutation it copies the project to a temp directory, weakens ONE security control,
 * runs the whole test suite there, and expects it to FAIL. A mutation that survives (tests
 * still green) means a control with no test behind it, and the script exits non-zero.
 *
 *   npm run mutation              # all mutations, 3 at a time
 *   npm run mutation -- authz     # only mutations whose name contains "authz"
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const MODULE_LINK_TYPE = process.platform === 'win32' ? 'junction' : 'dir';

const MUTATIONS = [
  // --- the authorisation decision itself
  { name: 'authz: anyone with no grant gets read', file: 'src/authz.js', find: "else if (grantPermission) level = grantPermission;", to: "else level = grantPermission || 'read';" },
  { name: 'authz: permission levels are never compared', file: 'src/authz.js', find: 'const can = (level, need) => Boolean(level) && RANK[level] >= RANK[need];', to: 'const can = () => true;' },
  { name: 'authz: revoked grants still count', file: 'src/authz.js', find: 'AND g.revoked_at IS NULL', to: 'AND TRUE' },
  { name: 'authz: expired grants still count', file: 'src/authz.js', find: 'AND (g.expires_at IS NULL OR g.expires_at > now())', to: 'AND TRUE' },
  { name: 'authz: deleted documents stay visible to grantees', file: 'src/authz.js', find: "if (doc.deleted_at && level !== 'owner') return null;", to: '' },
  { name: 'authz: viewer role ceiling removed', file: 'src/authz.js', find: "if (level === 'edit' && user.role === 'viewer') level = 'read';", to: '' },
  { name: 'authz: purged documents stay reachable', file: 'src/authz.js', find: 'if (doc.purged_at) return null;', to: '' },
  // --- where the decision is applied
  { name: 'route: insufficient-permission check removed', file: 'src/routes/documents.js', find: 'if (!can(r.level, need)) {', to: 'if (false) {' },
  { name: 'route: no-access check removed from authorize()', file: 'src/routes/documents.js', find: 'if (!r || (r.doc.deleted_at && !allowDeleted)) {', to: 'if (r && r.doc.deleted_at && !allowDeleted) {' },
  { name: 'route: revoke does not actually revoke', file: 'src/routes/documents.js', find: 'SET revoked_at = now(), revoked_by = $3 WHERE document_id = $1 AND user_id = $2', to: 'SET revoked_by = $3 WHERE document_id = $1 AND user_id = $2' },
  { name: 'route: refusals are not audited', file: 'src/routes/documents.js', find: /await audit\.record\(db, \{\n      actor: req\.user, action: 'access\.denied'/, to: "if (false) await audit.record(db, {\n      actor: req.user, action: 'access.denied'" },
  { name: 'route: viewers may upload', file: 'src/routes/documents.js', find: "router.post('/', requireRole('owner'),", to: "router.post('/'," },
  { name: 'route: viewers may use the people directory', file: 'src/routes/users.js', find: "requireRole('owner', 'admin'), asyncHandler", to: 'asyncHandler' },
  { name: 'route: admin endpoints open to every role', file: 'src/routes/admin.js', find: "router.use(requireAuth, requireRole('admin'));", to: 'router.use(requireAuth);' },
  { name: 'search: listing ignores grants', file: 'src/docs-service.js', find: "else where.push('(d.owner_id = $1 OR g.id IS NOT NULL)');", to: "else where.push('TRUE');" },
  { name: 'search: "shared" scope ignores grants', file: 'src/docs-service.js', find: "else if (f.scope === 'shared') where.push('d.owner_id <> $1 AND g.id IS NOT NULL');", to: "else if (f.scope === 'shared') where.push('d.owner_id <> $1');" },
  { name: 'categories endpoint ignores grants', file: 'src/routes/documents.js', find: 'WHERE d.deleted_at IS NULL AND (d.owner_id = $1 OR g.id IS NOT NULL) ORDER BY 1', to: 'WHERE d.deleted_at IS NULL ORDER BY 1' },
  // --- sessions, CSRF, accounts
  { name: 'session: deactivated users keep working', file: 'src/auth.js', find: 'AND s.expires_at > now() AND u.active = true', to: 'AND s.expires_at > now()' },
  { name: 'session: revoked sessions keep working', file: 'src/auth.js', find: 's.revoked_at IS NULL AND s.expires_at', to: 'TRUE AND s.expires_at' },
  { name: 'csrf: token check removed', file: 'src/auth.js', find: "if (typeof header !== 'string' || !safeEqual(header, req.session.csrf)) {", to: 'if (false) {' },
  { name: 'csrf: cross-origin check removed', file: 'src/auth.js', find: "if (!host || host !== req.headers.host) return next(", to: 'if (false) return next(' },
  { name: 'login: account lockout removed', file: 'src/routes/auth.js', find: "} else if (locked) {", to: '} else if (false) {' },
  { name: 'password change keeps other sessions alive', file: 'src/routes/auth.js', find: 'UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND id_hash <> $2 AND revoked_at IS NULL', to: 'SELECT 1 WHERE $1 = $1 AND $2 = $2' },
  { name: 'demo: credential migration keeps legacy sessions alive', file: 'src/seed.js', find: 'const sessionsRevoked = await revokeAllSessions(tx, current.id);', to: 'const sessionsRevoked = 0;' },
  { name: 'admin: owner-active guard on transfer removed', file: 'src/routes/admin.js', find: "if (d.owner_active) throw", to: 'if (false) throw' },
  { name: 'admin: deactivation does not revoke sessions', file: 'src/routes/admin.js', find: 'const killed = await revokeAllSessions(tx, u.id);', to: 'const killed = 0;' },
  // --- audit trail
  { name: 'audit: HMAC comparison removed', file: 'src/audit.js', find: 'if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {', to: 'if (false) {' },
  { name: 'audit: head / tail-truncation check removed', file: 'src/audit.js', find: 'if (head.seq !== count || head.hash !== prev) {', to: 'if (false) {' },
  { name: 'audit: gap detection removed', file: 'src/audit.js', find: 'if (r.seq !== expected) return', to: 'if (false) return' },
  { name: 'audit: database no longer rejects edits', file: 'db/schema.sql', find: "RAISE EXCEPTION 'audit_log is append-only';", to: 'RETURN NEW;' },
  { name: 'audit: chain is not serialised (no head lock)', file: 'src/audit.js', find: 'FROM audit_head WHERE id = 1 FOR UPDATE', to: 'FROM audit_head WHERE id = 1' },
  { name: 'audit: download is not audited', file: 'src/routes/documents.js', find: "actor: req.user, action: 'doc.download', docId: r.doc.id", to: "actor: req.user, action: 'doc.noop', docId: r.doc.id" },
  // --- storage and uploads
  { name: 'crypto: ciphertext not bound to its document', file: 'src/crypto.js', find: 'const aadFor = (documentId, version) => Buffer.from(`trustvault:v1:${documentId}:${version}`);', to: "const aadFor = () => Buffer.from('static');" },
  { name: 'upload: magic-byte check removed', file: 'src/validate.js', find: 'if (!type.check(buffer)) {', to: 'if (false) {' },
  { name: 'upload: extension allow-list removed', file: 'src/validate.js', find: 'if (!type) {', to: 'if (false) {' },
  { name: 'upload: size limit removed', file: 'src/routes/documents.js', find: 'limits: { fileSize: config.maxUploadBytes,', to: 'limits: { fileSize: Infinity,' },
  { name: 'download: attachment disposition removed', file: 'src/routes/documents.js', find: '`attachment; filename=', to: '`inline; filename=' },
  { name: 'suggestion: advisor proposes edit access', file: 'src/suggest.js', find: "suggestedPermission: 'read',", to: "suggestedPermission: 'edit'," },
];

function applyMutation(dir, m) {
  const p = path.join(dir, m.file);
  const src = fs.readFileSync(p, 'utf8');
  const out = typeof m.find === 'string' ? src.replace(m.find, () => m.to) : src.replace(m.find, m.to);
  if (out === src) throw new Error(`mutation did not apply (pattern not found): ${m.name}`);
  fs.writeFileSync(p, out);
}

function runTests(dir) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-concurrency=1', 'test/isolation.test.js', 'test/grants.test.js', 'test/audit.test.js', 'test/upload.test.js', 'test/seed.test.js'], { cwd: dir, env: { ...process.env, NODE_ENV: 'test' } });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    const timer = setTimeout(() => child.kill('SIGKILL'), 240000);
    child.on('close', (code) => {
      clearTimeout(timer);
      const failed = Number((out.match(/^(?:#|ℹ) fail (\d+)/m) || [])[1] || 0);
      resolve({ code, failed, out });
    });
  });
}

async function runOne(m, tmpRoot, i) {
  const dir = path.join(tmpRoot, 'm' + i);
  for (const d of ['src', 'db', 'test', 'scripts']) fs.cpSync(path.join(ROOT, d), path.join(dir, d), { recursive: true });
  fs.copyFileSync(path.join(ROOT, 'package.json'), path.join(dir, 'package.json'));
  fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(dir, 'node_modules'), MODULE_LINK_TYPE);
  applyMutation(dir, m);
  const r = await runTests(dir);
  fs.rmSync(dir, { recursive: true, force: true });
  return { m, killed: r.code !== 0, failed: r.failed };
}

(async () => {
  const filter = process.argv[2];
  const list = MUTATIONS.filter((m) => !filter || m.name.toLowerCase().includes(filter.toLowerCase()));
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-mutation-'));

  // Baseline must be green, or "killed" would be meaningless.
  const base = path.join(tmpRoot, 'base');
  for (const d of ['src', 'db', 'test', 'scripts']) fs.cpSync(path.join(ROOT, d), path.join(base, d), { recursive: true });
  fs.copyFileSync(path.join(ROOT, 'package.json'), path.join(base, 'package.json'));
  fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(base, 'node_modules'), MODULE_LINK_TYPE);
  const b = await runTests(base);
  if (b.code !== 0) { console.error('Baseline tests fail; fix them before running mutations.\n' + b.out.slice(-2000)); process.exit(2); }
  console.log(`Baseline green. Running ${list.length} mutation(s)...\n`);

  const results = [];
  let next = 0;
  const workers = Array.from({ length: 3 }, async () => {
    while (next < list.length) {
      const i = next++;
      const r = await runOne(list[i], tmpRoot, i);
      results[i] = r;
      console.log(`${r.killed ? 'KILLED  ' : 'SURVIVED'}  ${r.m.name}${r.killed ? `  (${r.failed} failing)` : ''}`);
    }
  });
  await Promise.all(workers);
  fs.rmSync(tmpRoot, { recursive: true, force: true });

  const survived = results.filter((r) => !r.killed);
  console.log(`\n${results.length - survived.length}/${results.length} mutations were caught by the tests.`);
  if (survived.length) {
    console.log('SURVIVORS (controls with no test behind them):');
    for (const s of survived) console.log('  - ' + s.m.name);
    process.exit(1);
  }
})().catch((e) => { console.error(e); process.exit(2); });

'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { start, Client } = require('./helper');
const { createUser } = require('../src/users');
const { hashPassword } = require('../src/crypto');
const { seedDemo, DEMO } = require('../src/seed');

let t;
before(async () => { t = await start(); });
after(() => t.stop());

test('demo credential migration updates only legacy demo accounts and revokes their sessions', async () => {
  const previous = [
    { email: 'alice.owner@trustvault.demo', name: 'Aarav Mehta', role: 'owner', password: 'Owner-Demo-2026!' },
    { email: 'bob.owner@trustvault.demo', name: 'Priya Iyer', role: 'owner', password: 'Owner-Demo-2026!' },
    { email: 'carol.viewer@trustvault.demo', name: 'Ananya Rao', role: 'viewer', password: 'Viewer-Demo-2026!' },
    { email: 'dave.viewer@trustvault.demo', name: 'Rohan Shah', role: 'viewer', password: 'Viewer-Demo-2026!' },
  ];
  const legacySessions = [];
  for (const account of previous) {
    await createUser(t.db, account);
    const client = new Client(t.base);
    assert.equal((await client.login(account.email, account.password)).status, 200);
    legacySessions.push(client);
  }
  const currentDemoAdmin = await createUser(t.db, {
    ...DEMO.admin,
    password: 'Out-of-sync-password-2026!',
  });
  const staleAdminSession = new Client(t.base);
  assert.equal((await staleAdminSession.login(currentDemoAdmin.email, 'Out-of-sync-password-2026!')).status, 200);
  await t.db.query(
    'UPDATE users SET failed_logins = 5, locked_until = now() + interval \'15 minutes\' WHERE id = $1',
    [currentDemoAdmin.id]);

  assert.equal(await seedDemo(t.db), false, 'existing databases should migrate accounts without reseeding documents');
  for (const client of [...legacySessions, staleAdminSession]) {
    assert.equal((await client.get('/api/admin/summary')).status, 401, 'old session must be revoked');
  }

  const migrated = (await t.db.query(
    `SELECT email, name, role FROM users
      WHERE email = ANY($1)
      ORDER BY email`,
    [Object.values(DEMO).map((u) => u.email)])).rows;
  assert.deepEqual(migrated, Object.values(DEMO)
    .map(({ email, name, role }) => ({ email, name, role }))
    .sort((a, b) => a.email.localeCompare(b.email)));

  let sreeClient;
  for (const account of Object.values(DEMO)) {
    const client = new Client(t.base);
    assert.equal((await client.login(account.email, account.password)).status, 200, `${account.email} should accept its new credentials`);
    if (account.email === DEMO.sree.email) sreeClient = client;
  }
  const migratedSree = (await t.db.query(
    'SELECT id FROM users WHERE email = $1',
    [DEMO.sree.email])).rows[0];
  assert.ok(migratedSree, 'the legacy owner login should migrate to Sree');
  const admin = new Client(t.base);
  assert.equal((await admin.login(DEMO.admin.email, DEMO.admin.password)).status, 200);
  const summary = await admin.get('/api/admin/summary');
  assert.equal(summary.status, 200);
  assert.ok(summary.json.recentSensitive.every((entry) => entry.actor_email !== 'system:seed'),
    'demo setup changes should not clutter the overview sensitive-changes summary');
  const fullAudit = await admin.get('/api/admin/audit?action=admin.user_credentials_update');
  assert.equal(fullAudit.status, 200);
  assert.equal(fullAudit.json.entries.length, 5, 'setup changes remain available in the full audit trail');
  assert.equal((await t.db.query(
    "SELECT count(*)::int AS n FROM audit_log WHERE action = 'admin.user_credentials_update'")).rows[0].n, 5);

  await t.db.query(
    'UPDATE users SET email = $2, name = $3, password_hash = $4 WHERE id = $1',
    [migratedSree.id, 'sai.owner@trustvault.demo', 'Sai', await hashPassword('Sai-Demo-2026!')]);
  const formerSaiSession = new Client(t.base);
  assert.equal((await formerSaiSession.login('sai.owner@trustvault.demo', 'Sai-Demo-2026!')).status, 200);
  assert.equal(await seedDemo(t.db), false, 'the former canonical owner login should migrate in place');
  assert.equal((await sreeClient.get('/api/admin/summary')).status, 401, 'the renamed account session must be revoked');
  assert.equal((await formerSaiSession.get('/api/admin/summary')).status, 401, 'the former login session must be revoked');
  const migratedAgain = (await t.db.query(
    'SELECT id, email, name FROM users WHERE email = $1',
    [DEMO.sree.email])).rows[0];
  assert.deepEqual(migratedAgain, { id: migratedSree.id, email: DEMO.sree.email, name: 'Sree' },
    'the existing owner account should be renamed, not recreated');
  const oldLogin = new Client(t.base);
  assert.equal((await oldLogin.login('sai.owner@trustvault.demo', 'Sai-Demo-2026!')).status, 401,
    'the former owner login must stop working');
  const newLogin = new Client(t.base);
  assert.equal((await newLogin.login(DEMO.sree.email, DEMO.sree.password)).status, 200,
    'the Sree login should work after migration');
  const newAudit = await admin.get('/api/admin/audit?action=admin.user_credentials_update');
  assert.equal(newAudit.json.entries.length, 6, 'the rename should be recorded in the audit trail');
  assert.equal(await seedDemo(t.db), false);
  assert.equal((await t.db.query(
    "SELECT count(*)::int AS n FROM audit_log WHERE action = 'admin.user_credentials_update'")).rows[0].n, 6, 'unchanged demo credentials should not be re-audited');
});

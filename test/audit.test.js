'use strict';
// THREAT: the audit trail is incomplete, or can be quietly altered.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { start } = require('./helper');
const audit = require('../src/audit');

let t, alice, bob, admin, docId;

before(async () => {
  t = await start();
  alice = await t.user('owner', 'alice');
  bob = await t.user('owner', 'bob');
  admin = await t.user('admin', 'root');
});
after(() => t.stop());

test('uploads, downloads, changes, deletions and permission changes are all recorded with actor and document', async () => {
  const up = await alice.client.upload('a.txt', 'hello audit', { name: 'Audit me', category: 'general' });
  docId = up.json.id;
  await alice.client.put(`/api/documents/${docId}/grants`, { userId: bob.id, permission: 'read' });
  await bob.client.get(`/api/documents/${docId}/download`);
  await alice.client.put(`/api/documents/${docId}/grants`, { userId: bob.id, permission: 'edit' });
  await bob.client.patch(`/api/documents/${docId}`, { name: 'Audit me too' });
  await bob.client.newVersion(docId, 'b.txt', 'second');
  await alice.client.del(`/api/documents/${docId}/grants/${bob.id}`);
  await bob.client.get(`/api/documents/${docId}/download`); // refused after revoke
  await alice.client.del(`/api/documents/${docId}`);
  await alice.client.post(`/api/documents/${docId}/restore`, {});

  const rows = await t.auditRows('doc_id = $1', [docId]);
  const seen = rows.map((r) => `${r.action}:${r.outcome}:${r.actor_email}`);
  const expect = [
    `doc.upload:allowed:${alice.email}`,
    `grant.add:allowed:${alice.email}`,
    `doc.download:allowed:${bob.email}`,
    `grant.change:allowed:${alice.email}`,
    `doc.update:allowed:${bob.email}`,
    `doc.version:allowed:${bob.email}`,
    `grant.revoke:allowed:${alice.email}`,
    `access.denied:denied:${bob.email}`,
    `doc.delete:allowed:${alice.email}`,
    `doc.restore:allowed:${alice.email}`,
  ];
  assert.deepEqual(seen, expect);
  const dl = rows.find((r) => r.action === 'doc.download');
  assert.equal(dl.detail.version, 1);
  assert.match(dl.detail.sha256, /^[0-9a-f]{64}$/);
  assert.ok(dl.ip);
  const g = rows.find((r) => r.action === 'grant.change');
  assert.equal(g.target_user_id, bob.id);
  assert.equal(g.detail.previous, 'read');
});

test('failed and successful sign-ins are recorded; lockout works without leaking which case it was', async () => {
  const c = new t.Client(t.base);
  for (let i = 0; i < 5; i++) assert.equal((await c.login(bob.email, 'wrong-password-123')).status, 401);
  const locked = await c.login(bob.email, t.PW); // correct password, but account is locked
  assert.equal(locked.status, 401);
  assert.equal(locked.json.error, 'invalid_credentials');
  const unknown = await c.login('nobody@example.test', 'whatever-123456');
  assert.deepEqual(unknown.json, locked.json, 'same body for unknown user and locked account');
  const fails = await t.auditRows("action = 'auth.login_failed' AND actor_email = $1", [bob.email]);
  assert.equal(fails.length, 6);
  assert.deepEqual([...new Set(fails.map((f) => f.detail.reason))].sort(), ['bad_password', 'locked']);
  await t.db.query('UPDATE users SET locked_until = NULL WHERE id = $1', [bob.id]);
});

test('the chain verifies when untouched', async () => {
  const r = await audit.verify(t.db);
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.ok(r.count > 10);
  const viaApi = await admin.client.get('/api/admin/audit/verify');
  assert.equal(viaApi.json.ok, true);
});

test('the database itself refuses UPDATE, DELETE and TRUNCATE on the audit log', async () => {
  await assert.rejects(t.db.query("UPDATE audit_log SET actor_email = 'someone.else@example.test' WHERE seq = 1"), /append-only/);
  await assert.rejects(t.db.query('DELETE FROM audit_log WHERE seq = 1'), /append-only/);
  await assert.rejects(t.db.exec('TRUNCATE audit_log'), /append-only/);
  assert.equal((await audit.verify(t.db)).ok, true);
});

test('even an attacker who disables the triggers cannot edit, delete, reorder or forge entries undetected', async () => {
  const withoutTriggers = async (fn) => {
    await t.db.exec('ALTER TABLE audit_log DISABLE TRIGGER USER');
    try { await fn(); } finally { await t.db.exec('ALTER TABLE audit_log ENABLE TRIGGER USER'); }
  };
  const snapshot = (await t.db.query('SELECT * FROM audit_log ORDER BY seq')).rows;
  const head = (await t.db.query('SELECT * FROM audit_head')).rows[0];
  const restore = async () => withoutTriggers(async () => {
    await t.db.exec('DELETE FROM audit_log');
    for (const r of snapshot) {
      await t.db.query('INSERT INTO audit_log(seq,ts,actor_id,actor_email,action,outcome,doc_id,target_user_id,ip,detail,prev_hash,hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)',
        [r.seq, r.ts, r.actor_id, r.actor_email, r.action, r.outcome, r.doc_id, r.target_user_id, r.ip, r.detail, r.prev_hash, r.hash]);
    }
    await t.db.query('UPDATE audit_head SET seq=$1, hash=$2', [head.seq, head.hash]);
  });

  // 1. edit a row (e.g. hide who downloaded)
  const victim = snapshot.find((r) => r.action === 'doc.download');
  await withoutTriggers(() => t.db.query("UPDATE audit_log SET actor_email = 'innocent@example.test' WHERE seq = $1", [victim.seq]));
  let r = await audit.verify(t.db);
  assert.equal(r.ok, false); assert.equal(r.brokenAt, victim.seq);
  await restore(); assert.equal((await audit.verify(t.db)).ok, true);

  // 2. delete a row from the middle
  await withoutTriggers(() => t.db.query('DELETE FROM audit_log WHERE seq = $1', [victim.seq]));
  r = await audit.verify(t.db);
  assert.equal(r.ok, false); assert.match(r.reason, /gap/);
  await restore(); assert.equal((await audit.verify(t.db)).ok, true);

  // 3. edit a row AND recompute its hash with SHA-256 (what someone without the HMAC key can do)
  const crypto = require('crypto');
  await withoutTriggers(async () => {
    await t.db.query("UPDATE audit_log SET actor_email = 'innocent@example.test', hash = $2 WHERE seq = $1", [victim.seq, crypto.createHash('sha256').update('forged').digest('hex')]);
  });
  r = await audit.verify(t.db);
  assert.equal(r.ok, false);
  await restore(); assert.equal((await audit.verify(t.db)).ok, true);

  // 4. remove the last rows AND leave audit_head alone (head mismatch)
  const last = snapshot[snapshot.length - 1];
  await withoutTriggers(() => t.db.query('DELETE FROM audit_log WHERE seq = $1', [last.seq]));
  r = await audit.verify(t.db);
  assert.equal(r.ok, false); assert.match(r.reason, /audit_head/);
  await restore(); assert.equal((await audit.verify(t.db)).ok, true);

  // 5. append a forged row at the end
  await withoutTriggers(() => t.db.query(
    "INSERT INTO audit_log(seq,ts,actor_email,action,outcome,detail,prev_hash,hash) VALUES ($1,$2,'x','doc.delete','allowed','{}',$3,$4)",
    [last.seq + 1, new Date().toISOString(), last.hash, 'f'.repeat(64)]));
  r = await audit.verify(t.db);
  assert.equal(r.ok, false);
  await restore(); assert.equal((await audit.verify(t.db)).ok, true);
});

test('an action cannot commit without its audit row (audit failure rolls the action back)', async () => {
  const id = (await alice.client.upload('c.txt', 'atomic', { name: 'Atomic' })).json.id;
  await t.db.exec('ALTER TABLE audit_log DISABLE TRIGGER USER');
  await t.db.exec("ALTER TABLE audit_log ADD CONSTRAINT audit_break CHECK (action <> 'doc.delete') NOT VALID");
  const errorLog = console.error;
  const loggedErrors = [];
  console.error = (...args) => loggedErrors.push(args);
  let r;
  try {
    r = await alice.client.del(`/api/documents/${id}`);
  } finally {
    console.error = errorLog;
    await t.db.exec('ALTER TABLE audit_log DROP CONSTRAINT audit_break');
    await t.db.exec('ALTER TABLE audit_log ENABLE TRIGGER USER');
  }
  assert.equal(r.status, 500);
  assert.equal(loggedErrors.length, 1);
  assert.equal(loggedErrors[0][0], '[error]');
  assert.equal(loggedErrors[0][1], 'DELETE');
  assert.equal(loggedErrors[0][3].code, '23514');
  const d = await alice.client.get(`/api/documents/${id}`);
  assert.equal(d.json.document.deletedAt, null, 'delete was rolled back along with its failed audit write');
  assert.equal((await audit.verify(t.db)).ok, true);
});

test('concurrent actions keep a gap-free, valid chain', async () => {
  await Promise.all(Array.from({ length: 12 }, (_, i) => alice.client.upload(`p${i}.txt`, 'parallel ' + i, { name: 'P' + i })));
  const r = await audit.verify(t.db);
  assert.equal(r.ok, true, JSON.stringify(r));
});

test('admin overview and audit viewer expose activity, refusals and the sensitive-change list', async () => {
  for (let i = 0; i < 6; i++) await bob.client.get(`/api/documents/${docId}/download`); // bob has no access now
  const s = await admin.client.get('/api/admin/summary');
  assert.equal(s.status, 200);
  assert.ok(s.json.counts.refusals24h >= 6);
  assert.ok(s.json.alerts.some((a) => a.kind === 'repeated_denials' && a.who === bob.email));
  const denied = await admin.client.get('/api/admin/audit?outcome=denied&action=access');
  assert.ok(denied.json.entries.length >= 6);
  assert.ok(denied.json.entries.every((e) => e.outcome === 'denied' && e.action.startsWith('access')));
  const forDoc = await admin.client.get(`/api/admin/audit?doc=${docId}`);
  assert.ok(forDoc.json.entries.some((e) => e.action === 'grant.revoke'));
  assert.equal((await admin.client.get('/api/admin/audit?from=notadate')).status, 400);
});

test('owners see the activity (including refusals) on their own documents, and only theirs', async () => {
  const mine = await alice.client.get(`/api/documents/${docId}/activity`);
  assert.equal(mine.status, 200);
  assert.ok(mine.json.activity.some((a) => a.action === 'doc.download' && a.actor === bob.email));
  assert.ok(mine.json.activity.some((a) => a.outcome === 'denied'));
  assert.equal((await bob.client.get(`/api/documents/${docId}/activity`)).status, 404);
});

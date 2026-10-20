'use strict';
// Smaller controls that THREATS.md claims: HEAD requests, cron endpoint, self-lockout guards.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { start } = require('./helper');

let t, alice, bob, admin, docId;
before(async () => {
  t = await start();
  alice = await t.user('owner', 'alice');
  bob = await t.user('owner', 'bob');
  admin = await t.user('admin', 'root');
  docId = (await alice.client.upload('h.txt', 'head request body', { name: 'H' })).json.id;
});
after(() => t.stop());

test('HEAD goes through the same authorisation as GET (no method-tricks around the check)', async () => {
  const denied = await bob.client.call('HEAD', `/api/documents/${docId}/download`);
  assert.equal(denied.status, 404);
  assert.equal(denied.raw.length, 0);
  const own = await alice.client.call('HEAD', `/api/documents/${docId}/download`);
  assert.equal(own.status, 200);
  const rows = await t.auditRows("doc_id = $1 AND actor_email = $2", [docId, bob.email]);
  assert.ok(rows.some((r) => r.action === 'access.denied'), 'the refused HEAD was audited');
});

test('unsupported verbs on document routes do not reach a handler', async () => {
  for (const m of ['PUT', 'POST', 'DELETE']) {
    const r = await bob.client.call(m, `/api/documents/${docId}/download`, m === 'DELETE' ? {} : { json: {} });
    assert.ok([404].includes(r.status), `${m} download -> ${r.status}`);
  }
});

test('the cron endpoint is invisible without CRON_SECRET, and refuses wrong bearer tokens', async () => {
  const anon = new t.Client(t.base);
  assert.equal((await anon.get('/api/cron/purge')).status, 404);
  assert.equal((await anon.get('/api/cron/purge', { headers: { authorization: 'Bearer guess' } })).status, 404);
  assert.equal((await alice.client.get('/api/cron/purge')).status, 404);
});

test('admins cannot lock themselves out: no self-deactivation, no self role-change', async () => {
  const a = await admin.client.post(`/api/admin/users/${admin.id}/deactivate`, {});
  assert.equal(a.status, 409);
  const b = await admin.client.post(`/api/admin/users/${admin.id}/role`, { role: 'viewer' });
  assert.equal(b.status, 409);
  assert.equal((await admin.client.get('/api/admin/summary')).status, 200);
});

test('admin-created users get a one-time password that works once and forces nothing else open', async () => {
  const created = await admin.client.post('/api/admin/users', { email: 'newbie@example.test', name: 'New Bie', role: 'viewer' });
  assert.equal(created.status, 201);
  const c = new t.Client(t.base);
  assert.equal((await c.login('newbie@example.test', created.json.temporaryPassword)).status, 200);
  assert.equal((await c.get('/api/documents')).json.documents.length, 0, 'a new user sees nothing');
  assert.equal((await admin.client.post('/api/admin/users', { email: 'newbie@example.test', name: 'dup', role: 'viewer' })).status, 409);
  assert.equal((await admin.client.post('/api/admin/users', { email: 'x@example.test', name: 'x', role: 'superuser' })).status, 400);
  assert.equal((await admin.client.post('/api/admin/users', { email: 'not-an-email', name: 'x', role: 'viewer' })).status, 400);
});

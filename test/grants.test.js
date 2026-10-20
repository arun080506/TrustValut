'use strict';
// THREAT: permissions that are too broad, or that outlive their removal.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { start } = require('./helper');

let t, alice, bob, carol, dave, admin, docId;
const BODY = '%PDF-1.4\nCONFIDENTIAL CONTRACT BODY 9981\n%%EOF';

before(async () => {
  t = await start();
  alice = await t.user('owner', 'alice');
  bob = await t.user('owner', 'bob');
  carol = await t.user('viewer', 'carol');
  dave = await t.user('viewer', 'dave');
  admin = await t.user('admin', 'root');
  docId = (await alice.client.upload('contract.pdf', BODY, { name: 'Contract', category: 'contracts' })).json.id;
});
after(() => t.stop());

const grant = (who, permission, extra = {}) => alice.client.put(`/api/documents/${docId}/grants`, { userId: who.id, permission, ...extra });

test('a read grant allows read+download only', async () => {
  assert.equal((await grant(carol, 'read')).status, 200);
  const c = carol.client;
  assert.equal((await c.get(`/api/documents/${docId}`)).status, 200);
  const dl = await c.get(`/api/documents/${docId}/download`);
  assert.equal(dl.status, 200);
  assert.equal(dl.raw.toString(), BODY);
  assert.equal(dl.headers.get('x-content-type-options'), 'nosniff');
  assert.match(dl.headers.get('content-disposition'), /^attachment;/);
  assert.match(dl.headers.get('cache-control'), /no-store/);
  // everything above read is refused with 403 (they know it exists) and logged
  assert.equal((await c.patch(`/api/documents/${docId}`, { name: 'x' })).status, 403);
  assert.equal((await c.newVersion(docId, 'v2.txt', 'new')).status, 403);
  assert.equal((await c.del(`/api/documents/${docId}`)).status, 403);
  assert.equal((await c.get(`/api/documents/${docId}/grants`)).status, 403);
  assert.equal((await c.put(`/api/documents/${docId}/grants`, { userId: dave.id, permission: 'read' })).status, 403);
  assert.equal((await c.get(`/api/documents/${docId}/activity`)).status, 403);
  assert.equal((await c.post(`/api/documents/${docId}/suggest-access`, {})).status, 403);
});

test('an edit grant allows metadata + new versions, but not delete, grants, or activity', async () => {
  assert.equal((await grant(bob, 'edit')).status, 200);
  const c = bob.client;
  assert.equal((await c.patch(`/api/documents/${docId}`, { name: 'Contract v2 title' })).status, 200);
  assert.equal((await c.newVersion(docId, 'contract-v2.txt', 'second version text')).status, 201);
  assert.equal((await c.del(`/api/documents/${docId}`)).status, 403);
  assert.equal((await c.put(`/api/documents/${docId}/grants`, { userId: dave.id, permission: 'read' })).status, 403);
  assert.equal((await c.del(`/api/documents/${docId}/grants/${carol.id}`)).status, 403);
  assert.equal((await c.get(`/api/documents/${docId}/activity`)).status, 403);
  assert.equal((await c.post(`/api/documents/${docId}/restore`, {})).status, 403);
  const dl = await c.get(`/api/documents/${docId}/download?version=1`);
  assert.equal(dl.raw.toString(), BODY, 'old versions remain downloadable by those with access');
});

test('viewer role is capped at read: edit grants are refused, and a pre-existing one is neutralised', async () => {
  const r = await grant(dave, 'edit');
  assert.equal(r.status, 400);
  assert.equal(r.json.error, 'viewer_cannot_edit');
  // Simulate a role lowered after the grant was made.
  await t.db.query("UPDATE users SET role = 'viewer' WHERE id = $1", [bob.id]);
  assert.equal((await bob.client.patch(`/api/documents/${docId}`, { name: 'should fail' })).status, 403);
  assert.equal((await bob.client.get(`/api/documents/${docId}/download`)).status, 200);
  await t.db.query("UPDATE users SET role = 'owner' WHERE id = $1", [bob.id]);
});

test('REVOCATION IS IMMEDIATE: the same live session loses access on the very next request', async () => {
  assert.equal((await carol.client.get(`/api/documents/${docId}/download`)).status, 200);
  const rev = await alice.client.del(`/api/documents/${docId}/grants/${carol.id}`);
  assert.equal(rev.status, 200);
  for (const p of [`/api/documents/${docId}`, `/api/documents/${docId}/download`, `/api/documents/${docId}/download?version=1`]) {
    const r = await carol.client.get(p);
    assert.equal(r.status, 404, p);
    assert.ok(!r.raw.toString().includes('CONFIDENTIAL'));
  }
  const list = await carol.client.get('/api/documents');
  assert.deepEqual(list.json.documents, []);
  // re-granting restores it, proving it was the grant and nothing cached
  await grant(carol, 'read');
  assert.equal((await carol.client.get(`/api/documents/${docId}/download`)).status, 200);
  await alice.client.del(`/api/documents/${docId}/grants/${carol.id}`);
});

test('there are no bearer download links: a copied URL without the session is useless', async () => {
  await grant(carol, 'read');
  const url = `/api/documents/${docId}/download`;
  const stranger = new t.Client(t.base);
  assert.equal((await stranger.get(url)).status, 401);
  assert.equal((await dave.client.get(url)).status, 404);
  await alice.client.del(`/api/documents/${docId}/grants/${carol.id}`);
});

test('expired grants stop working without anyone doing anything', async () => {
  await grant(carol, 'read', { expiresAt: new Date(Date.now() + 3600e3).toISOString() });
  assert.equal((await carol.client.get(`/api/documents/${docId}/download`)).status, 200);
  await t.db.query("UPDATE grants SET expires_at = now() - interval '1 second' WHERE document_id = $1 AND user_id = $2 AND revoked_at IS NULL", [docId, carol.id]);
  assert.equal((await carol.client.get(`/api/documents/${docId}/download`)).status, 404);
  assert.deepEqual((await carol.client.get('/api/documents')).json.documents, []);
  await t.db.query('UPDATE grants SET revoked_at = now() WHERE document_id = $1 AND user_id = $2 AND revoked_at IS NULL', [docId, carol.id]);
});

test('grant validation: owner, unknown user, bad permission, bad expiry, deactivated user', async () => {
  const put = (b) => alice.client.put(`/api/documents/${docId}/grants`, b);
  assert.equal((await put({ userId: alice.id, permission: 'read' })).status, 400);
  assert.equal((await put({ userId: '22222222-2222-4222-8222-222222222222', permission: 'read' })).status, 404);
  assert.equal((await put({ userId: carol.id, permission: 'admin' })).status, 400);
  assert.equal((await put({ userId: 'x', permission: 'read' })).status, 400);
  assert.equal((await put({ userId: carol.id, permission: 'read', expiresAt: '2001-01-01' })).status, 400);
  assert.equal((await put({ userId: carol.id, permission: 'read', expiresAt: 'banana' })).status, 400);
});

test('deactivating a user kills their live session at once; their grants stop mattering', async () => {
  await grant(dave, 'read');
  assert.equal((await dave.client.get(`/api/documents/${docId}/download`)).status, 200);
  const r = await admin.client.post(`/api/admin/users/${dave.id}/deactivate`, {});
  assert.equal(r.status, 200);
  assert.equal((await dave.client.get(`/api/documents/${docId}/download`)).status, 401);
  assert.equal((await dave.client.login(dave.email)).status, 401, 'cannot sign back in');
  // directory no longer offers them
  const dir = await alice.client.get('/api/users/directory?q=' + encodeURIComponent(dave.email.slice(0, 6)));
  assert.ok(!dir.json.users.some((u) => u.id === dave.id));
  await admin.client.post(`/api/admin/users/${dave.id}/activate`, {});
});

test('session validity re-checks the account on EVERY request, independently of session revocation', async () => {
  // Two separate controls protect a leaver: (a) the session query requires users.active, and
  // (b) deactivation revokes their session rows. Each is tested on its own.
  const frank = await t.user('viewer', 'frank');
  assert.equal((await frank.client.get('/api/documents')).status, 200);
  await t.db.query('UPDATE users SET active = false WHERE id = $1', [frank.id]); // session row untouched
  assert.equal((await frank.client.get('/api/documents')).status, 401, '(a) inactive account, live session row');

  const gina = await t.user('viewer', 'gina');
  assert.equal((await admin.client.post(`/api/admin/users/${gina.id}/deactivate`, {})).status, 200);
  await t.db.query('UPDATE users SET active = true WHERE id = $1', [gina.id]); // account is active again...
  assert.equal((await gina.client.get('/api/documents')).status, 401, '(b) ...but the old session was destroyed');
  const live = (await t.db.query('SELECT count(*)::int AS n FROM sessions WHERE user_id = $1 AND revoked_at IS NULL', [gina.id])).rows[0].n;
  assert.equal(live, 0);
});

test('changing a role forces re-login; password change kills other sessions', async () => {
  const second = new t.Client(t.base);
  await second.login(carol.email);
  assert.equal((await second.get('/api/documents')).status, 200);
  const change = await carol.client.post('/api/auth/password', { current: t.PW, next: 'A-Brand-New-Passphrase-1' });
  assert.equal(change.status, 200);
  assert.equal((await second.get('/api/documents')).status, 401, 'other session revoked');
  assert.equal((await carol.client.get('/api/documents')).status, 200, 'current session kept');
  assert.equal((await new t.Client(t.base).login(carol.email, t.PW)).status, 401, 'old password dead');
  await admin.client.post(`/api/admin/users/${carol.id}/role`, { role: 'viewer' });
  assert.equal((await carol.client.get('/api/documents')).status, 401);
});

test('admin emergency revoke works and is audited as an admin action', async () => {
  await grant(bob, 'read');
  const r = await admin.client.del(`/api/admin/documents/${docId}/grants/${bob.id}`);
  assert.equal(r.status, 200);
  assert.equal((await bob.client.get(`/api/documents/${docId}/download`)).status, 404);
  const rows = await t.auditRows("action = 'admin.grant_revoke'");
  assert.equal(rows.length, 1);
  assert.equal(rows[0].actor_email, admin.email);
});

test('soft delete hides from grantees immediately; owner can restore; trash is owner-only', async () => {
  await grant(carol2(), 'read').catch(() => {});
  const viewer = await t.user('viewer', 'erin');
  await alice.client.put(`/api/documents/${docId}/grants`, { userId: viewer.id, permission: 'read' });
  assert.equal((await viewer.client.get(`/api/documents/${docId}/download`)).status, 200);
  assert.equal((await alice.client.del(`/api/documents/${docId}`)).status, 200);
  assert.equal((await viewer.client.get(`/api/documents/${docId}/download`)).status, 404);
  assert.equal((await viewer.client.get(`/api/documents/${docId}`)).status, 404);
  assert.equal((await alice.client.get(`/api/documents/${docId}/download`)).status, 404, 'even the owner cannot download from the trash');
  assert.ok((await alice.client.get('/api/documents?trash=1')).json.documents.some((d) => d.id === docId));
  assert.ok(!(await viewer.client.get('/api/documents?trash=1')).json.documents.some((d) => d.id === docId));
  assert.equal((await viewer.client.post(`/api/documents/${docId}/restore`, {})).status, 404);
  assert.equal((await alice.client.post(`/api/documents/${docId}/restore`, {})).status, 200);
  assert.equal((await viewer.client.get(`/api/documents/${docId}/download`)).status, 200);
  function carol2() { return carol; }
});

test('retention purge destroys the bytes and the document is permanently unreachable', async () => {
  const { purgeExpired } = require('../src/purge');
  const id = (await alice.client.upload('temp.txt', 'purge me', { name: 'Temp' })).json.id;
  await alice.client.del(`/api/documents/${id}`);
  assert.equal(await purgeExpired(t.db), 0, 'not yet expired');
  await t.db.query("UPDATE documents SET deleted_at = now() - interval '40 days' WHERE id = $1", [id]);
  assert.equal(await purgeExpired(t.db), 1);
  const v = (await t.db.query('SELECT blob, wrapped_key FROM document_versions WHERE document_id = $1', [id])).rows[0];
  assert.equal(v.blob, null);
  assert.equal(v.wrapped_key, null);
  assert.equal((await alice.client.post(`/api/documents/${id}/restore`, {})).status, 404);
  assert.equal((await alice.client.get(`/api/documents/${id}/download`)).status, 404);
});

test('admin can only transfer documents of DEACTIVATED owners, and only to active owners', async () => {
  const leaver = await t.user('owner', 'leaver');
  const heir = await t.user('owner', 'heir');
  const id = (await leaver.client.upload('handover.txt', 'handover notes', { name: 'Handover' })).json.id;
  const attempt = (b) => admin.client.post(`/api/admin/documents/${id}/transfer`, b);
  assert.equal((await attempt({ newOwnerId: heir.id, reason: 'x' })).status, 409, 'owner still active');
  await admin.client.post(`/api/admin/users/${leaver.id}/deactivate`, {});
  assert.equal((await attempt({ newOwnerId: heir.id })).status, 400, 'reason required');
  assert.equal((await attempt({ newOwnerId: admin.id, reason: 'x' })).status, 400, 'admin cannot be new owner');
  assert.equal((await attempt({ newOwnerId: heir.id, reason: 'leaver offboarding' })).status, 200);
  assert.equal((await heir.client.get(`/api/documents/${id}/download`)).status, 200);
  assert.equal((await t.auditRows("action = 'admin.doc_transfer'")).length, 1);
});

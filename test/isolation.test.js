'use strict';
// THREAT: a user reaches a document they were never granted, by any route.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { start, Client } = require('./helper');

let t, alice, bob, carol, admin, docId, secret;
const PDFISH = '%PDF-1.4\nTOP SECRET SALARY DATA 4711\n%%EOF';

before(async () => {
  t = await start();
  alice = await t.user('owner', 'alice');
  bob = await t.user('owner', 'bob');
  carol = await t.user('viewer', 'carol');
  admin = await t.user('admin', 'root');
  const up = await alice.client.upload('salary.pdf', PDFISH, { name: 'Salary letter', category: 'hr' });
  assert.equal(up.status, 201, JSON.stringify(up.json));
  docId = up.json.id;
  secret = 'TOP SECRET SALARY DATA 4711';
});
after(() => t.stop());

// Every method + path an attacker could try against a document they have no grant on.
const ROUTES = (id) => [
  ['GET', `/api/documents/${id}`],
  ['GET', `/api/documents/${id}/download`],
  ['GET', `/api/documents/${id}/download?version=1`],
  ['GET', `/api/documents/${id}/activity`],
  ['GET', `/api/documents/${id}/grants`],
  ['PATCH', `/api/documents/${id}`, { name: 'pwned' }],
  ['DELETE', `/api/documents/${id}`],
  ['POST', `/api/documents/${id}/restore`, {}],
  ['PUT', `/api/documents/${id}/grants`, { userId: '00000000-0000-4000-8000-000000000000', permission: 'read' }],
  ['DELETE', `/api/documents/${id}/grants/00000000-0000-4000-8000-000000000000`],
  ['POST', `/api/documents/${id}/suggest-access`, {}],
];

for (const who of ['bob (other owner)', 'carol (viewer)']) {
  test(`${who} cannot touch a document they were not granted, on any route`, async () => {
    const c = (who.startsWith('bob') ? bob : carol).client;
    for (const [method, path, body] of ROUTES(docId)) {
      const r = await c.call(method, path, body !== undefined ? { json: body } : {});
      assert.equal(r.status, 404, `${method} ${path} should be 404 but was ${r.status}`);
      assert.deepEqual(r.json, { error: 'not_found', message: 'Document not found' }, `${method} ${path} leaked something`);
      assert.ok(!r.raw.toString().includes(secret));
    }
    const v = await c.newVersion(docId, 'x.txt', 'overwrite attempt');
    assert.equal(v.status, 404);
  });
}

test('"no access" is indistinguishable from "does not exist"', async () => {
  const real = await bob.client.get(`/api/documents/${docId}`);
  const fake = await bob.client.get('/api/documents/11111111-1111-4111-8111-111111111111');
  const junk = await bob.client.get('/api/documents/not-a-uuid');
  for (const r of [real, fake, junk]) assert.equal(r.status, 404);
  assert.deepEqual(real.json, fake.json);
  assert.deepEqual(real.json, junk.json);
});

test('list and search never reveal documents the caller cannot reach', async () => {
  for (const c of [bob.client, carol.client, admin.client]) {
    for (const q of ['', '?q=salary', '?q=Salary%20letter&scope=all', '?owner=alice', '?category=hr', '?from=2000-01-01&to=2100-01-01', '?q=%25', '?q=_']) {
      const r = await c.get('/api/documents' + q);
      assert.equal(r.status, 200);
      assert.deepEqual(r.json.documents.filter((d) => d.id === docId), [], `leak via ${q}`);
    }
    const cats = await c.get('/api/documents/categories');
    assert.ok(!cats.json.categories.includes('hr'));
  }
  const mine = await alice.client.get('/api/documents?q=salary');
  assert.equal(mine.json.documents.length, 1);
});

test('the "shared with me" and "mine" scopes only ever contain what the caller is entitled to', async () => {
  for (const c of [bob.client, carol.client, admin.client]) {
    for (const scope of ['shared', 'mine', 'all']) {
      const r = await c.get('/api/documents?scope=' + scope);
      assert.equal(r.status, 200);
      assert.deepEqual(r.json.documents.map((d) => d.id).filter((id) => id === docId), [], `scope=${scope}`);
    }
  }
});

test('SQL-injection style input in filters is inert', async () => {
  const payloads = ["' OR '1'='1", "'; DROP TABLE documents;--", '%', '\\'];
  for (const p of payloads) {
    const r = await bob.client.get('/api/documents?q=' + encodeURIComponent(p) + '&owner=' + encodeURIComponent(p) + '&category=' + encodeURIComponent(p));
    assert.equal(r.status, 200);
    assert.equal(r.json.documents.length, 0);
  }
  assert.equal((await alice.client.get(`/api/documents/${docId}`)).status, 200); // table still there
});

test('unauthenticated callers get 401 everywhere', async () => {
  const anon = new t.Client(t.base);
  for (const [method, path, body] of ROUTES(docId)) {
    const r = await anon.call(method, path, body !== undefined ? { json: body } : {});
    assert.equal(r.status, 401, `${method} ${path}`);
  }
  assert.equal((await anon.get('/api/documents')).status, 401);
  assert.equal((await anon.get('/api/admin/audit')).status, 401);
  assert.equal((await anon.get('/api/users/directory?q=abc')).status, 401);
});

test('a forged or garbage session cookie does not authenticate', async () => {
  const c = new t.Client(t.base);
  for (const cookie of ['tv_session=' + 'A'.repeat(43), 'tv_session=' + alice.client.cookie.split('=')[1] + 'x', 'tv_session=../../etc/passwd']) {
    c.cookie = cookie;
    assert.equal((await c.get(`/api/documents/${docId}/download`)).status, 401);
  }
});

test('administrators cannot read document content or metadata through the document routes', async () => {
  for (const [method, path, body] of ROUTES(docId)) {
    const r = await admin.client.call(method, path, body !== undefined ? { json: body } : {});
    assert.ok([404, 403].includes(r.status), `${method} ${path} gave admin ${r.status}`);
    assert.ok(!r.raw.toString().includes(secret));
  }
  // ...but they do see metadata in the governance view, never bytes.
  const list = await admin.client.get('/api/admin/documents');
  assert.equal(list.status, 200);
  assert.ok(list.json.documents.some((d) => d.id === docId));
  assert.ok(!list.raw.toString().includes(secret));
});

test('viewers cannot upload or call owner/admin endpoints', async () => {
  assert.equal((await carol.client.upload('a.txt', 'hello')).status, 403);
  assert.equal((await carol.client.get('/api/users/directory?q=abc')).status, 403);
  for (const p of ['/api/admin/summary', '/api/admin/audit', '/api/admin/audit/verify', '/api/admin/users', '/api/admin/documents']) {
    assert.equal((await carol.client.get(p)).status, 403, p);
    assert.equal((await bob.client.get(p)).status, 403, p);
  }
  assert.equal((await bob.client.post('/api/admin/users', { email: 'x@y.zz', name: 'x', role: 'admin' })).status, 403);
});

test('every refusal above is in the audit trail, attributed and flagged denied', async () => {
  const rows = await t.auditRows("action = 'access.denied' AND doc_id = $1", [docId]);
  const byActor = (email) => rows.filter((r) => r.actor_email === email && r.outcome === 'denied');
  assert.ok(byActor(bob.email).length >= ROUTES(docId).length, 'bob refusals recorded');
  assert.ok(byActor(carol.email).length >= ROUTES(docId).length, 'carol refusals recorded');
  assert.ok(byActor(admin.email).length >= 1, 'admin refusals recorded');
  assert.ok(rows.some((r) => r.detail.attempted === 'doc.download'));
  // and the owner's own content was never served to anyone else
  const served = await t.auditRows("action = 'doc.download' AND doc_id = $1", [docId]);
  assert.equal(served.length, 0);
});

test('mass assignment: PATCH cannot change the owner or other protected fields', async () => {
  const r = await alice.client.patch(`/api/documents/${docId}`, { name: 'Renamed', owner_id: bob.id, deleted_at: null, current_version: 99 });
  assert.equal(r.status, 200);
  const d = await alice.client.get(`/api/documents/${docId}`);
  assert.equal(d.json.document.name, 'Renamed');
  assert.equal(d.json.owner.id, alice.id);
  assert.equal(d.json.document.version, 1);
  assert.equal((await bob.client.get(`/api/documents/${docId}`)).status, 404);
});

test('cross-origin writes are refused and CSRF token is required', async () => {
  const noToken = await alice.client.call('PATCH', `/api/documents/${docId}`, { json: { name: 'csrf' }, csrf: false });
  assert.equal(noToken.status, 403);
  assert.equal(noToken.json.error, 'csrf');
  const evil = await alice.client.call('PATCH', `/api/documents/${docId}`, { json: { name: 'csrf' }, headers: { origin: 'https://evil.example' } });
  assert.equal(evil.status, 403);
  assert.equal(evil.json.error, 'cross_origin');
  const wrong = await alice.client.call('PATCH', `/api/documents/${docId}`, { json: { name: 'csrf' }, headers: { 'x-csrf-token': 'nope' }, csrf: false });
  assert.equal(wrong.status, 403);
  assert.equal((await alice.client.get(`/api/documents/${docId}`)).json.document.name, 'Renamed');
});

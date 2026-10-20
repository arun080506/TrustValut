'use strict';
// Needs a REAL PostgreSQL server (TEST_DATABASE_URL, see `npm run test:pg`). PGlite is a single
// connection, so it cannot exhibit lock races: without a real server this test would prove nothing,
// and is therefore skipped rather than pretending to pass.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { start, REAL_PG } = require('./helper');
const audit = require('../src/audit');

const opts = { skip: REAL_PG ? false : 'needs TEST_DATABASE_URL (real PostgreSQL)' };
let t, alice, bob, carol, docId;

before(async () => {
  if (!REAL_PG) return;
  t = await start();
  alice = await t.user('owner', 'alice');
  bob = await t.user('owner', 'bob');
  carol = await t.user('viewer', 'carol');
  docId = (await alice.client.upload('c.txt', 'concurrent', { name: 'C' })).json.id;
});
after(async () => { if (t) await t.stop(); });

test('parallel writes on separate connections still produce a gap-free, valid audit chain', opts, async () => {
  const results = await Promise.all(Array.from({ length: 40 }, (_, i) =>
    (i % 2 ? alice : bob).client.upload(`p${i}.txt`, 'parallel ' + i, { name: 'P' + i })));
  assert.ok(results.every((r) => r.status === 201), 'every request succeeded: ' + results.map((r) => r.status).join(','));
  const r = await audit.verify(t.db);
  assert.equal(r.ok, true, JSON.stringify(r));
  const max = (await t.db.query('SELECT max(seq)::int AS m, count(*)::int AS n FROM audit_log')).rows[0];
  assert.equal(max.m, max.n);
});

test('a download racing a revocation is serialised: after the revoke commits, no download succeeds', opts, async () => {
  // Repeated: the original bug (decision evaluated on a stale snapshot after waiting for the lock)
  // showed up in roughly 1 run in 7, so a single round is not evidence.
  for (let round = 0; round < 15; round++) {
    await alice.client.put(`/api/documents/${docId}/grants`, { userId: carol.id, permission: 'read' });
    const revoke = alice.client.del(`/api/documents/${docId}/grants/${carol.id}`);
    const downloads = Array.from({ length: 20 }, () => carol.client.get(`/api/documents/${docId}/download`));
    const [rev, ...dls] = await Promise.all([revoke, ...downloads]);
    assert.equal(rev.status, 200, `round ${round}`);
    assert.ok(dls.every((d) => d.status === 200 || d.status === 404), `round ${round}: only allowed or refused, never an error: ` + dls.map((d) => d.status).join(','));
    const revokeSeq = (await t.db.query("SELECT max(seq)::int AS s FROM audit_log WHERE doc_id = $1 AND action = 'grant.revoke'", [docId])).rows[0].s;
    const late = await t.auditRows("doc_id = $1 AND action = 'doc.download' AND outcome = 'allowed' AND seq > $2", [docId, revokeSeq]);
    assert.equal(late.length, 0, `round ${round}: ${late.length} download(s) served after the revocation was recorded`);
    assert.equal((await carol.client.get(`/api/documents/${docId}/download`)).status, 404);
  }
});

test('concurrent version uploads get distinct, consecutive version numbers', opts, async () => {
  const rs = await Promise.all(Array.from({ length: 8 }, (_, i) => alice.client.newVersion(docId, `v${i}.txt`, 'version ' + i)));
  assert.ok(rs.every((r) => r.status === 201), rs.map((r) => r.status).join(','));
  const versions = (await t.db.query('SELECT version FROM document_versions WHERE document_id = $1 ORDER BY version', [docId])).rows.map((r) => r.version);
  assert.deepEqual(versions, Array.from({ length: 9 }, (_, i) => i + 1));
});

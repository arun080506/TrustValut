'use strict';
// THREAT: hostile uploads, storage exposure, and the AI advisor widening access.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { start } = require('./helper');

let t, alice, bob, carol, dave;

before(async () => {
  t = await start();
  alice = await t.user('owner', 'alice');
  bob = await t.user('owner', 'bob');
  carol = await t.user('viewer', 'carol');
  dave = await t.user('viewer', 'dave');
});
after(() => t.stop());

test('disallowed types are refused whatever the client claims', async () => {
  const bad = [
    ['evil.exe', 'MZ\x90\x00'], ['page.html', '<script>alert(1)</script>'], ['pic.svg', '<svg onload=alert(1)/>'],
    ['run.sh', '#!/bin/sh\nrm -rf /'], ['macro.docm', 'PK\x03\x04'], ['noext', 'hello'], ['.htaccess', 'x'], ['a.php', '<?php'],
  ];
  for (const [name, body] of bad) {
    const r = await alice.client.upload(name, body);
    assert.equal(r.status, 415, `${name} -> ${r.status} ${JSON.stringify(r.json)}`);
  }
});

test('content must match the extension (magic bytes), so renaming does not smuggle files', async () => {
  assert.equal((await alice.client.upload('fake.pdf', 'this is just text')).json.error, 'content_mismatch');
  assert.equal((await alice.client.upload('fake.png', '%PDF-1.4 hi')).json.error, 'content_mismatch');
  assert.equal((await alice.client.upload('fake.docx', 'PK\x03\x04 not really word')).json.error, 'content_mismatch');
  assert.equal((await alice.client.upload('fake.txt', Buffer.from([0x68, 0x00, 0x69]))).json.error, 'content_mismatch');
  const macro = 'PK\x03\x04[Content_Types].xml word/document.xml vbaProject.bin';
  assert.equal((await alice.client.upload('macro.docx', macro)).json.error, 'content_mismatch');
  const ok = 'PK\x03\x04[Content_Types].xml word/document.xml';
  assert.equal((await alice.client.upload('real.docx', ok)).status, 201);
});

test('empty files, missing files and oversize files are refused', async () => {
  assert.equal((await alice.client.upload('empty.txt', '')).status, 400);
  const none = await alice.client.call('POST', '/api/documents', { form: new FormData() });
  assert.equal(none.status, 400);
  const big = await alice.client.upload('big.txt', Buffer.alloc(4 * 1024 * 1024 + 10, 97));
  assert.equal(big.status, 413);
});

test('filenames are sanitised: no paths, no control characters, no traversal, no header injection', async () => {
  for (const hostile of ['../../etc/passwd.txt', '..\\..\\windows\\system32\\x.txt', 'x\r\nSet-Cookie: a=b.txt', 'q"uote.txt', '/abs/olute.txt', '....hidden.txt']) {
    const r = await alice.client.upload(hostile, 'hello', { name: '' });
    assert.equal(r.status, 201, `${JSON.stringify(hostile)} -> ${r.status}`);
    const d = (await alice.client.get(`/api/documents/${r.json.id}`)).json;
    const stored = d.versions[0].filename;
    assert.ok(!/[\/\\\u0000-\u001f"]/.test(stored), `stored name ${JSON.stringify(stored)} still hostile`);
    assert.ok(!stored.startsWith('.'));
    const dl = await alice.client.get(`/api/documents/${r.json.id}/download`);
    assert.equal(dl.status, 200);
    assert.ok(!/[\r\n]/.test(dl.headers.get('content-disposition')));
    assert.equal(dl.headers.get('set-cookie'), null);
  }
  // A NUL byte makes the multipart request itself malformed: rejected outright, nothing stored.
  const before = (await t.db.query('SELECT count(*)::int AS n FROM documents')).rows[0].n;
  assert.equal((await alice.client.upload('a\u0000b.txt', 'hello')).status, 400);
  assert.equal((await t.db.query('SELECT count(*)::int AS n FROM documents')).rows[0].n, before);
});

test('stored bytes are ciphertext: the database contains no plaintext, and rows cannot be swapped', async () => {
  const marker = 'PLAINTEXT-MARKER-48151623';
  const a = (await alice.client.upload('a.txt', marker + ' alpha', { name: 'A' })).json.id;
  const b = (await alice.client.upload('b.txt', 'other file beta', { name: 'B' })).json.id;
  const rows = (await t.db.query('SELECT document_id, blob, wrapped_key, sha256, size FROM document_versions WHERE document_id = ANY($1::uuid[])', [[a, b]])).rows;
  for (const r of rows) assert.ok(!Buffer.from(r.blob).toString('latin1').includes('PLAINTEXT-MARKER'));
  // An attacker with database write access copies B's ciphertext, key AND checksum over A.
  // The stored SHA-256 would then match, so ONLY the GCM binding to "document id : version" stops it.
  const rb = rows.find((r) => r.document_id === b);
  await t.db.query('UPDATE document_versions SET blob = $2, wrapped_key = $3, sha256 = $4, size = $5 WHERE document_id = $1', [a, rb.blob, rb.wrapped_key, rb.sha256, rb.size]);
  const dl = await alice.client.get(`/api/documents/${a}/download`);
  assert.equal(dl.status, 500);
  assert.equal(dl.json.error, 'integrity_failure');
  assert.ok(!dl.raw.toString().includes('other file beta'));
  assert.equal((await t.auditRows("action = 'doc.integrity_failure' AND doc_id = $1", [a])).length, 1);
});

test('the response never serves HTML or inline content from an upload', async () => {
  const id = (await alice.client.upload('note.txt', '<html><script>alert(1)</script></html>', { name: 'N' })).json.id;
  const dl = await alice.client.get(`/api/documents/${id}/download`);
  assert.match(dl.headers.get('content-type'), /^text\/plain/);
  assert.match(dl.headers.get('content-disposition'), /^attachment/);
  assert.equal(dl.headers.get('x-content-type-options'), 'nosniff');
  assert.match(dl.headers.get('content-security-policy'), /sandbox/);
});

test('every response carries the security headers; API responses are not cacheable', async () => {
  const r = await alice.client.get('/api/documents');
  assert.match(r.headers.get('content-security-policy'), /default-src 'self'/);
  assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.match(r.headers.get('cache-control'), /no-store/);
  assert.equal(r.headers.get('x-powered-by'), null);
  assert.equal(r.headers.get('access-control-allow-origin'), null, 'no CORS');
});

test('the access advisor only suggests, never grants; a human confirms and both are audited', async () => {
  const mk = async (name, cat) => (await alice.client.upload(name + '.txt', name, { name, category: cat })).json.id;
  const d1 = await mk('contract-one', 'contracts');
  const d2 = await mk('contract-two', 'contracts');
  const target = await mk('contract-three', 'contracts');
  await alice.client.put(`/api/documents/${d1}/grants`, { userId: carol.id, permission: 'read' });
  await alice.client.put(`/api/documents/${d2}/grants`, { userId: carol.id, permission: 'read' });
  await alice.client.put(`/api/documents/${d2}/grants`, { userId: dave.id, permission: 'read' });

  const before = (await alice.client.get(`/api/documents/${target}/grants`)).json.grants;
  const s = await alice.client.post(`/api/documents/${target}/suggest-access`, {});
  assert.equal(s.status, 200);
  assert.equal(s.json.suggestions[0].userId, carol.id, 'most-related person ranked first');
  assert.ok(s.json.suggestions.every((x) => x.suggestedPermission === 'read'), 'never proposes edit');
  const after = (await alice.client.get(`/api/documents/${target}/grants`)).json.grants;
  assert.deepEqual(after, before, 'suggesting changed nothing');
  assert.equal((await carol.client.get(`/api/documents/${target}`)).status, 404, 'suggested person still has no access');

  // Only a confirmed grant call creates access, and it must reference a suggestion that really contained that user.
  const bogus = await alice.client.put(`/api/documents/${target}/grants`, { userId: bob.id, permission: 'read', suggestionId: s.json.suggestionId });
  assert.equal(bogus.status, 400);
  const ok = await alice.client.put(`/api/documents/${target}/grants`, { userId: carol.id, permission: 'read', suggestionId: s.json.suggestionId });
  assert.equal(ok.status, 200);
  assert.equal((await carol.client.get(`/api/documents/${target}`)).status, 200);

  const log = await t.auditRows('doc_id = $1', [target]);
  const actions = log.map((r) => r.action);
  assert.ok(actions.includes('ai.suggest'));
  assert.ok(actions.includes('ai.suggestion.accepted'));
  const acc = log.find((r) => r.action === 'ai.suggestion.accepted');
  assert.equal(acc.actor_email, alice.email, 'the decision is attributed to the human');
  assert.equal(acc.detail.overridden, false);
  // someone else's suggestion id cannot be replayed on another document
  const other = await mk('unrelated', 'misc');
  const replay = await alice.client.put(`/api/documents/${other}/grants`, { userId: carol.id, permission: 'read', suggestionId: s.json.suggestionId });
  assert.equal(replay.status, 400);
});

test('the user directory is narrow: short queries return nothing, viewers are refused, no secrets leak', async () => {
  assert.deepEqual((await alice.client.get('/api/users/directory?q=ab')).json.users, []);
  const r = await alice.client.get('/api/users/directory?q=carol');
  assert.ok(r.json.users.length >= 1);
  for (const u of r.json.users) assert.deepEqual(Object.keys(u).sort(), ['email', 'id', 'name', 'role']);
  assert.equal((await carol.client.get('/api/users/directory?q=carol')).status, 403);
});

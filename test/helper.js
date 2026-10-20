'use strict';
// Test harness: real HTTP against the real app, backed by an in-process Postgres (PGlite).
process.env.NODE_ENV = 'test';
process.env.SCRYPT_N = '4096'; // fast hashing in tests only
delete process.env.PGLITE_DIR;
delete process.env.SEED_DEMO;
// Default: in-process Postgres (PGlite). With TEST_DATABASE_URL set (see `npm run test:pg`) the very
// same suite runs against a real PostgreSQL server through the node-postgres driver used in production.
const REAL_PG = process.env.TEST_DATABASE_URL || null;
if (REAL_PG) process.env.DATABASE_URL = REAL_PG; else delete process.env.DATABASE_URL;

const { app } = require('../src/app');
const { getDb } = require('../src/db');
const { createUser } = require('../src/users');

const COOKIE = 'tv_session';
const PW = 'Correct-Horse-Battery-9';

class Client {
  constructor(base) { this.base = base; this.cookie = null; this.csrf = null; }

  async call(method, path, { json, form, headers = {}, csrf = true } = {}) {
    const h = { ...headers };
    if (this.cookie) h.cookie = this.cookie;
    if (csrf && this.csrf && method !== 'GET' && method !== 'HEAD') h['x-csrf-token'] = this.csrf;
    let body;
    if (json !== undefined) { h['content-type'] = 'application/json'; body = JSON.stringify(json); }
    if (form) body = form;
    const res = await fetch(this.base + path, { method, headers: h, body, redirect: 'manual' });
    for (const c of (res.headers.getSetCookie ? res.headers.getSetCookie() : [])) {
      const kv = c.split(';')[0];
      if (kv.startsWith(COOKIE + '=')) this.cookie = kv === COOKIE + '=' ? null : kv;
    }
    const raw = Buffer.from(await res.arrayBuffer());
    let parsed = null;
    try { parsed = JSON.parse(raw.toString('utf8')); } catch (_) { /* binary or empty */ }
    return { status: res.status, headers: res.headers, raw, json: parsed };
  }

  get(p, o) { return this.call('GET', p, o); }
  post(p, json, o) { return this.call('POST', p, { json, ...o }); }
  put(p, json) { return this.call('PUT', p, { json }); }
  patch(p, json) { return this.call('PATCH', p, { json }); }
  del(p) { return this.call('DELETE', p); }

  async login(email, password = PW) {
    const r = await this.post('/api/auth/login', { email, password });
    if (r.json && r.json.csrfToken) this.csrf = r.json.csrfToken;
    return r;
  }

  form(filename, content, fields = {}) {
    const f = new FormData();
    f.append('file', new Blob([content]), filename);
    for (const [k, v] of Object.entries(fields)) f.append(k, v);
    return f;
  }

  upload(filename, content, fields) { return this.call('POST', '/api/documents', { form: this.form(filename, content, fields) }); }
  newVersion(id, filename, content) { return this.call('POST', `/api/documents/${id}/versions`, { form: this.form(filename, content) }); }
}

let counter = 0;
async function start() {
  if (REAL_PG) { // every test file starts from an empty schema
    const { Pool } = require('pg');
    const pool = new Pool({ connectionString: REAL_PG });
    await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
    await pool.end();
  }
  const db = await getDb();
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;

  async function user(role, label) {
    const email = `${label || role}${++counter}@example.test`;
    const u = await createUser(db, { email, name: `${label || role} ${counter}`, role, password: PW });
    const c = new Client(base);
    const r = await c.login(email);
    if (r.status !== 200) throw new Error('test login failed: ' + r.status);
    return { ...u, client: c, email };
  }

  async function auditRows(where = 'TRUE', params = []) {
    return (await db.query(`SELECT * FROM audit_log WHERE ${where} ORDER BY seq`, params)).rows.map((r) => ({ ...r, detail: JSON.parse(r.detail) }));
  }

  const stop = () => new Promise((resolve) => server.close(() => { db.close().then(resolve, resolve); }));
  return { db, base, user, auditRows, stop, Client, PW };
}

module.exports = { start, Client, PW, REAL_PG };

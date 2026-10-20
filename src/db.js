'use strict';
/**
 * Tiny database adapter so the same SQL runs on:
 *   - node-postgres (production: Render Postgres, Neon, Supabase ...)
 *   - PGlite, an in-process Postgres (tests and `npm run dev`)
 * Every transaction object exposes query() and exec().
 */
const fs = require('fs');
const path = require('path');
const config = require('./config');

function createPg(url) {
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: url, max: process.env.VERCEL ? 3 : 10 });
  return {
    kind: 'pg',
    query: (text, params) => pool.query(text, params),
    exec: (text) => pool.query(text),
    async tx(fn) {
      const c = await pool.connect();
      try {
        await c.query('BEGIN');
        const out = await fn({ query: (t, p) => c.query(t, p), exec: (t) => c.query(t) });
        await c.query('COMMIT');
        return out;
      } catch (err) {
        try { await c.query('ROLLBACK'); } catch (_) { /* connection already broken */ }
        throw err;
      } finally {
        c.release();
      }
    },
    close: () => pool.end(),
  };
}

function createLite(dir) {
  const { PGlite } = require('@electric-sql/pglite');
  const pg = dir ? new PGlite(dir) : new PGlite();
  // PGlite reports changed rows as `affectedRows`; node-postgres calls it `rowCount`.
  // Normalise so application code (e.g. "did the revoke touch a row?") behaves identically on both.
  const norm = async (run) => {
    const r = await run();
    if (r && r.rowCount === undefined) r.rowCount = r.affectedRows !== undefined ? r.affectedRows : (r.rows ? r.rows.length : 0);
    return r;
  };
  return {
    kind: 'pglite',
    query: (text, params) => norm(() => pg.query(text, params)),
    exec: (text) => pg.exec(text),
    tx: (fn) => pg.transaction((t) => fn({ query: (s, p) => norm(() => t.query(s, p)), exec: (s) => t.exec(s) })),
    close: () => pg.close(),
  };
}

function makeDb() {
  if (config.databaseUrl) return createPg(config.databaseUrl);
  if (config.isProd) throw new Error('DATABASE_URL is required when NODE_ENV=production');
  return createLite(config.pgliteDir);
}

async function migrate(db) {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8');
  await db.tx(async (t) => {
    if (db.kind === 'pg') await t.query('SELECT pg_advisory_xact_lock(727274)'); // cold starts race
    await t.exec(sql);
  });
}

let dbPromise = null;

/** Lazily creates, migrates (and optionally demo-seeds) the database exactly once per process. */
function getDb() {
  if (!dbPromise) {
    dbPromise = (async () => {
      const db = makeDb();
      await migrate(db);
      if (config.seedDemo) await require('./seed').seedDemo(db);
      return db;
    })();
    dbPromise.catch(() => { dbPromise = null; }); // let the next request retry
  }
  return dbPromise;
}

module.exports = { getDb, migrate, makeDb };

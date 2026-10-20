'use strict';
// Creates / updates the schema (idempotent). Usage: DATABASE_URL=postgres://... npm run migrate
const { getDb } = require('../src/db');

getDb()
  .then(async (db) => { console.log(`Schema is up to date (${db.kind}).`); await db.close(); })
  .catch((e) => { console.error(e.message); process.exit(1); });

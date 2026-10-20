'use strict';
// Destroys the encrypted bytes of documents that have sat in the trash past the retention window.
// Run daily (Render Cron Job) or use the Vercel cron in vercel.json. Usage: npm run purge
const { getDb } = require('../src/db');
const { purgeExpired } = require('../src/purge');

getDb()
  .then(async (db) => { console.log(`Purged ${await purgeExpired(db)} document(s).`); await db.close(); })
  .catch((e) => { console.error(e.message); process.exit(1); });

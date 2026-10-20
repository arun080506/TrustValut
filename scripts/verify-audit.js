'use strict';
// Operator tool: verify the audit chain from the command line (needs the same AUDIT_HMAC_KEY
// the app uses). Exit code 1 if the trail has been altered. Usage: npm run audit:verify
const { getDb } = require('../src/db');
const audit = require('../src/audit');

getDb()
  .then(async (db) => {
    const r = await audit.verify(db);
    console.log(JSON.stringify(r, null, 2));
    await db.close();
    process.exit(r.ok ? 0 : 1);
  })
  .catch((e) => { console.error(e.message); process.exit(2); });

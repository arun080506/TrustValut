'use strict';
// Loads the demo accounts and documents into an EMPTY database. Usage: npm run seed
process.env.SEED_DEMO = 'true';
const { getDb } = require('../src/db');
const { DEMO } = require('../src/seed');

getDb()
  .then(async (db) => {
    console.log('Demo data present. Accounts:');
    for (const u of Object.values(DEMO)) console.log(`  ${u.role.padEnd(6)} ${u.email}  ${u.password}`);
    await db.close();
  })
  .catch((e) => { console.error(e.message); process.exit(1); });

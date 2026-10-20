'use strict';
/**
 * Runs the whole suite against a REAL PostgreSQL server (the same driver production uses) instead
 * of PGlite. Starts a throw-away server from the `embedded-postgres` dev dependency, runs the
 * tests, then stops it.
 *
 *   npm run test:pg
 *
 * Postgres refuses to start as root. In a root container:  runuser -u <someuser> -- npm run test:pg
 * Or point at your own server:  TEST_DATABASE_URL=postgres://... npm test   (WARNING: the public
 * schema of that database is dropped before every test file).
 */
const os = require('os');
const fs = require('fs');
const path = require('path');
const net = require('net');
const { spawn } = require('child_process');

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
    s.on('error', reject);
  });
}

(async () => {
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    console.error('PostgreSQL will not run as root. Re-run as an unprivileged user, e.g.\n  runuser -u nobody -- npm run test:pg');
    process.exit(2);
  }
  const { default: EmbeddedPostgres } = await import('embedded-postgres');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-pg-'));
  const port = await freePort();
  const pg = new EmbeddedPostgres({ databaseDir: path.join(dir, 'data'), user: 'tv', password: 'tv', port, persistent: false, onLog: () => {}, onError: () => {} });
  await pg.initialise();
  await pg.start();
  await pg.createDatabase('trustvault');
  const url = `postgres://tv:tv@127.0.0.1:${port}/trustvault`;
  console.log(`Real PostgreSQL ready on :${port}. Running the suite...\n`);

  const files = process.argv.slice(2);
  const args = ['--test', '--test-concurrency=1', ...(files.length ? files : fs.readdirSync(path.join(__dirname, '..', 'test')).filter((f) => f.endsWith('.test.js')).map((f) => 'test/' + f))];
  const child = spawn(process.execPath, args, { cwd: path.join(__dirname, '..'), stdio: 'inherit', env: { ...process.env, TEST_DATABASE_URL: url } });
  child.on('close', async (code) => {
    try { await pg.stop(); } catch (_) { /* already down */ }
    fs.rmSync(dir, { recursive: true, force: true });
    process.exit(code);
  });
})().catch((e) => { console.error(e); process.exit(2); });

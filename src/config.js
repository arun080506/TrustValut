'use strict';
const crypto = require('crypto');

const env = process.env;
const isProd = env.NODE_ENV === 'production';
const isTest = env.NODE_ENV === 'test';

const int = (v, d) => (v !== undefined && v !== '' && Number.isFinite(Number(v)) ? Number(v) : d);

/** Keys fail closed in production: no key, no start. Dev/test get a deterministic insecure key. */
function loadKey(name, minBytes) {
  const raw = env[name];
  if (raw) {
    const isHex = /^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0;
    const buf = isHex ? Buffer.from(raw, 'hex') : Buffer.from(raw, 'base64');
    if (buf.length < minBytes) {
      throw new Error(`${name} must decode to at least ${minBytes} bytes (hex or base64). Run: npm run keys`);
    }
    return buf;
  }
  if (isProd) throw new Error(`${name} is required when NODE_ENV=production. Run: npm run keys`);
  if (!isTest) console.warn(`[config] ${name} not set - using an INSECURE development key`);
  return crypto.createHash('sha256').update('trustvault-dev-only:' + name).digest();
}

module.exports = {
  isProd,
  isTest,
  masterKey: loadKey('FILE_MASTER_KEY', 32).subarray(0, 32),
  auditKey: loadKey('AUDIT_HMAC_KEY', 32),
  databaseUrl: env.DATABASE_URL || null,
  pgliteDir: env.PGLITE_DIR || null,
  // Vercel functions cap request bodies at ~4.5 MB, so the default stays under that.
  maxUploadBytes: int(env.MAX_UPLOAD_BYTES, 4 * 1024 * 1024),
  sessionAbsoluteMs: int(env.SESSION_ABSOLUTE_HOURS, 8) * 3600 * 1000,
  sessionIdleMs: int(env.SESSION_IDLE_MINUTES, 30) * 60 * 1000,
  cookieName: isProd ? '__Host-tv_session' : 'tv_session',
  scrypt: { N: int(env.SCRYPT_N, 32768), r: 8, p: 1 },
  lockout: { maxFails: 5, minutes: 15 },
  ipFailureLimit: { max: 30, windowMs: 10 * 60 * 1000 },
  trashRetentionDays: int(env.TRASH_RETENTION_DAYS, 30),
  seedDemo: env.SEED_DEMO === 'true',
  cronSecret: env.CRON_SECRET || null,
};

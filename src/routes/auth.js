'use strict';
const express = require('express');
const config = require('../config');
const { getDb } = require('../db');
const audit = require('../audit');
const { HttpError, asyncHandler, ipOf } = require('../http');
const { verifyPassword, hashPassword, dummyVerify, safeEqual } = require('../crypto');
const { normalizeEmail, checkPassword } = require('../validate');
const { requireAuth, createSession, setSessionCookie, clearSessionCookie, parseCookies } = require('../auth');
const { revokeAllSessions } = require('../users');
const { sha256hex } = require('../crypto');

const router = express.Router();

const INVALID = new HttpError(401, 'invalid_credentials', 'Invalid email or password');

router.post('/login', asyncHandler(async (req, res) => {
  const db = await getDb();
  const ip = ipOf(req);
  const email = normalizeEmail(req.body && req.body.email);
  const password = req.body && req.body.password;
  if (!email || typeof password !== 'string' || password.length > 256) throw INVALID;

  // Per-IP throttle, computed from the audit trail itself (works across serverless instances).
  const since = new Date(Date.now() - config.ipFailureLimit.windowMs).toISOString();
  const recent = await db.query(
    "SELECT count(*)::int AS n FROM audit_log WHERE action = 'auth.login_failed' AND ip = $1 AND ts > $2", [ip, since]);
  if (recent.rows[0].n >= config.ipFailureLimit.max) {
    throw new HttpError(429, 'too_many_attempts', 'Too many failed attempts. Try again later.');
  }

  const found = await db.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = found.rows[0];
  const locked = user && user.locked_until && new Date(user.locked_until) > new Date();

  let ok = false;
  let reason = 'unknown_user';
  if (!user) {
    await dummyVerify(password);
  } else if (locked) {
    await dummyVerify(password);
    reason = 'locked';
  } else if (!user.active) {
    await dummyVerify(password);
    reason = 'inactive';
  } else {
    ok = await verifyPassword(password, user.password_hash);
    reason = 'bad_password';
  }

  if (!ok) {
    await db.tx(async (tx) => {
      if (user && reason === 'bad_password') {
        const fails = user.failed_logins + 1;
        if (fails >= config.lockout.maxFails) {
          await tx.query(
            "UPDATE users SET failed_logins = 0, locked_until = now() + ($2 || ' minutes')::interval WHERE id = $1",
            [user.id, String(config.lockout.minutes)]);
        } else {
          await tx.query('UPDATE users SET failed_logins = $2 WHERE id = $1', [user.id, fails]);
        }
      }
      await audit.append(tx, {
        actorEmail: email.slice(0, 254), action: 'auth.login_failed', outcome: 'denied', ip,
        targetUserId: user ? user.id : null, detail: { reason },
      });
    });
    throw INVALID; // same answer for every failure mode
  }

  // Fresh token on every login (no session fixation); any session presented with the request is revoked.
  const old = parseCookies(req.headers.cookie)[config.cookieName];
  const result = await db.tx(async (tx) => {
    if (old) await tx.query('UPDATE sessions SET revoked_at = now() WHERE id_hash = $1 AND revoked_at IS NULL', [sha256hex(old)]);
    await tx.query('UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1', [user.id]);
    const s = await createSession(tx, user, req);
    await audit.append(tx, { actor: user, action: 'auth.login', ip, detail: {} });
    return s;
  });
  setSessionCookie(res, result.token, config.sessionAbsoluteMs);
  res.json({ user: { id: user.id, email: user.email, name: user.name, role: user.role }, csrfToken: result.csrf });
}));

router.get('/me', asyncHandler(async (req, res) => {
  if (!req.user) return res.json({ user: null, csrfToken: null }); // a probe, not an error
  return res.json({ user: req.user, csrfToken: req.session.csrf });
}));

router.post('/logout', requireAuth, asyncHandler(async (req, res) => {
  const db = await getDb();
  await db.tx(async (tx) => {
    await tx.query('UPDATE sessions SET revoked_at = now() WHERE id_hash = $1', [req.session.idHash]);
    await audit.append(tx, { actor: req.user, action: 'auth.logout', ip: ipOf(req), detail: {} });
  });
  clearSessionCookie(res);
  res.json({ ok: true });
}));

router.post('/password', requireAuth, asyncHandler(async (req, res) => {
  const db = await getDb();
  const { current, next } = req.body || {};
  checkPassword(next);
  const { rows } = await db.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
  if (typeof current !== 'string' || !(await verifyPassword(current, rows[0].password_hash))) {
    await audit.record(db, { actor: req.user, action: 'auth.password_change', outcome: 'denied', ip: ipOf(req), detail: { reason: 'bad_current_password' } });
    throw new HttpError(403, 'bad_current_password', 'Current password is incorrect');
  }
  const hash = await hashPassword(next);
  await db.tx(async (tx) => {
    await tx.query('UPDATE users SET password_hash = $2 WHERE id = $1', [req.user.id, hash]);
    // Every other session of this user dies immediately; the current one is kept.
    await tx.query('UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND id_hash <> $2 AND revoked_at IS NULL', [req.user.id, req.session.idHash]);
    await audit.append(tx, { actor: req.user, action: 'auth.password_change', ip: ipOf(req), detail: {} });
  });
  res.json({ ok: true });
}));

module.exports = router;
module.exports.safeEqual = safeEqual;

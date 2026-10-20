'use strict';
const config = require('./config');
const { getDb } = require('./db');
const audit = require('./audit');
const { HttpError, ipOf } = require('./http');
const { sha256hex, randomToken, safeEqual } = require('./crypto');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch (_) { /* skip */ }
  }
  return out;
}

function setSessionCookie(res, token, maxAgeMs) {
  const attrs = [`${config.cookieName}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${Math.floor(maxAgeMs / 1000)}`];
  if (config.isProd) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

const clearSessionCookie = (res) => setSessionCookie(res, '', 0);

async function createSession(tx, user, req) {
  const token = randomToken(32);
  const csrf = randomToken(24);
  await tx.query(
    `INSERT INTO sessions(id_hash, user_id, csrf_token, expires_at, ip, user_agent)
     VALUES ($1, $2, $3, now() + ($4 || ' milliseconds')::interval, $5, $6)`,
    [sha256hex(token), user.id, csrf, String(config.sessionAbsoluteMs), ipOf(req), String(req.headers['user-agent'] || '').slice(0, 200)]
  );
  return { token, csrf };
}

/** Loads the session on every request. Nothing about the user is trusted from the cookie itself. */
async function attachSession(req, res, next) {
  req.user = null;
  req.session = null;
  try {
    const token = parseCookies(req.headers.cookie)[config.cookieName];
    if (token && token.length >= 20 && token.length <= 200) {
      const db = await getDb();
      const { rows } = await db.query(
        `SELECT s.id_hash, s.csrf_token, s.last_seen, u.id, u.email, u.name, u.role
           FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE s.id_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now() AND u.active = true`,
        [sha256hex(token)]
      );
      const r = rows[0];
      if (r) {
        const idle = Date.now() - new Date(r.last_seen).getTime();
        if (idle > config.sessionIdleMs) {
          await db.query('UPDATE sessions SET revoked_at = now() WHERE id_hash = $1', [r.id_hash]);
        } else {
          req.user = { id: r.id, email: r.email, name: r.name, role: r.role };
          req.session = { idHash: r.id_hash, csrf: r.csrf_token };
          if (idle > 60000) await db.query('UPDATE sessions SET last_seen = now() WHERE id_hash = $1', [r.id_hash]);
        }
      }
    }
    next();
  } catch (err) {
    next(err);
  }
}

/** Authentication + CSRF (custom header bound to the session) for every state-changing request. */
function requireAuth(req, res, next) {
  if (!req.user) return next(new HttpError(401, 'unauthenticated', 'Sign in required'));
  if (!SAFE_METHODS.has(req.method)) {
    const header = req.headers['x-csrf-token'];
    if (typeof header !== 'string' || !safeEqual(header, req.session.csrf)) {
      return next(new HttpError(403, 'csrf', 'Missing or invalid CSRF token'));
    }
  }
  return next();
}

/** Role gate. Refusals are written to the audit trail, then answered with 403. */
function requireRole(...roles) {
  return async (req, res, next) => {
    if (roles.includes(req.user.role)) return next();
    try {
      const db = await getDb();
      await audit.record(db, {
        actor: req.user, action: 'access.denied', outcome: 'denied', ip: ipOf(req),
        detail: { reason: 'role', required: roles, had: req.user.role, route: `${req.method} ${req.baseUrl}${req.path}`.slice(0, 200) },
      });
    } catch (_) { /* refusal still stands */ }
    return next(new HttpError(403, 'forbidden', 'Your role does not allow this'));
  };
}

/** Same-site check for browsers: a cross-origin Origin header on a write is refused outright. */
function originCheck(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();
  const origin = req.headers.origin;
  if (origin) {
    let host = null;
    try { host = new URL(origin).host; } catch (_) { /* malformed */ }
    if (!host || host !== req.headers.host) return next(new HttpError(403, 'cross_origin', 'Cross-origin request refused'));
  }
  return next();
}

module.exports = {
  attachSession, requireAuth, requireRole, originCheck,
  createSession, setSessionCookie, clearSessionCookie, parseCookies,
};

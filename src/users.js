'use strict';
const { randomUUID } = require('crypto');
const { hashPassword, randomToken } = require('./crypto');
const { HttpError } = require('./http');
const { isEmail, normalizeEmail, checkPassword, requireText } = require('./validate');

const ROLES = ['admin', 'owner', 'viewer'];

async function createUser(q, { email, name, role, password }) {
  const e = normalizeEmail(email);
  if (!isEmail(e)) throw new HttpError(400, 'invalid_email', 'A valid email is required');
  if (!ROLES.includes(role)) throw new HttpError(400, 'invalid_role', `Role must be one of ${ROLES.join(', ')}`);
  const n = requireText(name, 'name', 100);
  checkPassword(password);
  const id = randomUUID();
  try {
    await q.query(
      'INSERT INTO users(id, email, name, role, password_hash) VALUES ($1,$2,$3,$4,$5)',
      [id, e, n, role, await hashPassword(password)]
    );
  } catch (err) {
    if (err && (err.code === '23505' || /unique/i.test(err.message))) throw new HttpError(409, 'email_taken', 'That email is already registered');
    throw err;
  }
  return { id, email: e, name: n, role };
}

/** 16 random chars satisfying the length policy; shown to the admin once. */
const temporaryPassword = () => randomToken(12) + 'aA1!';

async function revokeAllSessions(q, userId) {
  const r = await q.query('UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL', [userId]);
  return r.rowCount || 0;
}

module.exports = { createUser, temporaryPassword, revokeAllSessions, ROLES };

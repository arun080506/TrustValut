'use strict';
const express = require('express');
const { getDb } = require('../db');
const audit = require('../audit');
const { HttpError, asyncHandler, isUuid, ipOf } = require('../http');
const { requireAuth, requireRole } = require('../auth');
const { createUser, temporaryPassword, revokeAllSessions, ROLES } = require('../users');
const { requireText, clean, likeEscape, parseDate } = require('../validate');
const { hashPassword } = require('../crypto');

const router = express.Router();
router.use(requireAuth, requireRole('admin'));

// Admins govern the system; they do not read content. No route here returns file bytes.

// ------------------------------------------------------------------ overview + "worth noticing"
router.get('/summary', asyncHandler(async (req, res) => {
  const db = await getDb();
  const since = (ms) => new Date(Date.now() - ms).toISOString();
  const one = async (sql, p) => (await db.query(sql, p)).rows;

  const [users, docs, grants, events, denied24, failed24] = await Promise.all([
    one("SELECT role, count(*)::int AS n FROM users WHERE active = true GROUP BY role"),
    one('SELECT count(*)::int AS n FROM documents WHERE deleted_at IS NULL'),
    one('SELECT count(*)::int AS n FROM grants WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())'),
    one('SELECT count(*)::int AS n FROM audit_log'),
    one("SELECT count(*)::int AS n FROM audit_log WHERE outcome = 'denied' AND action NOT LIKE 'auth.%' AND ts > $1", [since(86400000)]),
    one("SELECT count(*)::int AS n FROM audit_log WHERE action = 'auth.login_failed' AND ts > $1", [since(86400000)]),
  ]);

  const alerts = [];
  for (const r of await one(
    `SELECT actor_email, count(*)::int AS n FROM audit_log
      WHERE outcome = 'denied' AND action NOT LIKE 'auth.%' AND ts > $1 GROUP BY actor_email HAVING count(*) >= 5`, [since(3600000)])) {
    alerts.push({ severity: 'high', kind: 'repeated_denials', message: `${r.actor_email} was refused ${r.n} times in the last hour`, who: r.actor_email });
  }
  for (const r of await one(
    `SELECT actor_email, count(*)::int AS n FROM audit_log
      WHERE action = 'doc.download' AND ts > $1 GROUP BY actor_email HAVING count(*) >= 10`, [since(600000)])) {
    alerts.push({ severity: 'high', kind: 'download_burst', message: `${r.actor_email} downloaded ${r.n} files in 10 minutes`, who: r.actor_email });
  }
  for (const r of await one(
    `SELECT ip, count(*)::int AS n FROM audit_log
      WHERE action = 'auth.login_failed' AND ts > $1 GROUP BY ip HAVING count(*) >= 5`, [since(3600000)])) {
    const source = ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(r.ip)
      ? `${r.ip} (this computer / local testing)`
      : r.ip;
    alerts.push({ severity: 'medium', kind: 'login_failures', message: `${r.n} failed sign-in attempts from ${source} in the last hour`, who: r.ip });
  }
  const sensitive = await one(
    `SELECT seq, ts, actor_email, action, doc_id, detail FROM audit_log
      WHERE actor_email <> 'system:seed'
        AND action IN ('admin.doc_transfer','admin.grant_revoke','admin.user_role','admin.user_deactivate','admin.user_create','admin.user_credentials_update','admin.password_reset','doc.integrity_failure')
      ORDER BY seq DESC LIMIT 20`);
  res.json({
    counts: {
      activeUsers: Object.fromEntries(users.map((u) => [u.role, u.n])),
      documents: docs[0].n, activeGrants: grants[0].n, auditEvents: events[0].n,
      refusals24h: denied24[0].n, failedLogins24h: failed24[0].n,
    },
    alerts,
    recentSensitive: sensitive.map((s) => ({ ...s, detail: JSON.parse(s.detail) })),
  });
}));

// ------------------------------------------------------------------ documents (metadata only)
router.get('/documents', asyncHandler(async (req, res) => {
  const db = await getDb();
  const params = [];
  const where = ['d.purged_at IS NULL'];
  const q = clean(req.query.q || '', 100);
  if (q) { params.push('%' + likeEscape(q) + '%'); where.push(`(d.name ILIKE $${params.length} OR u.email ILIKE $${params.length})`); }
  const { rows } = await db.query(
    `SELECT d.id, d.name, d.category, d.current_version, d.created_at, d.updated_at, d.deleted_at,
            u.id AS owner_id, u.name AS owner_name, u.email AS owner_email, u.active AS owner_active,
            (SELECT count(*)::int FROM grants g WHERE g.document_id = d.id AND g.revoked_at IS NULL
                AND (g.expires_at IS NULL OR g.expires_at > now())) AS active_grants
       FROM documents d JOIN users u ON u.id = d.owner_id
      WHERE ${where.join(' AND ')} ORDER BY d.updated_at DESC LIMIT 200`, params);
  res.json({ documents: rows });
}));

router.get('/documents/:id/grants', asyncHandler(async (req, res) => {
  const db = await getDb();
  if (!isUuid(req.params.id)) throw new HttpError(404, 'not_found', 'Document not found');
  const { rows } = await db.query(
    `SELECT g.user_id, g.permission, g.created_at, g.expires_at, g.revoked_at, u.email, u.name
       FROM grants g JOIN users u ON u.id = g.user_id WHERE g.document_id = $1 ORDER BY g.created_at DESC`, [req.params.id]);
  res.json({ grants: rows });
}));

// Emergency revoke (e.g. a leaver's grants). Audited as an admin action.
router.delete('/documents/:id/grants/:userId', asyncHandler(async (req, res) => {
  const db = await getDb();
  if (!isUuid(req.params.id) || !isUuid(req.params.userId)) throw new HttpError(400, 'invalid_id', 'Invalid id');
  await db.tx(async (tx) => {
    await tx.query('SELECT id FROM documents WHERE id = $1 FOR UPDATE', [req.params.id]);
    const done = await tx.query(
      'UPDATE grants SET revoked_at = now(), revoked_by = $3 WHERE document_id = $1 AND user_id = $2 AND revoked_at IS NULL',
      [req.params.id, req.params.userId, req.user.id]);
    if (!done.rowCount) throw new HttpError(404, 'no_active_grant', 'No active grant');
    await audit.append(tx, { actor: req.user, action: 'admin.grant_revoke', docId: req.params.id, targetUserId: req.params.userId, ip: ipOf(req), detail: { reason: requireText(req.body && req.body.reason, 'reason', 300, { required: false }) } });
  });
  res.json({ ok: true });
}));

// Ownership transfer is only possible for documents whose owner has been deactivated, so an
// admin cannot take a live user's documents. Always audited and always surfaced on the overview.
router.post('/documents/:id/transfer', asyncHandler(async (req, res) => {
  const db = await getDb();
  const { newOwnerId } = req.body || {};
  if (!isUuid(req.params.id) || !isUuid(newOwnerId)) throw new HttpError(400, 'invalid_id', 'Invalid id');
  const reason = requireText(req.body.reason, 'reason', 300);
  await db.tx(async (tx) => {
    const d = (await tx.query('SELECT d.id, d.owner_id, u.active AS owner_active FROM documents d JOIN users u ON u.id = d.owner_id WHERE d.id = $1 FOR UPDATE OF d', [req.params.id])).rows[0];
    if (!d) throw new HttpError(404, 'not_found', 'Document not found');
    if (d.owner_active) throw new HttpError(409, 'owner_active', 'Only documents whose owner is deactivated can be transferred');
    const n = (await tx.query('SELECT id, role, active, email FROM users WHERE id = $1', [newOwnerId])).rows[0];
    if (!n || !n.active || n.role !== 'owner') throw new HttpError(400, 'invalid_new_owner', 'New owner must be an active user with the owner role');
    await tx.query('UPDATE documents SET owner_id = $2, updated_at = now() WHERE id = $1', [d.id, n.id]);
    await tx.query('UPDATE grants SET revoked_at = now(), revoked_by = $2 WHERE document_id = $1 AND user_id = $3 AND revoked_at IS NULL', [d.id, req.user.id, n.id]);
    await audit.append(tx, { actor: req.user, action: 'admin.doc_transfer', docId: d.id, targetUserId: n.id, ip: ipOf(req), detail: { from: d.owner_id, to: n.id, toEmail: n.email, reason } });
  });
  res.json({ ok: true });
}));

// ------------------------------------------------------------------ audit trail
router.get('/audit', asyncHandler(async (req, res) => {
  const db = await getDb();
  const params = [];
  const where = [];
  const add = (v) => { params.push(v); return '$' + params.length; };
  const s = (v) => (typeof v === 'string' ? clean(v, 100) : '');
  if (s(req.query.actor)) where.push(`actor_email ILIKE ${add('%' + likeEscape(s(req.query.actor)) + '%')}`);
  if (s(req.query.action)) where.push(`action LIKE ${add(likeEscape(s(req.query.action)) + '%')}`);
  if (['allowed', 'denied'].includes(req.query.outcome)) where.push(`outcome = ${add(req.query.outcome)}`);
  if (isUuid(req.query.doc)) where.push(`doc_id = ${add(req.query.doc)}`);
  const from = parseDate(req.query.from, 'from');
  const to = parseDate(req.query.to, 'to');
  if (from) where.push(`ts >= ${add(from.toISOString())}`);
  if (to) where.push(`ts < ${add(new Date(to.getTime() + 86400000).toISOString())}`);
  const before = parseInt(req.query.before, 10);
  if (Number.isInteger(before) && before > 0) where.push(`seq < ${add(before)}`);
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 200);
  const { rows } = await db.query(
    `SELECT seq, ts, actor_id, actor_email, action, outcome, doc_id, target_user_id, ip, detail, hash
       FROM audit_log ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY seq DESC LIMIT ${limit}`, params);
  res.json({ entries: rows.map((r) => ({ ...r, detail: JSON.parse(r.detail) })) });
}));

router.get('/audit/verify', asyncHandler(async (req, res) => {
  const db = await getDb();
  res.json(await audit.verify(db));
}));

// ------------------------------------------------------------------ users
router.get('/users', asyncHandler(async (req, res) => {
  const db = await getDb();
  const { rows } = await db.query(
    `SELECT u.id, u.email, u.name, u.role, u.active, u.created_at,
            (SELECT count(*)::int FROM sessions s WHERE s.user_id = u.id AND s.revoked_at IS NULL AND s.expires_at > now()) AS live_sessions
       FROM users u ORDER BY u.created_at`);
  res.json({ users: rows });
}));

router.post('/users', asyncHandler(async (req, res) => {
  const db = await getDb();
  const { email, name, role } = req.body || {};
  const password = temporaryPassword();
  const user = await db.tx(async (tx) => {
    const u = await createUser(tx, { email, name, role, password });
    await audit.append(tx, { actor: req.user, action: 'admin.user_create', targetUserId: u.id, ip: ipOf(req), detail: { email: u.email, role: u.role } });
    return u;
  });
  res.status(201).json({ user, temporaryPassword: password, note: 'Shown once. Ask the user to change it after first sign-in.' });
}));

async function mutateUser(req, res, action, fn) {
  const db = await getDb();
  if (!isUuid(req.params.id)) throw new HttpError(404, 'not_found', 'User not found');
  await db.tx(async (tx) => {
    const u = (await tx.query('SELECT id, email, role, active FROM users WHERE id = $1 FOR UPDATE', [req.params.id])).rows[0];
    if (!u) throw new HttpError(404, 'not_found', 'User not found');
    const detail = await fn(tx, u);
    await audit.append(tx, { actor: req.user, action, targetUserId: u.id, ip: ipOf(req), detail: { email: u.email, ...detail } });
  });
  res.json({ ok: true });
}

const notSelf = (req) => {
  if (req.params.id === req.user.id) throw new HttpError(409, 'self_change', 'You cannot do this to your own account');
};

async function lastAdminGuard(tx, u) {
  if (u.role !== 'admin' || !u.active) return;
  const n = (await tx.query("SELECT count(*)::int AS n FROM users WHERE role = 'admin' AND active = true")).rows[0].n;
  if (n <= 1) throw new HttpError(409, 'last_admin', 'This is the last active administrator');
}

router.post('/users/:id/deactivate', asyncHandler(async (req, res) => {
  notSelf(req);
  await mutateUser(req, res, 'admin.user_deactivate', async (tx, u) => {
    await lastAdminGuard(tx, u);
    await tx.query('UPDATE users SET active = false WHERE id = $1', [u.id]);
    const killed = await revokeAllSessions(tx, u.id);
    return { sessionsRevoked: killed };
  });
}));

router.post('/users/:id/activate', asyncHandler(async (req, res) => {
  await mutateUser(req, res, 'admin.user_activate', async (tx, u) => {
    await tx.query('UPDATE users SET active = true, failed_logins = 0, locked_until = NULL WHERE id = $1', [u.id]);
    return {};
  });
}));

router.post('/users/:id/role', asyncHandler(async (req, res) => {
  notSelf(req);
  const role = req.body && req.body.role;
  if (!ROLES.includes(role)) throw new HttpError(400, 'invalid_role', `Role must be one of ${ROLES.join(', ')}`);
  await mutateUser(req, res, 'admin.user_role', async (tx, u) => {
    await lastAdminGuard(tx, u);
    await tx.query('UPDATE users SET role = $2 WHERE id = $1', [u.id, role]);
    await revokeAllSessions(tx, u.id); // privileges changed: force a fresh sign-in
    return { from: u.role, to: role };
  });
}));

router.post('/users/:id/revoke-sessions', asyncHandler(async (req, res) => {
  await mutateUser(req, res, 'admin.session_revoke', async (tx, u) => ({ sessionsRevoked: await revokeAllSessions(tx, u.id) }));
}));

router.post('/users/:id/reset-password', asyncHandler(async (req, res) => {
  const db = await getDb();
  if (!isUuid(req.params.id)) throw new HttpError(404, 'not_found', 'User not found');
  const password = temporaryPassword();
  const hash = await hashPassword(password);
  await db.tx(async (tx) => {
    const u = (await tx.query('SELECT id, email FROM users WHERE id = $1 FOR UPDATE', [req.params.id])).rows[0];
    if (!u) throw new HttpError(404, 'not_found', 'User not found');
    await tx.query('UPDATE users SET password_hash = $2, failed_logins = 0, locked_until = NULL WHERE id = $1', [u.id, hash]);
    await revokeAllSessions(tx, u.id);
    await audit.append(tx, { actor: req.user, action: 'admin.password_reset', targetUserId: u.id, ip: ipOf(req), detail: { email: u.email } });
  });
  res.json({ temporaryPassword: password, note: 'Shown once.' });
}));

module.exports = router;

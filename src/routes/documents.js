'use strict';
const express = require('express');
const multer = require('multer');
const { randomUUID } = require('crypto');
const config = require('../config');
const { getDb } = require('../db');
const audit = require('../audit');
const { HttpError, Denied, asyncHandler, isUuid, ipOf } = require('../http');
const { resolveAccess, can } = require('../authz');
const { requireAuth, requireRole } = require('../auth');
const { decryptFile, sha256hex } = require('../crypto');
const { requireText, clean, parseDate } = require('../validate');
const { createDocument, addVersion, searchDocuments } = require('../docs-service');
const { suggest } = require('../suggest');

const router = express.Router();
router.use(requireAuth);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxUploadBytes, files: 1, fields: 10, fieldSize: 4096, parts: 15 },
});

const parseUpload = (req, res) => new Promise((resolve, reject) => {
  upload.single('file')(req, res, (err) => {
    if (!err) return resolve();
    if (err.code === 'LIMIT_FILE_SIZE') return reject(new HttpError(413, 'file_too_large', `File exceeds the ${config.maxUploadBytes} byte limit`));
    return reject(new HttpError(400, 'bad_upload', 'Malformed upload'));
  });
});

/**
 * The one place a document decision is turned into allow / deny.
 *   no access at all          -> Denied(404)  identical to "does not exist"
 *   access, but not enough    -> Denied(403)
 * Called INSIDE the transaction that performs the action, with the document row locked.
 */
async function authorize(q, req, need, { lock, allowDeleted = false, action }) {
  const r = await resolveAccess(q, req.user, req.params.id, { lock });
  if (!r || (r.doc.deleted_at && !allowDeleted)) {
    throw new Denied(404, { action, need, had: null });
  }
  if (!can(r.level, need)) {
    throw new Denied(403, { action, need, had: r.level });
  }
  return r;
}

/** Wraps a handler: a Denied is audited (outcome=denied) and answered; anything else bubbles up. */
const docRoute = (fn) => asyncHandler(async (req, res) => {
  try {
    await fn(req, res);
  } catch (err) {
    if (!(err instanceof Denied)) throw err;
    const db = await getDb();
    await audit.record(db, {
      actor: req.user, action: 'access.denied', outcome: 'denied', ip: ipOf(req),
      docId: isUuid(req.params.id) ? req.params.id : null,
      detail: {
        attempted: err.info.action, needed: err.info.need, had: err.info.had,
        route: `${req.method} ${req.baseUrl}${req.path}`.slice(0, 200),
        rawId: isUuid(req.params.id) ? undefined : String(req.params.id).slice(0, 64),
      },
    });
    const body = err.status === 404
      ? { error: 'not_found', message: 'Document not found' }
      : { error: 'forbidden', message: 'You do not have permission to do that' };
    res.status(err.status).json(body);
  }
});

const view = (r) => ({
  id: r.doc.id, name: r.doc.name, category: r.doc.category, description: r.doc.description,
  version: r.doc.current_version, createdAt: r.doc.created_at, updatedAt: r.doc.updated_at,
  deletedAt: r.doc.deleted_at, access: r.level,
});

// ---------------------------------------------------------------- list / search
router.get('/', asyncHandler(async (req, res) => {
  const db = await getDb();
  const s = (v) => (typeof v === 'string' ? clean(v, 100) : '');
  const docs = await searchDocuments(db, req.user, {
    q: s(req.query.q), owner: s(req.query.owner), category: s(req.query.category),
    from: s(req.query.from), to: s(req.query.to), scope: s(req.query.scope),
    trash: req.query.trash === '1', limit: req.query.limit, offset: req.query.offset,
  });
  res.json({ documents: docs });
}));

router.get('/categories', asyncHandler(async (req, res) => {
  const db = await getDb();
  const { rows } = await db.query(
    `SELECT DISTINCT lower(d.category) AS category FROM documents d
       LEFT JOIN grants g ON g.document_id = d.id AND g.user_id = $1 AND g.revoked_at IS NULL
                         AND (g.expires_at IS NULL OR g.expires_at > now())
      WHERE d.deleted_at IS NULL AND (d.owner_id = $1 OR g.id IS NOT NULL) ORDER BY 1`, [req.user.id]);
  res.json({ categories: rows.map((r) => r.category) });
}));

// ---------------------------------------------------------------- upload (owners only)
router.post('/', requireRole('owner'), asyncHandler(async (req, res) => {
  await parseUpload(req, res);
  if (!req.file) throw new HttpError(400, 'no_file', 'Attach a file in the "file" field');
  const db = await getDb();
  const name = requireText(req.body.name, 'name', 200, { required: false });
  const category = requireText(req.body.category, 'category', 60, { required: false }) || 'general';
  const description = requireText(req.body.description, 'description', 1000, { required: false });
  const id = await db.tx((tx) => createDocument(tx, { owner: req.user, name, category, description, file: req.file, ip: ipOf(req) }));
  res.status(201).json({ id });
}));

// ---------------------------------------------------------------- metadata
router.get('/:id', docRoute(async (req, res) => {
  const db = await getDb();
  const r = await authorize(db, req, 'read', { action: 'doc.view', allowDeleted: true });
  const owner = (await db.query('SELECT id, name, email FROM users WHERE id = $1', [r.doc.owner_id])).rows[0];
  const versions = (await db.query(
    `SELECT v.version, v.filename, v.size, v.sha256, v.created_at, u.name AS uploaded_by
       FROM document_versions v JOIN users u ON u.id = v.uploaded_by
      WHERE v.document_id = $1 ORDER BY v.version DESC`, [r.doc.id])).rows;
  res.json({
    document: view(r), owner,
    versions: versions.map((v) => ({ version: v.version, filename: v.filename, size: v.size, sha256: v.sha256, createdAt: v.created_at, uploadedBy: v.uploaded_by })),
  });
}));

router.patch('/:id', docRoute(async (req, res) => {
  const db = await getDb();
  await db.tx(async (tx) => {
    const r = await authorize(tx, req, 'edit', { action: 'doc.update', lock: 'update' });
    const body = req.body || {};
    const next = {
      name: body.name !== undefined ? requireText(body.name, 'name', 200) : r.doc.name,
      category: body.category !== undefined ? requireText(body.category, 'category', 60) : r.doc.category,
      description: body.description !== undefined ? requireText(body.description, 'description', 1000, { required: false }) : r.doc.description,
    };
    const changed = Object.keys(next).filter((k) => next[k] !== r.doc[k]);
    if (!changed.length) return;
    await tx.query('UPDATE documents SET name=$2, category=$3, description=$4, updated_at=now() WHERE id=$1',
      [r.doc.id, next.name, next.category, next.description]);
    await audit.append(tx, {
      actor: req.user, action: 'doc.update', docId: r.doc.id, ip: ipOf(req),
      detail: { changed, from: Object.fromEntries(changed.map((k) => [k, r.doc[k]])), to: Object.fromEntries(changed.map((k) => [k, next[k]])) },
    });
  });
  res.json({ ok: true });
}));

// ---------------------------------------------------------------- content
router.get('/:id/download', docRoute(async (req, res) => {
  const db = await getDb();
  const wanted = req.query.version === undefined ? null : Number(req.query.version);
  if (wanted !== null && (!Number.isInteger(wanted) || wanted < 1)) throw new HttpError(400, 'invalid_version', 'version must be a positive integer');

  // Authorise and audit in one transaction BEFORE any bytes are read or sent.
  const row = await db.tx(async (tx) => {
    const r = await authorize(tx, req, 'read', { action: 'doc.download', lock: 'share' });
    const v = (await tx.query(
      'SELECT * FROM document_versions WHERE document_id = $1 AND version = $2', [r.doc.id, wanted || r.doc.current_version])).rows[0];
    if (!v || !v.blob) throw new HttpError(404, 'version_not_found', 'Version not found');
    await audit.append(tx, {
      actor: req.user, action: 'doc.download', docId: r.doc.id, ip: ipOf(req),
      detail: { version: v.version, filename: v.filename, size: v.size, sha256: v.sha256, via: r.level },
    });
    return v;
  });

  let plain;
  try {
    plain = decryptFile(Buffer.from(row.blob), Buffer.from(row.wrapped_key), row.document_id, row.version);
    if (sha256hex(plain) !== row.sha256) throw new Error('sha256 mismatch');
  } catch (err) {
    await audit.record(db, { actor: req.user, action: 'doc.integrity_failure', outcome: 'denied', docId: row.document_id, ip: ipOf(req), detail: { version: row.version } });
    throw new HttpError(500, 'integrity_failure', 'The stored file failed its integrity check');
  }
  const safeName = row.filename.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
  res.setHeader('Content-Type', row.mime);
  res.setHeader('Content-Disposition', `attachment; filename="${safeName}"; filename*=UTF-8''${encodeURIComponent(row.filename)}`);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('Content-Security-Policy', "sandbox; default-src 'none'");
  res.setHeader('Content-Length', plain.length);
  res.end(plain);
}));

router.post('/:id/versions', docRoute(async (req, res) => {
  const db = await getDb();
  // Cheap check first so an unauthorised caller cannot make us buffer an upload...
  await authorize(db, req, 'edit', { action: 'doc.version' });
  await parseUpload(req, res);
  if (!req.file) throw new HttpError(400, 'no_file', 'Attach a file in the "file" field');
  // ...then the authoritative check, locked, inside the writing transaction.
  const version = await db.tx(async (tx) => {
    const r = await authorize(tx, req, 'edit', { action: 'doc.version', lock: 'update' });
    return addVersion(tx, { doc: r.doc, actor: req.user, file: req.file, ip: ipOf(req) });
  });
  res.status(201).json({ version });
}));

// ---------------------------------------------------------------- delete / restore (owner only)
router.delete('/:id', docRoute(async (req, res) => {
  const db = await getDb();
  await db.tx(async (tx) => {
    const r = await authorize(tx, req, 'owner', { action: 'doc.delete', lock: 'update' });
    await tx.query('UPDATE documents SET deleted_at = now(), deleted_by = $2 WHERE id = $1', [r.doc.id, req.user.id]);
    await audit.append(tx, { actor: req.user, action: 'doc.delete', docId: r.doc.id, ip: ipOf(req), detail: { name: r.doc.name, recoverableDays: config.trashRetentionDays } });
  });
  res.json({ ok: true });
}));

router.post('/:id/restore', docRoute(async (req, res) => {
  const db = await getDb();
  await db.tx(async (tx) => {
    const r = await authorize(tx, req, 'owner', { action: 'doc.restore', lock: 'update', allowDeleted: true });
    if (!r.doc.deleted_at) throw new HttpError(409, 'not_deleted', 'Document is not in the trash');
    await tx.query('UPDATE documents SET deleted_at = NULL, deleted_by = NULL, updated_at = now() WHERE id = $1', [r.doc.id]);
    await audit.append(tx, { actor: req.user, action: 'doc.restore', docId: r.doc.id, ip: ipOf(req), detail: {} });
  });
  res.json({ ok: true });
}));

// ---------------------------------------------------------------- grants (owner only)
router.get('/:id/grants', docRoute(async (req, res) => {
  const db = await getDb();
  const r = await authorize(db, req, 'owner', { action: 'grant.list' });
  const { rows } = await db.query(
    `SELECT g.user_id, g.permission, g.created_at, g.expires_at, u.name, u.email, u.role, u.active
       FROM grants g JOIN users u ON u.id = g.user_id
      WHERE g.document_id = $1 AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > now())
      ORDER BY u.name`, [r.doc.id]);
  res.json({ grants: rows.map((g) => ({
    userId: g.user_id, name: g.name, email: g.email, role: g.role, active: g.active,
    permission: g.role === 'viewer' && g.permission === 'edit' ? 'read' : g.permission,
    grantedAt: g.created_at, expiresAt: g.expires_at,
  })) });
}));

router.put('/:id/grants', docRoute(async (req, res) => {
  const db = await getDb();
  const out = await db.tx(async (tx) => {
    const r = await authorize(tx, req, 'owner', { action: 'grant.add', lock: 'update' });
    const { userId, permission, expiresAt, suggestionId } = req.body || {};
    if (!isUuid(userId)) throw new HttpError(400, 'invalid_user', 'userId is required');
    if (!['read', 'edit'].includes(permission)) throw new HttpError(400, 'invalid_permission', 'permission must be "read" or "edit"');
    if (userId === r.doc.owner_id) throw new HttpError(400, 'owner_has_access', 'The owner already has full access');
    const target = (await tx.query('SELECT id, name, email, role, active FROM users WHERE id = $1', [userId])).rows[0];
    if (!target || !target.active) throw new HttpError(404, 'user_not_found', 'No such active user');
    if (permission === 'edit' && target.role === 'viewer') {
      throw new HttpError(400, 'viewer_cannot_edit', 'Users with the viewer role can only be given read access');
    }
    let expires = null;
    if (expiresAt) {
      expires = new Date(expiresAt);
      const days = (expires.getTime() - Date.now()) / 86400000;
      if (Number.isNaN(expires.getTime()) || days <= 0 || days > 365) throw new HttpError(400, 'invalid_expiry', 'expiresAt must be in the future and within one year');
    }
    let via = null;
    if (suggestionId) {
      if (!isUuid(suggestionId)) throw new HttpError(400, 'invalid_suggestion', 'Unknown suggestion');
      const sug = (await tx.query('SELECT payload FROM ai_suggestions WHERE id=$1 AND document_id=$2 AND owner_id=$3', [suggestionId, r.doc.id, req.user.id])).rows[0];
      const item = sug && JSON.parse(sug.payload).find((x) => x.userId === userId);
      if (!item) throw new HttpError(400, 'invalid_suggestion', 'That suggestion does not include this user');
      via = { suggestionId, suggestedPermission: item.suggestedPermission, overridden: item.suggestedPermission !== permission };
    }
    const existing = (await tx.query('SELECT id, permission FROM grants WHERE document_id=$1 AND user_id=$2 AND revoked_at IS NULL', [r.doc.id, userId])).rows[0];
    if (existing) {
      await tx.query('UPDATE grants SET permission=$2, expires_at=$3, granted_by=$4 WHERE id=$1', [existing.id, permission, expires, req.user.id]);
    } else {
      await tx.query('INSERT INTO grants(id, document_id, user_id, permission, granted_by, expires_at) VALUES ($1,$2,$3,$4,$5,$6)',
        [randomUUID(), r.doc.id, userId, permission, req.user.id, expires]);
    }
    await audit.append(tx, {
      actor: req.user, action: existing ? 'grant.change' : 'grant.add', docId: r.doc.id, targetUserId: userId, ip: ipOf(req),
      detail: { permission, previous: existing ? existing.permission : null, expiresAt: expires ? expires.toISOString() : null, viaSuggestion: via, grantee: target.email },
    });
    if (via) {
      await audit.append(tx, {
        actor: req.user, action: 'ai.suggestion.accepted', docId: r.doc.id, targetUserId: userId, ip: ipOf(req),
        detail: { ...via, decidedBy: req.user.email, finalPermission: permission },
      });
    }
    return { userId, permission };
  });
  res.json(out);
}));

router.delete('/:id/grants/:userId', docRoute(async (req, res) => {
  const db = await getDb();
  if (!isUuid(req.params.userId)) throw new HttpError(400, 'invalid_user', 'Invalid user id');
  await db.tx(async (tx) => {
    const r = await authorize(tx, req, 'owner', { action: 'grant.revoke', lock: 'update' });
    const done = await tx.query(
      'UPDATE grants SET revoked_at = now(), revoked_by = $3 WHERE document_id = $1 AND user_id = $2 AND revoked_at IS NULL',
      [r.doc.id, req.params.userId, req.user.id]);
    if (!done.rowCount) throw new HttpError(404, 'no_active_grant', 'That user has no active grant on this document');
    await audit.append(tx, { actor: req.user, action: 'grant.revoke', docId: r.doc.id, targetUserId: req.params.userId, ip: ipOf(req), detail: {} });
  });
  res.json({ ok: true });
}));

// ---------------------------------------------------------------- access advisor (read-only suggestion)
router.post('/:id/suggest-access', docRoute(async (req, res) => {
  const db = await getDb();
  const out = await db.tx(async (tx) => {
    const r = await authorize(tx, req, 'owner', { action: 'ai.suggest', lock: 'share' });
    const suggestions = await suggest(tx, r.doc, req.user);
    const id = randomUUID();
    await tx.query('INSERT INTO ai_suggestions(id, document_id, owner_id, payload) VALUES ($1,$2,$3,$4)', [id, r.doc.id, req.user.id, JSON.stringify(suggestions)]);
    await audit.append(tx, {
      actor: req.user, action: 'ai.suggest', docId: r.doc.id, ip: ipOf(req),
      detail: { suggestionId: id, advisor: 'rule-based-v1', suggested: suggestions.map((s) => ({ userId: s.userId, permission: s.suggestedPermission })) },
    });
    return { suggestionId: id, advisor: 'rule-based-v1', note: 'Suggestions only. Nothing is shared until you confirm each one.', suggestions };
  });
  res.json(out);
}));

// ---------------------------------------------------------------- per-document activity (owner only)
router.get('/:id/activity', docRoute(async (req, res) => {
  const db = await getDb();
  const r = await authorize(db, req, 'owner', { action: 'doc.activity' });
  const { rows } = await db.query(
    'SELECT seq, ts, actor_email, action, outcome, target_user_id, detail FROM audit_log WHERE doc_id = $1 ORDER BY seq DESC LIMIT 200', [r.doc.id]);
  res.json({ activity: rows.map((a) => ({ seq: a.seq, ts: a.ts, actor: a.actor_email, action: a.action, outcome: a.outcome, targetUserId: a.target_user_id, detail: JSON.parse(a.detail) })) });
}));

module.exports = router;

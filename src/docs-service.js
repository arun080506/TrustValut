'use strict';
const { randomUUID } = require('crypto');
const audit = require('./audit');
const { HttpError } = require('./http');
const { encryptFile, sha256hex } = require('./crypto');
const { validateUpload, likeEscape, parseDate, clean } = require('./validate');
const { effectiveLevel } = require('./authz');

async function insertVersion(tx, { documentId, version, file, uploader }) {
  const checked = validateUpload(file.originalname, file.buffer);
  const { blob, wrappedKey } = encryptFile(file.buffer, documentId, version);
  const sha = sha256hex(file.buffer);
  await tx.query(
    `INSERT INTO document_versions(id, document_id, version, filename, mime, size, sha256, wrapped_key, blob, uploaded_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [randomUUID(), documentId, version, checked.filename, checked.mime, file.buffer.length, sha, wrappedKey, blob, uploader.id]
  );
  return { filename: checked.filename, mime: checked.mime, size: file.buffer.length, sha256: sha };
}

async function createDocument(tx, { owner, name, category, description, file, ip }) {
  const id = randomUUID();
  const title = name || file.originalname;
  await tx.query(
    'INSERT INTO documents(id, owner_id, name, category, description) VALUES ($1,$2,$3,$4,$5)',
    [id, owner.id, clean(title, 200) || 'Untitled', category || 'general', description || '']
  );
  const v = await insertVersion(tx, { documentId: id, version: 1, file, uploader: owner });
  await audit.append(tx, {
    actor: owner, action: 'doc.upload', docId: id, ip,
    detail: { version: 1, filename: v.filename, size: v.size, sha256: v.sha256, category: category || 'general' },
  });
  return id;
}

async function addVersion(tx, { doc, actor, file, ip }) {
  const version = doc.current_version + 1;
  const v = await insertVersion(tx, { documentId: doc.id, version, file, uploader: actor });
  await tx.query('UPDATE documents SET current_version = $2, updated_at = now() WHERE id = $1', [doc.id, version]);
  await audit.append(tx, {
    actor, action: 'doc.version', docId: doc.id, ip,
    detail: { version, filename: v.filename, size: v.size, sha256: v.sha256 },
  });
  return version;
}

/**
 * Listing/search. The access rule is part of the WHERE clause itself, so a document the caller
 * cannot reach is never selected, counted, or paginated - there is nothing to filter out later.
 */
async function searchDocuments(q, user, f) {
  const params = [user.id];
  const where = [];
  const add = (v) => { params.push(v); return '$' + params.length; };

  if (f.trash) {
    where.push('d.owner_id = $1 AND d.deleted_at IS NOT NULL AND d.purged_at IS NULL');
  } else {
    where.push('d.deleted_at IS NULL');
    if (f.scope === 'mine') where.push('d.owner_id = $1');
    else if (f.scope === 'shared') where.push('d.owner_id <> $1 AND g.id IS NOT NULL');
    else where.push('(d.owner_id = $1 OR g.id IS NOT NULL)');
  }
  if (f.q) where.push(`d.name ILIKE ${add('%' + likeEscape(f.q) + '%')}`);
  if (f.owner) {
    const p = add('%' + likeEscape(f.owner) + '%');
    where.push(`(u.name ILIKE ${p} OR u.email ILIKE ${p})`);
  }
  if (f.category) where.push(`lower(d.category) = ${add(f.category.toLowerCase())}`);
  const from = parseDate(f.from, 'from');
  const to = parseDate(f.to, 'to');
  if (from) where.push(`d.created_at >= ${add(from.toISOString())}::timestamptz`);
  if (to) where.push(`d.created_at < ${add(new Date(to.getTime() + 86400000).toISOString())}::timestamptz`);

  const limit = Math.min(Math.max(parseInt(f.limit, 10) || 50, 1), 100);
  const offset = Math.max(parseInt(f.offset, 10) || 0, 0);

  const { rows } = await q.query(
    `SELECT d.id, d.name, d.category, d.description, d.current_version, d.created_at, d.updated_at, d.deleted_at,
            d.owner_id, u.name AS owner_name, u.email AS owner_email, g.permission AS grant_permission
       FROM documents d
       JOIN users u ON u.id = d.owner_id
       LEFT JOIN grants g
              ON g.document_id = d.id AND g.user_id = $1 AND g.revoked_at IS NULL
             AND (g.expires_at IS NULL OR g.expires_at > now())
      WHERE ${where.join(' AND ')}
      ORDER BY d.updated_at DESC
      LIMIT ${limit} OFFSET ${offset}`,
    params
  );
  return rows.map((r) => ({
    id: r.id, name: r.name, category: r.category, description: r.description,
    version: r.current_version, createdAt: r.created_at, updatedAt: r.updated_at, deletedAt: r.deleted_at,
    owner: { id: r.owner_id, name: r.owner_name, email: r.owner_email },
    access: effectiveLevel(user, { owner_id: r.owner_id }, r.grant_permission),
  }));
}

module.exports = { createDocument, addVersion, searchDocuments };

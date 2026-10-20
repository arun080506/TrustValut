'use strict';
/**
 * THE authorisation decision for documents. Every route that touches a document (metadata,
 * content, edits, deletion, grants, activity) calls resolveAccess() through authorize() in
 * routes/documents.js. List and search enforce the same rule in SQL (see docs-service.js).
 *
 * Model:
 *   owner  - the user in documents.owner_id. Implicit; cannot be granted. Full control.
 *   edit   - read + change metadata + upload new versions.      (grant)
 *   read   - view metadata + download any version.              (grant)
 *   none   - the document does not exist as far as they can tell (404, same body as "missing").
 *
 * Role ceiling: a user whose role is "viewer" never exceeds "read", even if an edit grant row
 * exists (for instance because the role was lowered after the grant was made).
 * Admins get NO implicit access to content. They manage users, see metadata and the audit
 * trail, and can emergency-revoke grants, but reading a file requires a grant like anyone else.
 *
 * Nothing is cached: the decision is recomputed from the database on every request, inside the
 * same transaction as the action, with the document row locked. A revocation that has committed
 * is therefore visible to the very next request, and cannot interleave with an in-flight action.
 */
const { isUuid } = require('./http');

const RANK = { read: 1, edit: 2, owner: 3 };

const can = (level, need) => Boolean(level) && RANK[level] >= RANK[need];

function effectiveLevel(user, doc, grantPermission) {
  let level = null;
  if (doc.owner_id === user.id) level = 'owner';
  else if (grantPermission) level = grantPermission;
  if (level === 'edit' && user.role === 'viewer') level = 'read';
  return level;
}

/**
 * @param q    a query runner (db or transaction)
 * @param opts.lock 'share' | 'update' | undefined  - row lock on the document for this transaction
 * @returns {doc, level} or null when the user has no access at all (or the id is malformed)
 */
async function resolveAccess(q, user, docId, opts = {}) {
  if (!isUuid(docId)) return null;
  if (opts.lock) {
    // Take the lock in its OWN statement, then decide in a NEW statement.
    // Under READ COMMITTED a statement that waits for a row lock only re-checks the locked row;
    // joined rows (the grant) keep the snapshot the statement started with. Doing lock + decision
    // in one statement therefore let a download that queued behind a revoke still see the grant as
    // live, and be served after the revoke had committed. A fresh statement sees committed state.
    const mode = opts.lock === 'update' ? 'FOR UPDATE' : 'FOR SHARE';
    const locked = await q.query(`SELECT 1 FROM documents WHERE id = $1 ${mode}`, [docId]);
    if (!locked.rows.length) return null;
  }
  const { rows } = await q.query(
    `SELECT d.id, d.owner_id, d.name, d.category, d.description, d.current_version,
            d.created_at, d.updated_at, d.deleted_at, d.purged_at,
            g.permission AS grant_permission
       FROM documents d
       LEFT JOIN grants g
              ON g.document_id = d.id
             AND g.user_id = $2
             AND g.revoked_at IS NULL
             AND (g.expires_at IS NULL OR g.expires_at > now())
      WHERE d.id = $1`,
    [docId, user.id]
  );
  if (!rows.length) return null;
  const doc = rows[0];
  const level = effectiveLevel(user, doc, doc.grant_permission);
  if (!level) return null;
  // Deleted documents: only the owner can still see them (to restore). Purged ones are gone.
  if (doc.purged_at) return null;
  if (doc.deleted_at && level !== 'owner') return null;
  return { doc, level };
}

module.exports = { resolveAccess, can, effectiveLevel, RANK };

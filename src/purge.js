'use strict';
const audit = require('./audit');
const config = require('./config');

/**
 * Retention: documents in the trash longer than TRASH_RETENTION_DAYS have their encrypted
 * bytes destroyed. The metadata, grant history and audit trail remain (so "who had access"
 * can still be answered), but the content is gone and the document is permanently unreachable.
 */
async function purgeExpired(db) {
  const { rows } = await db.query(
    `SELECT id FROM documents
      WHERE deleted_at IS NOT NULL AND purged_at IS NULL
        AND deleted_at < now() - ($1 || ' days')::interval`, [String(config.trashRetentionDays)]);
  for (const d of rows) {
    await db.tx(async (tx) => {
      await tx.query('UPDATE document_versions SET blob = NULL, wrapped_key = NULL WHERE document_id = $1', [d.id]);
      await tx.query('UPDATE documents SET purged_at = now() WHERE id = $1', [d.id]);
      await audit.append(tx, { actorEmail: 'system:retention', action: 'doc.purge', docId: d.id, detail: { retentionDays: config.trashRetentionDays } });
    });
  }
  return rows.length;
}

module.exports = { purgeExpired };

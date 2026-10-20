'use strict';
/**
 * Tamper-evident audit trail.
 *
 *  - Append-only: DB triggers reject UPDATE / DELETE / TRUNCATE on audit_log.
 *  - Hash-chained: each row's hash = HMAC(AUDIT_HMAC_KEY, previous_hash | canonical(row)).
 *    The key lives in the application environment, not in the database, so someone with
 *    database write access can delete or edit rows but cannot forge a valid chain.
 *  - Anchored: every append also logs "AUDIT_ANCHOR seq hash" to stdout, which platform log
 *    drains retain outside the database. That is what catches truncation of the tail.
 *  - Serialised: appends lock the single audit_head row, so seq is gap-free and ordered.
 *
 * append(tx, ...) is called inside the same transaction as the action it records, so an
 * action cannot commit without its audit row (and vice versa).
 */
const crypto = require('crypto');
const config = require('./config');

const GENESIS = '0'.repeat(64);

/** Deterministic JSON (sorted keys) so the stored text and the hashed text are identical. */
function stable(v) {
  if (v === undefined || v === null) return 'null';
  if (typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}';
}

function chainHash(prev, fields) {
  return crypto.createHmac('sha256', config.auditKey).update(prev + '|' + stable(fields)).digest('hex');
}

const fieldsOf = (r) => [r.seq, r.ts, r.actor_id, r.actor_email, r.action, r.outcome, r.doc_id, r.target_user_id, r.ip, r.detail];

async function append(tx, e) {
  const head = (await tx.query('SELECT seq, hash FROM audit_head WHERE id = 1 FOR UPDATE')).rows[0];
  const row = {
    seq: head.seq + 1,
    ts: new Date().toISOString(),
    actor_id: e.actor ? e.actor.id : null,
    actor_email: e.actor ? e.actor.email : (e.actorEmail || null),
    action: e.action,
    outcome: e.outcome || 'allowed',
    doc_id: e.docId || null,
    target_user_id: e.targetUserId || null,
    ip: e.ip || null,
    detail: stable(e.detail || {}),
  };
  const hash = chainHash(head.hash, fieldsOf(row));
  await tx.query(
    `INSERT INTO audit_log(seq, ts, actor_id, actor_email, action, outcome, doc_id, target_user_id, ip, detail, prev_hash, hash)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [row.seq, row.ts, row.actor_id, row.actor_email, row.action, row.outcome, row.doc_id,
      row.target_user_id, row.ip, row.detail, head.hash, hash]
  );
  await tx.query('UPDATE audit_head SET seq = $1, hash = $2 WHERE id = 1', [row.seq, hash]);
  console.log(`AUDIT_ANCHOR ${row.seq} ${hash}`);
  return row.seq;
}

/** Standalone append for events that have no surrounding transaction (e.g. refusals). */
async function record(db, e) {
  try {
    await db.tx((tx) => append(tx, e));
  } catch (err) {
    console.error('[audit] FAILED to record event', e.action, err.message);
  }
}

/** Recompute the whole chain. Detects edits, deletions, reordering and (via audit_head) tail removal. */
async function verify(db) {
  let prev = GENESIS;
  let expected = 1;
  let count = 0;
  let cursor = 0;
  for (;;) {
    const { rows } = await db.query('SELECT * FROM audit_log WHERE seq > $1 ORDER BY seq ASC LIMIT 1000', [cursor]);
    if (!rows.length) break;
    for (const r of rows) {
      if (r.seq !== expected) return { ok: false, count, brokenAt: expected, reason: 'sequence gap: an entry is missing' };
      if (r.prev_hash !== prev) return { ok: false, count, brokenAt: r.seq, reason: 'prev_hash does not match the previous entry' };
      const want = chainHash(prev, fieldsOf(r));
      const a = Buffer.from(want);
      const b = Buffer.from(String(r.hash));
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return { ok: false, count, brokenAt: r.seq, reason: 'entry content does not match its HMAC (edited, or forged without the key)' };
      }
      prev = r.hash;
      expected++;
      count++;
      cursor = r.seq;
    }
  }
  const head = (await db.query('SELECT seq, hash FROM audit_head WHERE id = 1')).rows[0];
  if (head.seq !== count || head.hash !== prev) {
    return { ok: false, count, brokenAt: count + 1, reason: 'audit_head disagrees with the log (rows removed from the end, or appended outside the app)' };
  }
  return { ok: true, count, headSeq: head.seq, headHash: head.hash };
}

module.exports = { append, record, verify, stable, GENESIS };

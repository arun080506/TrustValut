'use strict';
/**
 * Access advisor ("AI" in the brief). Deliberately rule-based and local: no document content or
 * names leave the system, and it is deterministic and explainable.
 *
 * Hard rules, enforced by structure rather than by trust:
 *  1. suggest() only READS. It has no code path that writes a grant.
 *  2. It only draws on grants the owner has personally made on the owner's other documents.
 *  3. It always proposes the least privilege ("read"), never "edit".
 *  4. A human confirms through the normal grant endpoint; both the suggestion and the decision
 *     are written to the audit trail (ai.suggest, grant.add with viaSuggestion, ai.suggestion.accepted).
 */
async function suggest(q, doc, owner) {
  const { rows } = await q.query(
    `SELECT g.user_id, u.name, u.email, u.role, lower(d2.category) AS category, count(*)::int AS n
       FROM grants g
       JOIN documents d2 ON d2.id = g.document_id
       JOIN users u ON u.id = g.user_id
      WHERE d2.owner_id = $1 AND d2.id <> $2 AND d2.deleted_at IS NULL
        AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > now())
        AND u.active = true AND g.user_id <> $1
        AND NOT EXISTS (
          SELECT 1 FROM grants gx
           WHERE gx.document_id = $2 AND gx.user_id = g.user_id AND gx.revoked_at IS NULL)
      GROUP BY g.user_id, u.name, u.email, u.role, lower(d2.category)`,
    [owner.id, doc.id]
  );
  const byUser = new Map();
  for (const r of rows) {
    const s = byUser.get(r.user_id) || { userId: r.user_id, name: r.name, email: r.email, role: r.role, score: 0, sameCategory: 0, total: 0 };
    s.total += r.n;
    s.score += r.n;
    if (r.category === String(doc.category).toLowerCase()) { s.sameCategory += r.n; s.score += r.n * 3; }
    byUser.set(r.user_id, s);
  }
  return [...byUser.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, 5)
    .map((s) => ({
      userId: s.userId, name: s.name, email: s.email, role: s.role,
      suggestedPermission: 'read',
      score: s.score,
      reasons: [
        s.sameCategory ? `You already shared ${s.sameCategory} other "${doc.category}" document(s) with them` : null,
        `They currently have access to ${s.total} of your other documents`,
      ].filter(Boolean),
    }));
}

module.exports = { suggest };

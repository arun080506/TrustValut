'use strict';
const express = require('express');
const { getDb } = require('../db');
const { asyncHandler } = require('../http');
const { requireAuth, requireRole } = require('../auth');
const { likeEscape, clean } = require('../validate');

const router = express.Router();
router.use(requireAuth);

// People-picker for owners/admins. Deliberately narrow: >= 3 characters, active users only,
// 10 results, never returns password material, and viewers cannot call it at all.
router.get('/directory', requireRole('owner', 'admin'), asyncHandler(async (req, res) => {
  const q = clean(req.query.q, 60);
  if (q.length < 3) return res.json({ users: [] });
  const db = await getDb();
  const p = '%' + likeEscape(q) + '%';
  const { rows } = await db.query(
    'SELECT id, name, email, role FROM users WHERE active = true AND id <> $1 AND (email ILIKE $2 OR name ILIKE $2) ORDER BY name LIMIT 10',
    [req.user.id, p]);
  return res.json({ users: rows });
}));

module.exports = router;

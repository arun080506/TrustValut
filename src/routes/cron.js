'use strict';
const express = require('express');
const config = require('../config');
const { getDb } = require('../db');
const { HttpError, asyncHandler } = require('../http');
const { safeEqual } = require('../crypto');
const { purgeExpired } = require('../purge');

const router = express.Router();

// Vercel Cron sends "Authorization: Bearer $CRON_SECRET". No secret configured = endpoint disabled.
router.get('/purge', asyncHandler(async (req, res) => {
  const header = String(req.headers.authorization || '');
  if (!config.cronSecret || !safeEqual(header, `Bearer ${config.cronSecret}`)) {
    throw new HttpError(404, 'not_found', 'Not found');
  }
  const db = await getDb();
  res.json({ purged: await purgeExpired(db) });
}));

module.exports = router;

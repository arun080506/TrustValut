'use strict';
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const config = require('./config');
const { getDb } = require('./db');
const { asyncHandler, errorHandler } = require('./http');
const { attachSession, originCheck } = require('./auth');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // Render and Vercel each put exactly one proxy in front

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      'default-src': ["'self'"],
      'script-src': ["'self'"],
      'style-src': ["'self'"],
      'img-src': ["'self'", 'data:'],
      'object-src': ["'none'"],
      'base-uri': ["'none'"],
      'form-action': ["'self'"],
      'frame-ancestors': ["'none'"],
    },
  },
  hsts: config.isProd ? { maxAge: 31536000, includeSubDomains: true } : false,
  crossOriginResourcePolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'no-referrer' },
}));

// Everything under /api is uncacheable, authenticated per request, and same-origin only (no CORS headers).
app.use('/api', (req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
app.use('/api', express.json({ limit: '20kb' }));
app.use('/api', originCheck);
app.use('/api', asyncHandler(async (req, res, next) => { await getDb(); next(); }));
app.use('/api', attachSession);

app.get('/api/health', asyncHandler(async (req, res) => {
  const db = await getDb();
  await db.query('SELECT 1');
  res.json({ ok: true });
}));

app.use('/api/auth', require('./routes/auth'));
app.use('/api/users', require('./routes/users'));
app.use('/api/documents', require('./routes/documents'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api/cron', require('./routes/cron'));
app.use('/api', (req, res) => res.status(404).json({ error: 'not_found', message: 'No such endpoint' }));

app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html', maxAge: 0, dotfiles: 'ignore' }));
app.use(errorHandler);

module.exports = { app };

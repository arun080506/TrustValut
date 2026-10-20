'use strict';

class HttpError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

/** Thrown by authorize(); the route wrapper records the refusal in the audit trail. */
class Denied extends Error {
  constructor(status, info) {
    super('denied');
    this.status = status;
    this.info = info;
  }
}

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const isUuid = (v) => typeof v === 'string' && UUID_RE.test(v);

const ipOf = (req) => String(req.ip || (req.socket && req.socket.remoteAddress) || 'unknown').slice(0, 64);

function errorHandler(err, req, res, next) {
  if (res.headersSent) return next(err);
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.code, message: err.message });
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'too_large', message: 'Request body too large' });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'bad_json', message: 'Malformed JSON' });
  console.error('[error]', req.method, req.originalUrl, err);
  return res.status(500).json({ error: 'internal_error', message: 'Something went wrong' });
}

module.exports = { HttpError, Denied, asyncHandler, isUuid, ipOf, errorHandler };

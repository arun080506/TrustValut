'use strict';
const { HttpError } = require('./http');

/**
 * Upload validation is an allow-list on THREE things that must all agree:
 * the file extension, the file's magic bytes, and a server-chosen MIME type.
 * The client-supplied Content-Type is never trusted or stored.
 */
const TYPES = {
  pdf:  { mime: 'application/pdf', check: (b) => b.subarray(0, 5).toString('latin1') === '%PDF-' },
  png:  { mime: 'image/png', check: (b) => b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) },
  jpg:  { mime: 'image/jpeg', check: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  jpeg: { mime: 'image/jpeg', check: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  txt:  { mime: 'text/plain; charset=utf-8', check: isUtf8Text },
  csv:  { mime: 'text/csv; charset=utf-8', check: isUtf8Text },
  md:   { mime: 'text/plain; charset=utf-8', check: isUtf8Text },
  docx: { mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', check: (b) => ooxml(b, 'word/') },
  xlsx: { mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', check: (b) => ooxml(b, 'xl/') },
  pptx: { mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', check: (b) => ooxml(b, 'ppt/') },
};

function isUtf8Text(buf) {
  if (buf.includes(0)) return false;
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(buf);
    return true;
  } catch (_) {
    return false;
  }
}

/** OOXML is a zip: require the zip magic, the expected part folder, and no macro project. */
function ooxml(buf, folder) {
  if (!(buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04)) return false;
  const text = buf.toString('latin1');
  if (!text.includes('[Content_Types].xml')) return false;
  if (!text.includes(folder)) return false;
  if (text.includes('vbaProject.bin')) return false; // macro-enabled content is refused
  return true;
}

/** Multer decodes multipart filenames as latin1; recover UTF-8 names when that is what was sent. */
function fixEncoding(name) {
  try {
    const recovered = Buffer.from(name, 'latin1').toString('utf8');
    return recovered.includes('�') ? name : recovered;
  } catch (_) {
    return name;
  }
}

function sanitizeFilename(original) {
  let n = fixEncoding(String(original || ''));
  n = n.split(/[\\/]/).pop();                              // strip any path
  n = n.replace(/[\u0000-\u001f\u007f<>:"|?*]/g, '');      // control + reserved characters
  n = n.replace(/\s+/g, ' ').trim().replace(/^\.+/, '');   // no leading dots
  return n.slice(0, 120);
}

/** Returns {filename, ext, mime} or throws HttpError 400/415. */
function validateUpload(originalName, buffer) {
  if (!buffer || !buffer.length) throw new HttpError(400, 'empty_file', 'The file is empty');
  const filename = sanitizeFilename(originalName);
  if (!filename) throw new HttpError(400, 'bad_filename', 'The file name is not valid');
  const dot = filename.lastIndexOf('.');
  const ext = dot > 0 ? filename.slice(dot + 1).toLowerCase() : '';
  const type = TYPES[ext];
  if (!type) {
    throw new HttpError(415, 'type_not_allowed', `File type ".${ext || '?'}" is not allowed. Allowed: ${Object.keys(TYPES).join(', ')}`);
  }
  if (!type.check(buffer)) {
    throw new HttpError(415, 'content_mismatch', 'The file content does not match its extension');
  }
  return { filename, ext, mime: type.mime };
}

const clean = (s, max) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);

function requireText(value, field, max, { required = true } = {}) {
  const v = clean(value, max);
  if (required && !v) throw new HttpError(400, 'invalid_' + field, `${field} is required`);
  return v;
}

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;
const normalizeEmail = (e) => String(e || '').trim().toLowerCase();
const isEmail = (e) => typeof e === 'string' && e.length <= 254 && EMAIL_RE.test(e);

function checkPassword(pw) {
  if (typeof pw !== 'string' || pw.length < 12 || pw.length > 128) {
    throw new HttpError(400, 'weak_password', 'Password must be 12 to 128 characters');
  }
}

const likeEscape = (s) => String(s).replace(/[\\%_]/g, '\\$&');

function parseDate(value, field) {
  if (value === undefined || value === null || value === '') return null;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value))) throw new HttpError(400, 'invalid_' + field, `${field} must be YYYY-MM-DD`);
  const d = new Date(value + 'T00:00:00Z');
  if (Number.isNaN(d.getTime())) throw new HttpError(400, 'invalid_' + field, `${field} is not a valid date`);
  return d;
}

module.exports = {
  TYPES, validateUpload, sanitizeFilename, clean, requireText,
  normalizeEmail, isEmail, checkPassword, likeEscape, parseDate,
};

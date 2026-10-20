'use strict';
const crypto = require('crypto');
const { promisify } = require('util');
const config = require('./config');

const scrypt = promisify(crypto.scrypt);
const ALG = 'aes-256-gcm';

const sha256hex = (v) => crypto.createHash('sha256').update(v).digest('hex');
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}

// ---------- passwords (scrypt, per-user salt, parameters stored with the hash) ----------
async function hashPassword(password, params = config.scrypt) {
  const salt = crypto.randomBytes(16);
  const { N, r, p } = params;
  const hash = await scrypt(password, salt, 32, { N, r, p, maxmem: 128 * N * r * 2 });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [N, r, p] = [Number(parts[1]), Number(parts[2]), Number(parts[3])];
  const salt = Buffer.from(parts[4], 'base64');
  const expected = Buffer.from(parts[5], 'base64');
  const actual = await scrypt(password, salt, expected.length, { N, r, p, maxmem: 128 * N * r * 2 });
  return crypto.timingSafeEqual(actual, expected);
}

let dummyHash = null;
/** Burn the same CPU as a real check so unknown accounts are not distinguishable by timing. */
async function dummyVerify(password) {
  if (!dummyHash) dummyHash = await hashPassword('trustvault-dummy-password');
  await verifyPassword(password, dummyHash);
  return false;
}

// ---------- file encryption: per-version random DEK, wrapped by the master key ----------
const aadFor = (documentId, version) => Buffer.from(`trustvault:v1:${documentId}:${version}`);

function seal(key, plaintext, aad) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv(ALG, key, iv);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]);
}

function open(key, sealed, aad) {
  const buf = Buffer.from(sealed);
  const d = crypto.createDecipheriv(ALG, key, buf.subarray(0, 12));
  d.setAAD(aad);
  d.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([d.update(buf.subarray(28)), d.final()]);
}

function encryptFile(plaintext, documentId, version) {
  const aad = aadFor(documentId, version);
  const dek = crypto.randomBytes(32);
  return { blob: seal(dek, plaintext, aad), wrappedKey: seal(config.masterKey, dek, aad) };
}

function decryptFile(blob, wrappedKey, documentId, version) {
  const aad = aadFor(documentId, version);
  const dek = open(config.masterKey, wrappedKey, aad);
  return open(dek, blob, aad);
}

module.exports = {
  sha256hex, randomToken, safeEqual,
  hashPassword, verifyPassword, dummyVerify,
  encryptFile, decryptFile,
};

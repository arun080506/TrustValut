'use strict';
/**
 * Demo data. Only runs when SEED_DEMO=true (or `npm run seed`), and only on an empty database.
 * These passwords are PUBLIC (they are in the README so reviewers can sign in). Never set
 * SEED_DEMO=true on a system holding real documents.
 */
const audit = require('./audit');
const { randomUUID } = require('crypto');
const { createUser, revokeAllSessions } = require('./users');
const { hashPassword, verifyPassword } = require('./crypto');
const { createDocument } = require('./docs-service');

const DEMO = {
  admin:    { email: 'arun.admin@trustvault.demo',    name: 'Arun',     role: 'admin',  password: 'Arun-Demo-2026!' },
  sree:     { email: 'sree.owner@trustvault.demo',    name: 'Sree',     role: 'owner',  password: 'Sree-Demo-2026!' },
  yaswanth: { email: 'yaswanth.owner@trustvault.demo', name: 'Yaswanth', role: 'owner',  password: 'Yaswanth-Demo-2026!' },
  pavan:    { email: 'pavan.viewer@trustvault.demo',   name: 'Pavan',    role: 'viewer', password: 'Pavan-Demo-2026!' },
  sasank:   { email: 'sasank.viewer@trustvault.demo',  name: 'Sasank',   role: 'viewer', password: 'Sasank-Demo-2026!' },
};
const PREVIOUS_DEMO_EMAILS = {
  'admin@trustvault.demo': 'admin',
  'alice.owner@trustvault.demo': 'sree',
  'sai.owner@trustvault.demo': 'sree',
  'bob.owner@trustvault.demo': 'yaswanth',
  'carol.viewer@trustvault.demo': 'pavan',
  'dave.viewer@trustvault.demo': 'sasank',
};

const text = (title, body) => Buffer.from(`${title}\n${'='.repeat(title.length)}\n\n${body}\n\n[TrustVault demo document]\n`);
const file = (name, buffer) => ({ originalname: name, buffer });

async function seedDemo(db) {
  await db.tx(async (tx) => {
    for (const [previousEmail, key] of Object.entries(PREVIOUS_DEMO_EMAILS)) {
      const next = DEMO[key];
      const current = (await tx.query(
        'SELECT id, email, name, role, password_hash, failed_logins, locked_until FROM users WHERE email = $1 OR email = $2 FOR UPDATE',
        [previousEmail, next.email])).rows.find((u) => u.email === previousEmail)
        || (await tx.query('SELECT id, email, name, role, password_hash, failed_logins, locked_until FROM users WHERE email = $1 FOR UPDATE', [next.email])).rows[0];
      if (!current) continue;

      if (current.role !== next.role) {
        throw new Error(`Cannot migrate demo account ${previousEmail}: unexpected role`);
      }
      const collision = (await tx.query('SELECT id FROM users WHERE email = $1', [next.email])).rows[0];
      if (collision && collision.id !== current.id) {
        throw new Error(`Cannot migrate demo account ${previousEmail}: ${next.email} is already in use`);
      }

      const passwordMatches = await verifyPassword(next.password, current.password_hash);
      if (current.email === next.email && current.name === next.name && passwordMatches
          && current.failed_logins === 0 && current.locked_until == null) continue;

      const passwordHash = await hashPassword(next.password);
      await tx.query(
        'UPDATE users SET email = $2, name = $3, password_hash = $4, failed_logins = 0, locked_until = NULL WHERE id = $1',
        [current.id, next.email, next.name, passwordHash]);
      const sessionsRevoked = await revokeAllSessions(tx, current.id);
      await audit.append(tx, {
        actorEmail: 'system:seed',
        action: 'admin.user_credentials_update',
        targetUserId: current.id,
        ip: 'seed',
        detail: {
          from: { email: current.email, name: current.name },
          to: { email: next.email, name: next.name },
          sessionsRevoked,
        },
      });
    }
  });

  const { rows } = await db.query('SELECT count(*)::int AS n FROM users');
  if (rows[0].n > 0) return false;

  const users = {};
  await db.tx(async (tx) => {
    for (const [key, u] of Object.entries(DEMO)) {
      users[key] = await createUser(tx, u);
      await audit.append(tx, { actorEmail: 'system:seed', action: 'admin.user_create', targetUserId: users[key].id, ip: 'seed', detail: { email: u.email, role: u.role } });
    }
  });

  const make = (owner, name, category, description, filename, content) =>
    db.tx((tx) => createDocument(tx, { owner, name, category, description, file: file(filename, content), ip: 'seed' }));

  const salary = await make(users.sree, 'Salary letter - P. Raman', 'hr', 'Confidential. Sree only.', 'salary-letter.txt', text('Salary letter', 'Base salary revision effective 1 Nov. Visible to the owner only.'));
  const acme   = await make(users.sree, 'Acme customer contract', 'contracts', 'Master services agreement (draft 3)', 'acme-msa.txt', text('Acme MSA', 'Term: 24 months. Shared read-only with Pavan.'));
  const audit1 = await make(users.sree, 'FY26 audit workpapers', 'audit', 'Regulator audit papers', 'audit-fy26.csv', Buffer.from('account,balance\n1000,25000\n2000,-4300\n'));
  const draw   = await make(users.yaswanth, 'Partner drawings rev B', 'drawings', 'External partner drawing set', 'drawings-revb.txt', text('Drawings Rev B', 'Sheet list: A-101 to A-140. Shared read-only with Sasank.'));
  await make(users.yaswanth, 'Regulator submission', 'compliance', 'Yaswanth only.', 'submission.txt', text('Regulator submission', 'Draft. Visible to the owner only.'));

  const grant = (docId, user, permission, by) => db.tx(async (tx) => {
    await tx.query('INSERT INTO grants(id, document_id, user_id, permission, granted_by) VALUES ($1,$2,$3,$4,$5)', [randomUUID(), docId, user.id, permission, by.id]);
    await audit.append(tx, { actor: by, action: 'grant.add', docId, targetUserId: user.id, ip: 'seed', detail: { permission, previous: null, expiresAt: null, viaSuggestion: null, grantee: user.email } });
  });
  await grant(acme, users.pavan, 'read', users.sree);
  await grant(audit1, users.yaswanth, 'edit', users.sree);
  await grant(draw, users.sasank, 'read', users.yaswanth);
  void salary;
  return true;
}

module.exports = { seedDemo, DEMO };

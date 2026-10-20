'use strict';
// Drives the real UI in headless Chromium against a throw-away demo server and fails on any
// console error / CSP violation. Usage: node scripts/ui-smoke.js   (needs playwright + chromium)
process.env.NODE_ENV = 'test'; process.env.SCRYPT_N = '4096'; process.env.SEED_DEMO = 'true';
const { app } = require('../src/app');
const { getDb } = require('../src/db');
let chromium;
try { ({ chromium } = require('playwright')); } catch (_) { ({ chromium } = require('/opt/npm-tools/node_modules/playwright')); }

(async () => {
  await getDb();
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || undefined, args: ['--no-sandbox'] });
  const problems = [];
  async function session(email, password, fn) {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    page.on('console', (m) => { if (['error', 'warning'].includes(m.type())) problems.push(`${email}: ${m.type()}: ${m.text()}`); });
    page.on('pageerror', (e) => problems.push(`${email}: pageerror: ${e.message}`));
    await page.goto(base);
    await page.fill('input[type=email]', email);
    await page.fill('input[type=password]', password);
    await page.click('button[type=submit]');
    await fn(page);
    await ctx.close();
  }
  const text = (p) => p.locator('main').innerText();

  await session('sree.owner@trustvault.demo', 'Sree-Demo-2026!', async (p) => {
    await p.waitForSelector('table');
    let t = await text(p); if (!/Acme customer contract/.test(t) || /Partner drawings/.test(t)) throw new Error('alice list wrong:\n' + t);
    await p.click('text=Acme customer contract');
    await p.waitForSelector('text=Who has access');
    await p.waitForSelector('text=Activity on this document');
    await p.click('text=Suggest who should have access');
    await p.waitForSelector('text=Nothing is shared until you confirm');
    await p.click('text=Upload'); await p.waitForSelector('input[type=file]');
    console.log('alice OK');
  });
  await session('pavan.viewer@trustvault.demo', 'Pavan-Demo-2026!', async (p) => {
    await p.waitForSelector('table');
    const t = await text(p); if (!/Acme customer contract/.test(t) || /Salary letter/.test(t)) throw new Error('carol list wrong:\n' + t);
    if (await p.locator('nav >> text=Upload').count()) throw new Error('viewer sees Upload');
    console.log('carol OK');
  });
  await session('arun.admin@trustvault.demo', 'Arun-Demo-2026!', async (p) => {
    await p.waitForSelector('text=Audit trail verified');
    await p.click('nav >> text=Audit trail'); await p.waitForSelector('table');
    await p.click('nav >> text=Users'); await p.waitForSelector('text=Create user');
    await p.click('nav >> text=Documents'); await p.waitForSelector('table');
    console.log('admin OK');
  });
  await browser.close(); server.close();
  if (problems.length) { console.error('CONSOLE PROBLEMS:\n' + problems.join('\n')); process.exit(1); }
  console.log('UI smoke test passed with zero console errors / CSP violations.');
  process.exit(0);
})().catch((e) => { console.error('UI SMOKE FAILED:', e.message); process.exit(1); });

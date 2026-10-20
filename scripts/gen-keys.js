'use strict';
// Prints fresh secrets to paste into your host's environment settings. Usage: npm run keys
const { randomBytes } = require('crypto');
console.log('# Keep these secret and BACK THEM UP. Losing FILE_MASTER_KEY makes every stored file unreadable.');
console.log('FILE_MASTER_KEY=' + randomBytes(32).toString('hex'));
console.log('AUDIT_HMAC_KEY=' + randomBytes(32).toString('hex'));
console.log('CRON_SECRET=' + randomBytes(24).toString('hex'));

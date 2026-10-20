'use strict';
const http = require('http');
const { app } = require('./app');
const { getDb } = require('./db');

const port = Number(process.env.PORT) || 3000;

function trustVaultIsRunning(port) {
  return new Promise((resolve) => {
    const request = http.get({ hostname: '127.0.0.1', port, path: '/api/health', timeout: 2000 }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => resolve(response.statusCode === 200 && body === '{"ok":true}'));
    });
    request.on('timeout', () => request.destroy());
    request.on('error', () => resolve(false));
  });
}

getDb()
  .then(() => {
    const server = app.listen(port, '0.0.0.0', () => console.log(`TrustVault is running at http://localhost:${port}`));
    server.on('error', async (err) => {
      if (err.code === 'EADDRINUSE') {
        if (await trustVaultIsRunning(port)) {
          console.log(`TrustVault is already running at http://localhost:${port}`);
          process.exit(0);
        }
        console.error(`Port ${port} is already in use by another app. Stop that app or set PORT to a different port.`);
      } else {
        console.error('Server failed to start:', err.message);
      }
      process.exit(1);
    });
  })
  .catch((err) => {
    console.error('Startup failed:', err.message);
    process.exit(1);
  });

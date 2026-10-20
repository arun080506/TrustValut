'use strict';
// Vercel entry point: the same Express app, exported as a serverless handler.
// vercel.json rewrites /api/* here; the app routes on the original URL.
module.exports = require('../src/app').app;

'use strict';

const fs = require('fs');
const path = require('path');

process.env.PGLITE_DIR = '.data/pglite';
process.env.SEED_DEMO = 'true';

fs.mkdirSync(path.dirname(process.env.PGLITE_DIR), { recursive: true });

require('../src/server');

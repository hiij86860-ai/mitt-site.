// Generate GitHub App JWT (Node.js)
const fs = require('fs');
const jwt = require('jsonwebtoken');

const APP_ID = process.env.GITHUB_APP_ID; // t.ex. från App settings
const PRIVATE_KEY_PATH = process.env.GITHUB_PRIVATE_KEY || './app.pem';

const privateKey = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');

const now = Math.floor(Date.now() / 1000);
const payload = {
  iat: now - 60,
  exp: now + (10 * 60), // max 10 minutes
  iss: APP_ID
};

const token = jwt.sign(payload, privateKey, { algorithm: 'RS256' });
console.log(token);
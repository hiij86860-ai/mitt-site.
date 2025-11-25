// Enkel Express webhook verifiering (Node.js)
const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '1mb' }));

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'byt-till-en-stark-secret';

// Verifiera GitHub HMAC SHA256-signatur
function verifySignature(req) {
  const sig = req.get('x-hub-signature-256') || '';
  const payload = JSON.stringify(req.body);
  const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET).update(payload).digest('hex');
  const expected = `sha256=${hmac}`;
  // use timing-safe compare
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

app.post('/webhook', (req, res) => {
  if (!verifySignature(req)) {
    return res.status(401).send('Invalid signature');
  }
  const event = req.get('x-github-event');
  const payload = req.body;
  console.log('Received event:', event);
  // Hantera events här (push, pull_request, installation, osv.)
  res.status(200).send('OK');
});

app.listen(3000, () => console.log('Webhook listener på :3000'));
// webhook-verify.js
const express = require('express');
const crypto = require('crypto');

const app = express();
// parse JSON bodies (raw needed for HMAC if you want exact bytes)
app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf } }));

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || 'byt-till-stark-secret';

// Timing-safe signaturkontroll
function verifySignature(req) {
  const signature = req.get('x-hub-signature-256') || '';
  const payload = req.rawBody || Buffer.from(JSON.stringify(req.body));
  const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET).update(payload).digest('hex');
  const expected = `sha256=${hmac}`;
  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  } catch (e) {
    return false;
  }
}

app.post('/webhook', (req, res) => {
  if (!verifySignature(req)) {
    console.warn('Invalid signature for delivery', req.get('x-github-delivery'));
    return res.status(401).send('Invalid signature');
  }
  const event = req.get('x-github-event');
  const delivery = req.get('x-github-delivery');
  console.log('Webhook received:', event, delivery);
  // Svara snabbt
  res.status(200).send('OK');
  // Behandla payload asynkront (enqueue jobb)
  // processWebhook(req.body, event).catch(err => console.error(err));
});

app.listen(3000, () => console.log('Webhook listener på :3000'));
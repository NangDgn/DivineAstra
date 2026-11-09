// Vercel Serverless Function: POST /api/unlock  (CommonJS, works with or without a package.json)
// Environment variables: TURNSTILE_SECRET, TOOLS_URL

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') return res.status(405).json({ error: 'method not allowed' });

  const origin = req.headers.origin;
  if (origin) {
    try {
      if (new URL(origin).host !== req.headers.host) return res.status(403).json({ error: 'forbidden' });
    } catch (_) {
      return res.status(403).json({ error: 'forbidden' });
    }
  }

  const token = req.body && req.body.token;
  if (!token || typeof token !== 'string' || token.length > 2048) {
    return res.status(400).json({ error: 'bad request' });
  }

  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const form = new URLSearchParams({
    secret: process.env.TURNSTILE_SECRET || '',
    response: token
  });
  if (ip) form.set('remoteip', ip);

  let check = { success: false };
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: form
    });
    check = await r.json();
  } catch (_) {}

  if (!check.success) return res.status(403).json({ error: 'verification failed' });
  return res.status(200).json({ url: process.env.TOOLS_URL });
};

// Node server for Wasmer Edge (node-base preset). No dependencies.
// Serves index.html and POST /api/unlock (Turnstile check, then returns the tools link).
// Environment variables: TURNSTILE_SECRET, TOOLS_URL, optional ALLOWED_ORIGINS, PORT.

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.PORT, 10) || 80;      // Wasmer Edge expects port 80 by default
const VERIFY_URL = process.env.VERIFY_URL || 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

function loadHtml() {
  const tries = [path.join(__dirname, 'index.html'), path.join(process.cwd(), 'index.html')];
  for (const p of tries) {
    try { return fs.readFileSync(p); } catch (_) {}
  }
  return Buffer.from('<h1>index.html not found</h1>');
}
const HTML = loadHtml();

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: https://cdn.corenexis.com; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; base-uri 'self'; form-action 'self'; object-src 'none'"
};

function send(res, status, body, type, extra) {
  res.writeHead(status, Object.assign({ 'Content-Type': type }, SECURITY_HEADERS, extra || {}));
  res.end(body);
}
function sendJson(res, status, obj) {
  send(res, status, JSON.stringify(obj), 'application/json', { 'Cache-Control': 'no-store' });
}

/* Best-effort limit: 5 unlock attempts per IP per 60 s, only when the proxy tells us the IP. */
const hits = new Map();
function limited(ip) {
  if (!ip) return false;
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < 60000);
  arr.push(now);
  hits.set(ip, arr);
  if (hits.size > 5000) {
    for (const [k, v] of hits) if (!v.length || now - v[v.length - 1] > 60000) hits.delete(k);
  }
  return arr.length > 5;
}

function readBody(req, max) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > max) { reject(new Error('too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

/* POST form-encoded data. Uses fetch when the runtime has it, node:http(s) otherwise. */
function postForm(url, formString) {
  if (typeof fetch === 'function' && !process.env.FORCE_HTTP_CLIENT) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formString
    }).then((r) => r.json());
  }
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'http:' ? http : https;
    const rq = lib.request(u, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(formString) }
    }, (r) => {
      let data = '';
      r.on('data', (c) => (data += c));
      r.on('end', () => { try { resolve(JSON.parse(data)); } catch (e) { reject(e); } });
    });
    rq.on('error', reject);
    rq.write(formString);
    rq.end();
  });
}

async function unlock(req, res) {
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'method not allowed' });

  const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  const origin = req.headers.origin;
  if (allowed.length && origin && !allowed.includes(origin)) return sendJson(res, 403, { error: 'forbidden' });

  const ip = String(req.headers['x-forwarded-for'] || req.headers['cf-connecting-ip'] || '').split(',')[0].trim();
  if (limited(ip)) return sendJson(res, 429, { error: 'too many requests' });

  let token = '';
  try { token = JSON.parse(await readBody(req, 4096)).token; }
  catch (_) { return sendJson(res, 400, { error: 'bad request' }); }
  if (!token || typeof token !== 'string' || token.length > 2048) return sendJson(res, 400, { error: 'bad request' });

  const form = new URLSearchParams();
  form.set('secret', process.env.TURNSTILE_SECRET || '');
  form.set('response', token);
  if (ip) form.set('remoteip', ip);

  let check = { success: false };
  try { check = await postForm(VERIFY_URL, form.toString()); } catch (_) {}

  if (!check || !check.success) return sendJson(res, 403, { error: 'verification failed' });
  return sendJson(res, 200, { url: process.env.TOOLS_URL || '' });
}

const server = http.createServer((req, res) => {
  const pathname = (req.url || '/').split('?')[0];
  if (pathname === '/api/unlock') return void unlock(req, res).catch(() => sendJson(res, 500, { error: 'server error' }));
  if (pathname === '/' || pathname === '/index.html') {
    return send(res, 200, HTML, 'text/html; charset=utf-8', { 'Cache-Control': 'public, max-age=300' });
  }
  send(res, 404, 'Not found', 'text/plain; charset=utf-8');
});

server.listen(PORT, '0.0.0.0', () => console.log('Listening on port ' + PORT));

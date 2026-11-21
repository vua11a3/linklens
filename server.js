const express = require('express');
const rateLimit = require('express-rate-limit');
const dns = require('dns').promises;
const net = require('net');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use('/api/', rateLimit({ windowMs: 60000, max: 30 }));

const cache = new Map();
const TTL = 10 * 60 * 1000;
const PARAMS = ['url','dest','u','target','redirect','link','to','goto','next'];

function isPrivate(ip) {
  if (net.isIPv6(ip)) return ip === '::1' || /^(fc|fd|fe80)/i.test(ip);
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) ||
         (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

async function assertSafe(raw) {
  const u = new URL(raw);
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Giao thức không hợp lệ');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  if (addrs.some(a => isPrivate(a.address))) throw new Error('Địa chỉ nội bộ bị chặn (SSRF)');
}

function quickDecode(raw) {
  const u = new URL(raw);
  for (const k of PARAMS) {
    const v = u.searchParams.get(k);
    if (!v) continue;
    if (/^https?:\/\//i.test(v)) return v;
    try {
      const d = Buffer.from(v.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
      if (/^https?:\/\//i.test(d)) return d;
    } catch {}
  }
  return null;
}

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.post('/api/resolve', async (req, res) => {
  const t0 = Date.now();
  try {
    const input = String(req.body.url || '').trim();
    await assertSafe(input);
    const hit = cache.get(input);
    if (hit && Date.now() - hit.t < TTL) return res.json({ ...hit.data, cached: true });

    const chain = [];
    let current = input;
    const quick = quickDecode(input);
    if (quick) { chain.push({ url: input, type: 'param-decode' }); current = quick; }

    for (let i = 0; i < 10; i++) {
      await assertSafe(current);
      const r = await fetch(current, {
        redirect: 'manual',
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; LinkLens/1.0)' },
        signal: AbortSignal.timeout(8000)
      });
      chain.push({ url: current, status: r.status });
      const loc = r.headers.get('location');
      if (r.status >= 300 && r.status < 400 && loc) current = new URL(loc, current).href;
      else break;
    }

    const data = { success: true, finalUrl: current, chain, ms: Date.now() - t0 };
    cache.set(input, { t: Date.now(), data });
    res.json(data);
  } catch (e) {
    res.status(400).json({ success: false, error: e.message, ms: Date.now() - t0 });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('LinkLens đang chạy'));

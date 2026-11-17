'use strict';
/*
 * BixTech auth server — zero npm dependencies (Node 18+).
 * Serves the website from ./public and handles OAuth 2.0 / OpenID Connect for
 * Google, Apple, GitHub, Facebook and Microsoft (authorization-code flow).
 *
 *   GET  /auth/:provider            start login (redirects to the provider)
 *   GET  /auth/:provider/callback   provider redirects back here (Apple uses POST)
 *   GET  /api/providers             which providers are configured
 *   GET  /api/me                    PROTECTED: the signed-in user, 401 otherwise
 *   POST /auth/logout               destroy the session
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/* ---------- config ---------- */
function loadEnvFile(file) {
  try {
    for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
      if (!m || line.trim().startsWith('#')) continue;
      let val = m[2];
      if (/^(".*"|'.*')$/.test(val)) val = val.slice(1, -1);
      else val = val.replace(/\s+#.*$/, '').replace(/^#.*$/, ''); // drop trailing comments
      if (process.env[m[1]] === undefined) process.env[m[1]] = val;
    }
  } catch (e) { /* no .env file: use real environment variables */ }
}
loadEnvFile(path.join(__dirname, '.env'));

const env = process.env;
const PORT = Number(env.PORT) || 3000;
const BASE_URL = (env.BASE_URL || env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');
const SECURE = BASE_URL.startsWith('https://');
const RATE_LIMIT = Number(env.RATE_LIMIT) || 30;
const SESSION_TTL = (Number(env.SESSION_DAYS) || 7) * 86400; // seconds
const DATA_FILE = path.join(env.DATA_DIR || path.join(__dirname, 'data'), 'store.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const SESSION_SECRET = env.SESSION_SECRET || '';
if (SESSION_SECRET.length < 32) {
  const msg = '[auth] SESSION_SECRET is missing or shorter than 32 characters. Run "node setup.js" or set a long random value (see README).';
  if (SECURE) { console.error(msg); process.exit(1); } // never run a public site with a weak secret
  console.warn(msg);
}
const SID_COOKIE = (SECURE ? '__Host-' : '') + 'bix_sid';
const OAUTH_COOKIE = (SECURE ? '__Host-' : '') + 'bix_oauth';

/* ---------- tiny helpers ---------- */
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const rand = (n = 32) => crypto.randomBytes(n).toString('base64url');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest();
const hmac = (s) => crypto.createHmac('sha256', SESSION_SECRET || 'dev-only-secret').update(s).digest('base64url');
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const nowS = () => Math.floor(Date.now() / 1000);
class AuthError extends Error { constructor(code, msg) { super(msg || code); this.code = code; } }

/* ---------- storage (JSON file; swap for a real DB when you grow) ---------- */
let store = { users: [], identities: [] };
try { store = Object.assign(store, JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'))); } catch (e) { /* first run */ }
function persist() {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(store), { mode: 0o600 });
  try { fs.renameSync(tmp, DATA_FILE); } // atomic replace on a normal disk
  catch (e) { fs.writeFileSync(DATA_FILE, JSON.stringify(store), { mode: 0o600 }); } // some mounted drives can't rename
}

/* ---------- users: first sign-in creates the account, later ones reuse it ---------- */
function findOrCreateUser(p) {
  const ident = store.identities.find((i) => i.provider === p.provider && i.subject === p.subject);
  if (ident) {
    const user = store.users.find((u) => u.id === ident.userId);
    if (user) { user.lastLoginAt = nowS(); persist(); return { user, created: false }; }
  }
  const email = (p.email || '').trim().toLowerCase();
  if (!email) throw new AuthError('no_email', 'provider returned no email');

  let user = store.users.find((u) => u.email === email);
  if (user) {
    // Only attach a new provider to an existing account if the provider PROVES the email is theirs.
    if (!p.emailVerified) throw new AuthError('email_exists', 'unverified email matches an existing account');
    if (!user.emailVerified) {
      // The account was made with an unproven email: drop whoever else is attached to it.
      store.identities = store.identities.filter((i) => i.userId !== user.id);
      user.emailVerified = true;
    }
  } else {
    user = { id: 'u_' + rand(12), email, name: (p.name || email.split('@')[0]).slice(0, 120),
             emailVerified: !!p.emailVerified, createdAt: nowS(), lastLoginAt: nowS() };
    store.users.push(user);
    var created = true;
  }
  store.identities.push({ provider: p.provider, subject: p.subject, userId: user.id });
  user.lastLoginAt = nowS();
  persist();
  return { user, created: !!created };
}

/* ---------- sessions: signed, HttpOnly cookie (stateless, so they survive restarts and sleeping hosts) ---------- */
const revoked = new Map(); // logged-out session ids (best effort, in memory) -> expiry
function createSession(user, provider) {
  const blob = b64u(JSON.stringify({ j: rand(12), u: user.id, n: user.name, e: user.email, p: provider, x: nowS() + SESSION_TTL }));
  return blob + '.' + hmac(blob); // tamper-evident: changing anything breaks the signature
}
function sessionFrom(req) {
  const raw = parseCookies(req)[SID_COOKIE];
  if (!raw) return null;
  const [blob, sig] = raw.split('.');
  if (!blob || !sig || !safeEq(sig, hmac(blob))) return null;
  let c; try { c = JSON.parse(Buffer.from(blob, 'base64url').toString('utf8')); } catch (e) { return null; }
  if (!c || c.x < nowS() || revoked.has(c.j)) return null;
  return { key: c.j, exp: c.x, user: { id: c.u, name: c.n, email: c.e }, provider: c.p };
}
setInterval(() => {
  for (const [k, exp] of consumed) if (exp < nowS()) consumed.delete(k);
  for (const [k, exp] of revoked) if (exp < nowS()) revoked.delete(k);
}, 10 * 60 * 1000).unref();

/* ---------- http helpers ---------- */
function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function cookie(name, value, { maxAge, sameSite = 'Lax' } = {}) {
  let c = `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=${sameSite}`;
  if (SECURE || sameSite === 'None') c += '; Secure';
  if (maxAge !== undefined) c += `; Max-Age=${maxAge}`;
  return c;
}
function send(res, status, body, headers = {}) {
  const isObj = body !== null && typeof body === 'object';
  res.writeHead(status, Object.assign({
    'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
  }, headers));
  res.end(isObj ? JSON.stringify(body) : body || '');
}
function redirect(res, url, cookies = []) {
  res.writeHead(302, Object.assign({ Location: url, 'Cache-Control': 'no-store' }, cookies.length ? { 'Set-Cookie': cookies } : {}));
  res.end();
}
function readBody(req, limit = 100000) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > limit) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
const securityHeaders = () => Object.assign({
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Content-Security-Policy': "frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
  'Permissions-Policy': 'camera=(self), microphone=(), geolocation=()',
}, SECURE ? { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } : {});

/* simple per-IP rate limit for /auth/* (RATE_LIMIT requests / minute, default 30) */
const hits = new Map();
function limited(req) {
  const ip = (SECURE && req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0] : req.socket.remoteAddress) || '?';
  const t = Date.now(), h = (hits.get(ip) || []).filter((x) => t - x < 60000);
  h.push(t); hits.set(ip, h);
  if (hits.size > 5000) hits.clear();
  return h.length > RATE_LIMIT;
}

/* ---------- providers ---------- */
async function fetchJSON(url, opts = {}) {
  const r = await fetch(url, Object.assign({ signal: AbortSignal.timeout(10000) }, opts));
  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch (e) { data = { raw: text }; }
  if (!r.ok) throw new Error(`${url} -> ${r.status} ${text.slice(0, 200)}`);
  return data;
}
const bearer = (t) => ({ Authorization: 'Bearer ' + t, Accept: 'application/json' });

function appleClientSecret() {
  const key = (env.APPLE_PRIVATE_KEY || '').replace(/\\n/g, '\n') ||
    (env.APPLE_PRIVATE_KEY_PATH ? fs.readFileSync(env.APPLE_PRIVATE_KEY_PATH, 'utf8') : '');
  const header = b64u(JSON.stringify({ alg: 'ES256', kid: env.APPLE_KEY_ID }));
  const t = nowS();
  const payload = b64u(JSON.stringify({ iss: env.APPLE_TEAM_ID, iat: t, exp: t + 300, aud: 'https://appleid.apple.com', sub: env.APPLE_CLIENT_ID }));
  const sig = crypto.sign('sha256', Buffer.from(`${header}.${payload}`), { key, dsaEncoding: 'ieee-p1363' });
  return `${header}.${payload}.${b64u(sig)}`;
}
let appleKeys = { at: 0, keys: [] };
async function verifyAppleIdToken(idToken, nonce) {
  const [h, p, s] = String(idToken).split('.');
  if (!h || !p || !s) throw new Error('bad id_token');
  const header = JSON.parse(Buffer.from(h, 'base64url'));
  if (header.alg !== 'RS256') throw new Error('bad alg');
  if (Date.now() - appleKeys.at > 3600000 || !appleKeys.keys.some((k) => k.kid === header.kid)) {
    appleKeys = { at: Date.now(), keys: (await fetchJSON('https://appleid.apple.com/auth/keys')).keys };
  }
  const jwk = appleKeys.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('unknown key');
  const ok = crypto.verify('RSA-SHA256', Buffer.from(`${h}.${p}`), crypto.createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(s, 'base64url'));
  if (!ok) throw new Error('bad signature');
  const c = JSON.parse(Buffer.from(p, 'base64url'));
  if (c.iss !== 'https://appleid.apple.com' || c.aud !== env.APPLE_CLIENT_ID || c.exp < nowS() || !safeEq(c.nonce || '', nonce)) throw new Error('bad claims');
  return c;
}

const providers = {
  google: {
    label: 'Google', pkce: true, scope: 'openid email profile',
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth', tokenUrl: 'https://oauth2.googleapis.com/token',
    id: () => env.GOOGLE_CLIENT_ID, secret: () => env.GOOGLE_CLIENT_SECRET,
    async profile(tok) {
      const u = await fetchJSON('https://openidconnect.googleapis.com/v1/userinfo', { headers: bearer(tok.access_token) });
      return { subject: u.sub, email: u.email, emailVerified: u.email_verified === true, name: u.name };
    },
  },
  github: {
    label: 'GitHub', pkce: true, scope: 'read:user user:email',
    authUrl: 'https://github.com/login/oauth/authorize', tokenUrl: 'https://github.com/login/oauth/access_token',
    id: () => env.GITHUB_CLIENT_ID, secret: () => env.GITHUB_CLIENT_SECRET,
    async profile(tok) {
      const h = Object.assign(bearer(tok.access_token), { 'User-Agent': 'bixtech-auth', 'X-GitHub-Api-Version': '2022-11-28' });
      const u = await fetchJSON('https://api.github.com/user', { headers: h });
      const emails = await fetchJSON('https://api.github.com/user/emails', { headers: h });
      const best = emails.find((e) => e.primary && e.verified) || emails.find((e) => e.verified);
      return { subject: String(u.id), email: best && best.email, emailVerified: !!best, name: u.name || u.login };
    },
  },
  facebook: {
    label: 'Facebook', pkce: false, scope: 'email public_profile',
    authUrl: 'https://www.facebook.com/v19.0/dialog/oauth', tokenUrl: 'https://graph.facebook.com/v19.0/oauth/access_token',
    id: () => env.FACEBOOK_APP_ID, secret: () => env.FACEBOOK_APP_SECRET,
    async profile(tok) {
      const u = await fetchJSON('https://graph.facebook.com/v19.0/me?fields=id,name,email', { headers: bearer(tok.access_token) });
      // Facebook does not say whether the email is verified, so we never auto-link it to an existing account.
      return { subject: u.id, email: u.email, emailVerified: false, name: u.name };
    },
  },
  microsoft: {
    label: 'Microsoft', pkce: true, scope: 'openid email profile',
    get authUrl() { return `https://login.microsoftonline.com/${env.MICROSOFT_TENANT || 'common'}/oauth2/v2.0/authorize`; },
    get tokenUrl() { return `https://login.microsoftonline.com/${env.MICROSOFT_TENANT || 'common'}/oauth2/v2.0/token`; },
    id: () => env.MICROSOFT_CLIENT_ID, secret: () => env.MICROSOFT_CLIENT_SECRET,
    async profile(tok) {
      const u = await fetchJSON('https://graph.microsoft.com/oidc/userinfo', { headers: bearer(tok.access_token) });
      // Microsoft's email claim is not guaranteed verified (the "nOAuth" issue), so never auto-link it.
      return { subject: u.sub, email: u.email, emailVerified: false, name: u.name };
    },
  },
  apple: {
    label: 'Apple', pkce: false, scope: 'name email', formPost: true,
    authUrl: 'https://appleid.apple.com/auth/authorize', tokenUrl: 'https://appleid.apple.com/auth/token',
    id: () => env.APPLE_CLIENT_ID,
    secret: () => (env.APPLE_TEAM_ID && env.APPLE_KEY_ID && (env.APPLE_PRIVATE_KEY || env.APPLE_PRIVATE_KEY_PATH) ? appleClientSecret() : ''),
    async profile(tok, ctx) {
      const c = await verifyAppleIdToken(tok.id_token, ctx.nonce);
      let name = ctx.appleUser && ctx.appleUser.name ? [ctx.appleUser.name.firstName, ctx.appleUser.name.lastName].filter(Boolean).join(' ') : '';
      return { subject: c.sub, email: c.email, emailVerified: c.email_verified === true || c.email_verified === 'true', name };
    },
  },
};
const configured = (p) => !!(providers[p].id() && providers[p].secret());
const REQUIRED = {
  google: ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'], github: ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'],
  facebook: ['FACEBOOK_APP_ID', 'FACEBOOK_APP_SECRET'], microsoft: ['MICROSOFT_CLIENT_ID', 'MICROSOFT_CLIENT_SECRET'],
  apple: ['APPLE_CLIENT_ID', 'APPLE_TEAM_ID', 'APPLE_KEY_ID', 'APPLE_PRIVATE_KEY (or APPLE_PRIVATE_KEY_PATH)'],
};
const missing = (p) => REQUIRED[p].filter((v) => !(env[v.split(' ')[0]] || (v.startsWith('APPLE_PRIVATE_KEY') && env.APPLE_PRIVATE_KEY_PATH)));

/* ---------- OAuth flow ---------- */
const consumed = new Map(); // best-effort single-use memory of finished states (state -> exp)
const redirectUri = (p) => `${BASE_URL}/auth/${p}/callback`;
const fail = (res, code, extra = []) => redirect(res, `/?auth_error=${encodeURIComponent(code)}`, extra);
const clearOauth = () => cookie(OAUTH_COOKIE, '', { maxAge: 0 });

function readOauthCookie(req) {
  const raw = parseCookies(req)[OAUTH_COOKIE];
  if (!raw) return null;
  const [blob, sig] = raw.split('.');
  if (!blob || !sig || !safeEq(sig, hmac(blob))) return null;
  try { return JSON.parse(Buffer.from(blob, 'base64url').toString('utf8')); } catch (e) { return null; }
}

function startLogin(res, name) {
  const p = providers[name];
  if (!configured(name)) return fail(res, 'not_configured');
  const state = rand(24), verifier = rand(48), nonce = rand(16);
  // Everything we must remember about this login attempt lives in a signed HttpOnly cookie,
  // so it survives server restarts and works with several / scaled-to-zero instances.
  const blob = b64u(JSON.stringify({ s: state, p: name, v: verifier, n: nonce, e: nowS() + 600 }));
  const q = new URLSearchParams({ response_type: 'code', client_id: p.id(), redirect_uri: redirectUri(name), scope: p.scope, state });
  if (p.pkce) { q.set('code_challenge', b64u(sha256(verifier))); q.set('code_challenge_method', 'S256'); }
  if (name === 'apple') { q.set('response_mode', 'form_post'); q.set('nonce', nonce); }
  if (name === 'google') q.set('prompt', 'select_account');
  if (name === 'microsoft') q.set('prompt', 'select_account');
  // Apple posts back cross-site, so its binding cookie must be SameSite=None (needs HTTPS).
  const c = cookie(OAUTH_COOKIE, blob + '.' + hmac(blob), { maxAge: 600, sameSite: p.formPost ? 'None' : 'Lax' });
  redirect(res, `${p.authUrl}?${q}`, [c]);
}

async function finishLogin(req, res, name, params) {
  const p = providers[name];
  const done = (code) => fail(res, code, [clearOauth()]);
  try {
    if (!configured(name)) return done('not_configured');
    const st = readOauthCookie(req);
    if (!st || st.p !== name || st.e < nowS() || !params.state || !safeEq(params.state, st.s) || consumed.has(st.s)) return done('state');
    consumed.set(st.s, st.e); // single use
    if (params.error) return done(params.error === 'access_denied' || params.error === 'user_cancelled_authorize' ? 'access_denied' : 'provider');
    if (!params.code) return done('provider');

    const body = new URLSearchParams({ grant_type: 'authorization_code', code: params.code, redirect_uri: redirectUri(name), client_id: p.id(), client_secret: p.secret() });
    if (p.pkce) body.set('code_verifier', st.v);
    const tok = await fetchJSON(p.tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body });
    if (!tok.access_token && !tok.id_token) throw new Error('no token in response');

    let appleUser = null;
    if (params.user) { try { appleUser = JSON.parse(params.user); } catch (e) { /* ignore */ } }
    const prof = await p.profile(tok, { nonce: st.n, appleUser });
    if (!prof.subject) throw new Error('no subject');

    const { user, created } = findOrCreateUser(Object.assign({ provider: name }, prof));
    const sid = createSession(user, name);
    redirect(res, `/?auth=ok&p=${name}${created ? '&new=1' : ''}`, [cookie(SID_COOKIE, sid, { maxAge: SESSION_TTL }), clearOauth()]);
  } catch (e) {
    console.error(`[auth] ${name} failed:`, e.code || '', e.message);
    done(e instanceof AuthError ? e.code : 'provider');
  }
}

/* ---------- static files ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webp': 'image/webp', '.txt': 'text/plain' };
const PUBLIC_PAGES = ['/']; // pages Google may index (private areas live inside the app, behind login)
function seoFile(res, pathname) {
  if (pathname === '/robots.txt') {
    send(res, 200, `User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /auth/\n\nSitemap: ${BASE_URL}/sitemap.xml\n`, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=3600' });
    return true;
  }
  if (pathname === '/sitemap.xml') {
    const day = new Date().toISOString().slice(0, 10);
    const urls = PUBLIC_PAGES.map((p) => `  <url><loc>${BASE_URL}${p}</loc><lastmod>${day}</lastmod></url>`).join('\n');
    send(res, 200, `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`, { 'Content-Type': 'application/xml; charset=utf-8', 'Cache-Control': 'public, max-age=3600' });
    return true;
  }
  return false;
}
function serveStatic(req, res, pathname) {
  if (seoFile(res, pathname)) return;
  let rel = decodeURIComponent(pathname);
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return send(res, 403, 'Forbidden');
  fs.readFile(file, (err, data) => {
    if (err) return send(res, 404, '<!doctype html><meta charset="utf-8"><meta name="robots" content="noindex"><title>Page not found · BixTech</title><body style="font-family:sans-serif;text-align:center;padding:3rem"><h1>404</h1><p>This page doesn’t exist.</p><p><a href="/">Back to BixTech</a></p>', { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    if (path.extname(file) === '.html') { // fill in the real address and optional Google verification tag
      const verify = env.GOOGLE_SITE_VERIFICATION ? `<meta name="google-site-verification" content="${String(env.GOOGLE_SITE_VERIFICATION).replace(/[^A-Za-z0-9_-]/g, '')}">\n` : '';
      data = Buffer.from(data.toString('utf8').split('%%BASE_URL%%').join(BASE_URL).split('%%VERIFY%%').join(verify));
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}

/* ---------- router ---------- */
async function handler(req, res) {
  for (const [k, v] of Object.entries(securityHeaders())) res.setHeader(k, v);
  const url = new URL(req.url, BASE_URL);
  const { pathname } = url;
  if (pathname.startsWith('/api/') || pathname.startsWith('/auth/')) res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  try {
    if (pathname.startsWith('/auth/') && limited(req)) return send(res, 429, { error: 'too_many_requests' });

    if (pathname === '/healthz') return send(res, 200, { ok: true });

    if (pathname === '/api/providers' && req.method === 'GET')
      return send(res, 200, { baseUrl: BASE_URL, providers: Object.fromEntries(Object.keys(providers).map((k) => [k, configured(k)])) });

    if (pathname === '/api/me' && req.method === 'GET') { // protected route
      const s = sessionFrom(req);
      if (!s) return send(res, 401, { error: 'unauthenticated' });
      return send(res, 200, { user: { id: s.user.id, name: s.user.name, email: s.user.email, provider: s.provider } });
    }

    if (pathname === '/auth/logout' && req.method === 'POST') {
      if (req.headers['x-requested-with'] !== 'fetch') return send(res, 403, { error: 'forbidden' }); // CSRF guard
      const s = sessionFrom(req);
      if (s) revoked.set(s.key, s.exp);
      return send(res, 200, { ok: true }, { 'Set-Cookie': cookie(SID_COOKIE, '', { maxAge: 0 }) });
    }

    const m = pathname.match(/^\/auth\/(google|apple|github|facebook|microsoft)(\/callback)?$/);
    if (m) {
      const name = m[1];
      if (!m[2] && req.method === 'GET') return startLogin(res, name);
      if (m[2] && req.method === 'GET' && !providers[name].formPost) return finishLogin(req, res, name, Object.fromEntries(url.searchParams));
      if (m[2] && req.method === 'POST' && providers[name].formPost)
        return finishLogin(req, res, name, Object.fromEntries(new URLSearchParams(await readBody(req))));
      return send(res, 405, 'Method not allowed');
    }

    if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res, pathname);
    send(res, 405, 'Method not allowed');
  } catch (e) {
    console.error('[server]', e);
    send(res, 500, { error: 'server_error' });
  }
}

const server = http.createServer(handler);
if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`BixTech running at ${BASE_URL}`);
    for (const k of Object.keys(providers)) {
      console.log(`  ${providers[k].label.padEnd(10)} ${configured(k) ? 'READY' : 'NOT SET UP, missing: ' + missing(k).join(', ')}`);
      console.log(`  ${''.padEnd(10)} callback URL to register: ${redirectUri(k)}`);
    }
  });
}
module.exports = { server, store, providers, missing };

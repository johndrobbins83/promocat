/**
 * PromoCat API — Cloudflare Worker
 * 
 * SETUP INSTRUCTIONS:
 * 1. Go to workers.cloudflare.com → Create Worker → paste this file
 * 2. Name it "promocat-api"
 * 3. Settings → Variables → KV Namespace Bindings → Add:
 *      Variable name: PROMOCAT_KV
 *      KV Namespace: (create one called "promocat")
 * 4. Settings → Variables → Environment Variables → Add:
 *      INVITE_CODE  = (your secret invite code, e.g. "meowmeow2024")
 *      JWT_SECRET   = (random string, e.g. "xk9zQp2rW8mT5vYn")
 * 5. Deploy → Settings → Triggers → Add custom domain:
 *      promocat-api.johnthepm.com
 * 
 * ADMIN ENDPOINTS (create your first invite code):
 *   The invite code is set in INVITE_CODE env var — share it privately with users you want to register.
 *   To view all users (for debugging): GET /admin/users?secret=YOUR_JWT_SECRET
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  'https://johnthepm.com',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// ── Simple JWT (HMAC-SHA256) ──
async function signToken(payload, secret) {
  const header  = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body    = btoa(JSON.stringify(payload));
  const data    = header + '.' + body;
  const key     = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig     = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64  = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return data + '.' + sigB64;
}

async function verifyToken(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const data   = header + '.' + body;
    const key    = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBuf = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
    const valid  = await crypto.subtle.verify('HMAC', key, sigBuf, new TextEncoder().encode(data));
    if (!valid) return null;
    const payload = JSON.parse(atob(body));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

// ── Password hashing (SHA-256 with salt) ──
async function hashPassword(password, salt) {
  const data = new TextEncoder().encode(salt + password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

function randomSalt() {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
  });
}

// ── Auth middleware ──
async function getUser(request, env) {
  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return null;
  const token   = auth.slice(7);
  const payload = await verifyToken(token, env.JWT_SECRET);
  if (!payload) return null;
  return payload; // { username, exp }
}

// ── Main handler ──
export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url  = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '');

    // ════════════════════════════
    // POST /register
    // Body: { username, password, inviteCode }
    // ════════════════════════════
    if (path === '/register' && request.method === 'POST') {
      const { username, password, inviteCode } = await request.json();

      if (!username || !password || !inviteCode)
        return json({ error: 'Missing fields' }, 400);

      if (inviteCode !== env.INVITE_CODE)
        return json({ error: 'Invalid invite code' }, 403);

      const userKey = 'user:' + username.toLowerCase();
      const existing = await env.PROMOCAT_KV.get(userKey);
      if (existing)
        return json({ error: 'Username already taken' }, 409);

      if (username.length < 3 || username.length > 30 || !/^[a-zA-Z0-9_-]+$/.test(username))
        return json({ error: 'Username must be 3-30 alphanumeric chars' }, 400);

      if (password.length < 6)
        return json({ error: 'Password must be at least 6 characters' }, 400);

      const salt     = randomSalt();
      const pwHash   = await hashPassword(password, salt);
      const userData = { username, salt, pwHash, createdAt: Date.now(), profiles: [] };
      await env.PROMOCAT_KV.put(userKey, JSON.stringify(userData));

      return json({ ok: true, message: 'Account created' });
    }

    // ════════════════════════════
    // POST /login
    // Body: { username, password }
    // ════════════════════════════
    if (path === '/login' && request.method === 'POST') {
      const { username, password } = await request.json();
      if (!username || !password)
        return json({ error: 'Missing credentials' }, 400);

      const userKey  = 'user:' + username.toLowerCase();
      const userJson = await env.PROMOCAT_KV.get(userKey);
      if (!userJson)
        return json({ error: 'Invalid username or password' }, 401);

      const userData = JSON.parse(userJson);
      const pwHash   = await hashPassword(password, userData.salt);

      if (pwHash !== userData.pwHash)
        return json({ error: 'Invalid username or password' }, 401);

      // Issue token — expires in 30 days
      const token = await signToken(
        { username: userData.username, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 },
        env.JWT_SECRET
      );

      return json({ ok: true, token, username: userData.username });
    }

    // ════════════════════════════
    // GET /verify
    // Header: Authorization: Bearer <token>
    // ════════════════════════════
    if (path === '/verify' && request.method === 'GET') {
      const user = await getUser(request, env);
      if (!user) return json({ error: 'Invalid or expired token' }, 401);
      return json({ ok: true, username: user.username });
    }

    // ════════════════════════════
    // GET /profiles  — get current user's profiles
    // PUT /profiles  — save current user's profiles
    // ════════════════════════════
    if (path === '/profiles') {
      const user = await getUser(request, env);
      if (!user) return json({ error: 'Unauthorised' }, 401);

      const userKey  = 'user:' + user.username.toLowerCase();
      const userJson = await env.PROMOCAT_KV.get(userKey);
      if (!userJson) return json({ error: 'User not found' }, 404);

      const userData = JSON.parse(userJson);

      if (request.method === 'GET') {
        return json({ ok: true, profiles: userData.profiles || [] });
      }

      if (request.method === 'PUT') {
        const { profiles } = await request.json();
        if (!Array.isArray(profiles)) return json({ error: 'profiles must be array' }, 400);
        userData.profiles = profiles;
        await env.PROMOCAT_KV.put(userKey, JSON.stringify(userData));
        return json({ ok: true });
      }
    }

    // ════════════════════════════
    // GET /public-profiles — all profiles from all users (no auth needed, for public roster)
    // ════════════════════════════
    if (path === '/public-profiles' && request.method === 'GET') {
      // List all user keys and aggregate their profiles
      const list = await env.PROMOCAT_KV.list({ prefix: 'user:' });
      const allProfiles = [];
      for (const key of list.keys) {
        const userJson = await env.PROMOCAT_KV.get(key.name);
        if (userJson) {
          const userData = JSON.parse(userJson);
          (userData.profiles || []).forEach(p => {
            allProfiles.push({ ...p, _owner: userData.username });
          });
        }
      }
      return json({ ok: true, profiles: allProfiles });
    }

    // ════════════════════════════
    // GET /admin/users?secret=JWT_SECRET  — list all users (admin only)
    // ════════════════════════════
    if (path === '/admin/users' && request.method === 'GET') {
      if (url.searchParams.get('secret') !== env.JWT_SECRET)
        return json({ error: 'Forbidden' }, 403);
      const list = await env.PROMOCAT_KV.list({ prefix: 'user:' });
      const users = [];
      for (const key of list.keys) {
        const userJson = await env.PROMOCAT_KV.get(key.name);
        if (userJson) {
          const { username, createdAt, profiles } = JSON.parse(userJson);
          users.push({ username, createdAt, profileCount: (profiles||[]).length });
        }
      }
      return json({ ok: true, users });
    }

    // ════════════════════════════
    // DELETE /admin/user/:username?secret=JWT_SECRET — remove a user
    // ════════════════════════════
    if (path.startsWith('/admin/user/') && request.method === 'DELETE') {
      if (url.searchParams.get('secret') !== env.JWT_SECRET)
        return json({ error: 'Forbidden' }, 403);
      const targetUser = path.replace('/admin/user/', '');
      await env.PROMOCAT_KV.delete('user:' + targetUser.toLowerCase());
      return json({ ok: true });
    }

    return json({ error: 'Not found' }, 404);
  }
};

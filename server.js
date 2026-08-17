const express = require('express');
const Datastore = require('@seald-io/nedb');
const { randomUUID, createHash, createHmac, timingSafeEqual } = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 8080;

if (!fs.existsSync('./data')) fs.mkdirSync('./data');

const keysDb  = new Datastore({ filename: './data/keys.db',  autoload: true });
const logsDb  = new Datastore({ filename: './data/logs.db',  autoload: true });
const adminDb = new Datastore({ filename: './data/admin.db', autoload: true });
const appsDb  = new Datastore({ filename: './data/apps.db',  autoload: true });
const blocksDb= new Datastore({ filename: './data/blocks.db',autoload: true });

keysDb.ensureIndex({ fieldName: 'key', unique: true });
logsDb.ensureIndex({ fieldName: 'timestamp' });
appsDb.ensureIndex({ fieldName: 'publicKey', unique: true });
blocksDb.ensureIndex({ fieldName: 'ip' });

adminDb.findOne({ _id: 'admin' }, (err, doc) => {
  if (!doc) adminDb.insert({ _id: 'admin', password: 'boostempire123' });
});

// ── ACTIVE SESSION TOKENS (in-memory) ────────────────────────────────────────
// Maps key → sessionToken. When a ban or HWID reset occurs, the token is
// cleared here so the next heartbeat/re-auth call returns KICKED.
const activeSessions = new Map(); // key → { token, appId }

// ── RATE LIMIT STORE (in-memory) ──────────────────────────────────────────────
const rateLimitMap = new Map();
const RATE_WINDOW  = 60 * 1000;  // 1 minute
const RATE_MAX     = 30;          // 30 requests per minute per IP
const BLOCK_AFTER  = 80;          // auto-block IP after 80 failed attempts
const failCounts   = new Map();

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-admin-token, x-public-key, x-secret-key, x-request-id, x-timestamp');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── HELPERS ───────────────────────────────────────────────────────────────────
function getIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  const raw = req.socket.remoteAddress || req.connection.remoteAddress || '';
  const socketIP = raw.replace(/^::ffff:/, '');
  // If socket reports loopback (client on same machine as server),
  // accept a real_ip field the client can include in the request body/headers
  if (socketIP === '127.0.0.1' || socketIP === '::1' || socketIP === '') {
    const clientReported = req.headers['x-real-ip'] || (req.body && req.body.real_ip) || '';
    if (clientReported && clientReported !== '127.0.0.1') return clientReported.trim();
  }
  return socketIP;
}
function genKey()        { return 'BE-' + randomUUID().toUpperCase().replace(/-/g,'').substring(0,20); }
function genSessionToken() { return randomUUID().replace(/-/g,'') + randomUUID().replace(/-/g,''); }
function genPubKey() { return 'pk_' + randomUUID().replace(/-/g,''); }
function genSecKey() { return 'sk_' + randomUUID().replace(/-/g,'') + randomUUID().replace(/-/g,''); }
function hashString(s) { return createHash('sha256').update(s).digest('hex'); }

// Safe string compare (prevents timing attacks)
function safeCompare(a, b) {
  try {
    return timingSafeEqual(Buffer.from(String(a)), Buffer.from(String(b)));
  } catch { return false; }
}

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  adminDb.findOne({ _id: 'admin' }, (err, doc) => {
    if (!doc || !safeCompare(token, doc.password)) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    next();
  });
}

function log(appId, keyVal, hwid, appName, action, result, ip, details='') {
  logsDb.insert({
    appId: appId||null, key: keyVal, hwid: hwid||null,
    app_name: appName||'Unknown', action, result,
    ip: ip||null, details, timestamp: new Date().toISOString()
  });
}

// ── RATE LIMITER MIDDLEWARE (public auth only) ────────────────────────────────
function rateLimit(req, res, next) {
  const ip = getIP(req);
  const now = Date.now();

  // Check hard block list
  blocksDb.findOne({ ip }, (err, blocked) => {
    if (blocked) {
      return res.status(429).json({
        success: false, code: 'IP_BLOCKED',
        message: 'Your IP has been permanently blocked due to abuse'
      });
    }

    // Rate limit
    if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
    const hits = rateLimitMap.get(ip).filter(t => now - t < RATE_WINDOW);
    hits.push(now);
    rateLimitMap.set(ip, hits);

    if (hits.length > RATE_MAX) {
      log(null, '—', null, 'RATELIMIT', 'AUTH', 'RATE_LIMITED', ip, `${hits.length} requests in 60s`);
      return res.status(429).json({
        success: false, code: 'RATE_LIMITED',
        message: 'Too many requests — slow down',
        retry_after: 60
      });
    }
    next();
  });
}

// Track failed attempts and auto-block abusers
function trackFail(ip, key) {
  const count = (failCounts.get(ip) || 0) + 1;
  failCounts.set(ip, count);
  if (count >= BLOCK_AFTER) {
    blocksDb.findOne({ ip }, (err, doc) => {
      if (!doc) {
        blocksDb.insert({ ip, reason: 'Auto-blocked: too many failed auth attempts', blockedAt: new Date().toISOString() });
      }
    });
  }
}

// ── PUBLIC IP HELPER ─────────────────────────────────────────────────────────
// Clients running on the same machine as the server will always show 127.0.0.1
// on the socket. This endpoint lets the C++ client fetch its real public IP
// via an external lookup, then pass it back in real_ip on the auth request.
const https = require('https');
function fetchPublicIP() {
  return new Promise((resolve) => {
    https.get('https://api.ipify.org?format=json', (r) => {
      let d = '';
      r.on('data', c => d += c);
      r.on('end', () => { try { resolve(JSON.parse(d).ip); } catch { resolve(null); } });
    }).on('error', () => resolve(null));
  });
}

app.get('/api/myip', (req, res) => {
  const ip = getIP(req);
  res.json({ ip });
});

// Internal helper: resolve real IP for loopback connections
async function resolveRealIP(req) {
  const ip = getIP(req);
  if (ip !== '127.0.0.1' && ip !== '::1') return ip;
  // Socket is loopback — try external lookup (only for dev/same-machine setups)
  const publicIP = await fetchPublicIP().catch(() => null);
  return publicIP || ip;
}

// ── PUBLIC AUTH ───────────────────────────────────────────────────────────────
app.post('/api/auth', rateLimit, async (req, res) => {
  const { key, hwid, app_name } = req.body;
  const publicKey = req.headers['x-public-key'] || req.body.public_key;
  const ip = await resolveRealIP(req);

  // Validate all required fields exist and are strings
  if (!publicKey || typeof publicKey !== 'string' || publicKey.length > 200) {
    return res.json({ success:false, code:'NO_PUBLIC_KEY', message:'Missing or invalid public API key' });
  }
  if (!key || typeof key !== 'string' || key.length > 100) {
    return res.json({ success:false, code:'NO_KEY', message:'Missing or invalid license key' });
  }
  if (!hwid || typeof hwid !== 'string' || hwid.length > 200) {
    return res.json({ success:false, code:'NO_HWID', message:'Missing or invalid HWID' });
  }

  // HWID must look legitimate (min 8 chars, no suspicious patterns)
  if (hwid.length < 8 || /^(0+|1+|test|fake|crack|bypass|debug|cheat)$/i.test(hwid)) {
    log(null, key, hwid, app_name, 'AUTH', 'INVALID_HWID', ip, 'Suspicious HWID pattern rejected');
    trackFail(ip, key);
    return res.json({ success:false, code:'INVALID_HWID', message:'Invalid hardware ID' });
  }

  appsDb.findOne({ publicKey }, (err, appDoc) => {
    if (!appDoc) {
      trackFail(ip, key);
      log(null, key, hwid, app_name, 'AUTH', 'INVALID_PUBLIC_KEY', ip, `Unknown public key`);
      return res.json({ success:false, code:'INVALID_PUBLIC_KEY', message:'Invalid public API key' });
    }
    if (!appDoc.active) {
      return res.json({ success:false, code:'APP_DISABLED', message:'This application is disabled' });
    }

    keysDb.findOne({ key, appId: appDoc._id }, (err, doc) => {
      if (!doc) {
        trackFail(ip, key);
        log(appDoc._id, key, hwid, app_name||appDoc.name, 'AUTH', 'INVALID_KEY', ip, 'Key not found');
        return res.json({ success:false, code:'INVALID_KEY', message:'License key not found' });
      }
      if (doc.status === 'banned') {
        trackFail(ip, key);
        log(appDoc._id, key, hwid, app_name||appDoc.name, 'AUTH', 'BANNED', ip, 'Key is banned');
        return res.json({ success:false, code:'BANNED', message:'This license key has been banned' });
      }
      if (doc.status === 'frozen') {
        log(appDoc._id, key, hwid, app_name||appDoc.name, 'AUTH', 'FROZEN', ip, 'Key is frozen');
        return res.json({ success:false, code:'FROZEN', message:'This license key has been temporarily frozen' });
      }
      if (doc.expiresAt && new Date(doc.expiresAt) < new Date()) {
        log(appDoc._id, key, hwid, app_name||appDoc.name, 'AUTH', 'EXPIRED', ip, `Expired: ${doc.expiresAt}`);
        return res.json({ success:false, code:'EXPIRED', message:'License key has expired' });
      }
      // MAX_USES enforcement removed — keys only lock on HWID mismatch

      // Hash the HWID before storing (privacy + anti-enum)
      const hwidHash = hashString(hwid + appDoc._id);

      if (doc.hwid) {
        if (!safeCompare(doc.hwid, hwidHash)) {
          trackFail(ip, key);
          log(appDoc._id, key, hwid, app_name||appDoc.name, 'AUTH', 'HWID_MISMATCH', ip, 'HWID mismatch — wrong machine');
          return res.json({ success:false, code:'HWID_MISMATCH', message:'HWID mismatch — please contact support' });
        }
      } else {
        keysDb.update({ key }, { $set: { hwid: hwidHash, hwidRaw: hwid } }, {});
        log(appDoc._id, key, hwid, app_name||appDoc.name, 'AUTH', 'HWID_BOUND', ip, `HWID locked`);
      }

      // Reset fail counter on success
      failCounts.delete(ip);

      // Issue a session token so bans/HWID-resets can kick the user immediately
      const sessionToken = genSessionToken();
      activeSessions.set(key, { token: sessionToken, appId: appDoc._id });

      keysDb.update({ key }, { $set:{ lastUsed: new Date().toISOString() } }, {}, () => {
        log(appDoc._id, key, hwid, app_name||appDoc.name, 'AUTH', 'SUCCESS', ip, `Authenticated — HWID locked`);
        res.json({
          success: true, code: 'OK', message: 'Authenticated successfully',
          session_token: sessionToken,
          data: {
            app: appDoc.name, product: doc.product, label: doc.label,
            expires_at: doc.expiresAt||null,
            hwid_locked: true
          }
        });
      });
    });
  });
});

// ── HEARTBEAT (called by client app every ~30s to detect kick) ────────────────
// Client sends: { key, session_token }
// Returns: { valid: true } or { valid: false, code: 'KICKED'|'BANNED'|'EXPIRED' }
app.post('/api/heartbeat', rateLimit, (req, res) => {
  const { key, session_token } = req.body;
  const publicKey = req.headers['x-public-key'] || req.body.public_key;
  if (!key || !session_token) {
    return res.json({ valid: false, code: 'MISSING_PARAMS' });
  }

  // Check session token is still active (not cleared by ban/HWID reset)
  const session = activeSessions.get(key);
  if (!session || session.token !== session_token) {
    return res.json({ valid: false, code: 'KICKED', message: 'Your session has been terminated by an administrator.' });
  }

  // Also re-check the key status in DB
  keysDb.findOne({ key }, (err, doc) => {
    if (!doc) return res.json({ valid: false, code: 'INVALID_KEY' });
    if (doc.status === 'banned') {
      activeSessions.delete(key);
      return res.json({ valid: false, code: 'BANNED', message: 'Your license key has been banned.' });
    }
    if (doc.status === 'frozen') {
      activeSessions.delete(key);
      return res.json({ valid: false, code: 'FROZEN', message: 'Your license key has been temporarily frozen.' });
    }
    if (doc.expiresAt && new Date(doc.expiresAt) < new Date()) {
      activeSessions.delete(key);
      return res.json({ valid: false, code: 'EXPIRED', message: 'Your license key has expired.' });
    }
    return res.json({ valid: true, code: 'OK' });
  });
});

// ── ADMIN APPS ────────────────────────────────────────────────────────────────
app.get('/api/admin/apps', requireAdmin, (req, res) => {
  appsDb.find({}).sort({ createdAt:-1 }).exec((err, docs) => res.json({ success:true, apps:docs }));
});
app.post('/api/admin/apps', requireAdmin, (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.json({ success:false, message:'App name required' });
  const doc = { name, description:description||'', publicKey:genPubKey(), secretKey:genSecKey(), active:true, createdAt:new Date().toISOString() };
  appsDb.insert(doc, (err, newDoc) => {
    if (err) return res.json({ success:false, message:err.message });
    res.json({ success:true, app:newDoc });
  });
});
app.delete('/api/admin/apps/:id', requireAdmin, (req, res) => {
  appsDb.remove({ _id:req.params.id }, {}, () => res.json({ success:true }));
});
app.post('/api/admin/apps/:id/toggle', requireAdmin, (req, res) => {
  appsDb.findOne({ _id:req.params.id }, (err, doc) => {
    if (!doc) return res.json({ success:false, message:'Not found' });
    appsDb.update({ _id:req.params.id }, { $set:{ active:!doc.active } }, {}, () => res.json({ success:true, active:!doc.active }));
  });
});
app.post('/api/admin/apps/:id/rotate', requireAdmin, (req, res) => {
  const newPub=genPubKey(), newSec=genSecKey();
  appsDb.update({ _id:req.params.id }, { $set:{ publicKey:newPub, secretKey:newSec } }, {}, () => res.json({ success:true, publicKey:newPub, secretKey:newSec }));
});

// ── ADMIN KEYS ────────────────────────────────────────────────────────────────
app.get('/api/admin/keys', requireAdmin, (req, res) => {
  const filter = req.query.appId ? { appId:req.query.appId } : {};
  keysDb.find(filter).sort({ createdAt:-1 }).exec((err, docs) => res.json({ success:true, keys:docs }));
});
app.post('/api/admin/generate', requireAdmin, (req, res) => {
  let { count=1, label='', product='Default', max_uses=1, expires_days=null, appId } = req.body;
  if (!appId) return res.json({ success:false, message:'Select an app first' });
  appsDb.findOne({ _id:appId }, (err, appDoc) => {
    if (!appDoc) return res.json({ success:false, message:'App not found' });
    count = Math.min(parseInt(count)||1, 500);
    const docs=[], keys=[];
    for (let i=0; i<count; i++) {
      const key=genKey();
      const expiresAt=expires_days&&parseInt(expires_days)>0?new Date(Date.now()+parseInt(expires_days)*86400000).toISOString():null;
      docs.push({ key, appId, appName:appDoc.name, label, product, status:'active', hwid:null, hwidRaw:null, max_uses:parseInt(max_uses)||1, uses:0, expiresAt, createdAt:new Date().toISOString(), lastUsed:null });
      keys.push(key);
    }
    keysDb.insert(docs, (err) => {
      if (err) return res.json({ success:false, message:err.message });
      res.json({ success:true, keys });
    });
  });
});
app.delete('/api/admin/keys/:key', requireAdmin, (req, res) => {
  keysDb.remove({ key:req.params.key }, {}, () => res.json({ success:true }));
});
app.post('/api/admin/keys/:key/reset-hwid', requireAdmin, (req, res) => {
  // Reset HWID, reset uses to 0, and invalidate any active session (kicks the user)
  keysDb.update({ key:req.params.key }, { $set:{ hwid:null, hwidRaw:null, uses:0 } }, {}, () => {
    activeSessions.delete(req.params.key); // kick active session immediately
    log(null,req.params.key,'—','ADMIN','HWID_RESET','SUCCESS','admin','Admin reset HWID + uses reset to 0 + session kicked');
    res.json({ success:true });
  });
});
app.post('/api/admin/keys/:key/toggle', requireAdmin, (req, res) => {
  keysDb.findOne({ key:req.params.key }, (err, doc) => {
    if (!doc) return res.json({ success:false, message:'Not found' });
    const s=doc.status==='active'?'banned':'active';
    keysDb.update({ key:req.params.key }, { $set:{ status:s } }, {}, () => {
      // If we just banned this key, immediately kill its active session
      if (s === 'banned') {
        activeSessions.delete(req.params.key);
        log(null,req.params.key,'—','ADMIN','BAN','SUCCESS','admin','Admin banned key + session kicked');
      }
      res.json({ success:true, status:s });
    });
  });
});

// ── ADMIN LOGS / BLOCKS ───────────────────────────────────────────────────────
app.get('/api/admin/logs', requireAdmin, (req, res) => {
  const filter={};
  if (req.query.result) filter.result=req.query.result;
  if (req.query.appId)  filter.appId=req.query.appId;
  logsDb.find(filter).sort({ timestamp:-1 }).limit(500).exec((err, docs) => res.json({ success:true, logs:docs }));
});
app.delete('/api/admin/logs', requireAdmin, (req, res) => {
  logsDb.remove({}, { multi:true }, () => res.json({ success:true }));
});
app.get('/api/admin/blocks', requireAdmin, (req, res) => {
  blocksDb.find({}).sort({ blockedAt:-1 }).exec((err, docs) => res.json({ success:true, blocks:docs }));
});
app.delete('/api/admin/blocks/:ip', requireAdmin, (req, res) => {
  blocksDb.remove({ ip:req.params.ip }, {}, () => {
    failCounts.delete(req.params.ip);
    res.json({ success:true });
  });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  keysDb.count({}, (_,total) => keysDb.count({ status:'active' }, (_,active) =>
    keysDb.count({ status:'banned' }, (_,banned) => keysDb.count({ uses:{ $gt:0 } }, (_,used) => {
      const hr=new Date(Date.now()-3600000).toISOString();
      logsDb.count({ timestamp:{ $gt:hr } }, (_,recentAuths) =>
        logsDb.count({ result:'HWID_MISMATCH' }, (_,hwidBlocks) =>
          appsDb.count({}, (_,totalApps) =>
            blocksDb.count({}, (_,blockedIPs) =>
              res.json({ success:true, stats:{ total,active,banned,used,recentAuths,hwidBlocks,totalApps,blockedIPs } })
            )
          )
        )
      );
    }))
  ));
});
app.post('/api/admin/login', (req, res) => {
  adminDb.findOne({ _id:'admin' }, (err, doc) => {
    if (doc && safeCompare(req.body.password, doc.password)) res.json({ success:true, token:doc.password });
    else res.json({ success:false, message:'Wrong password' });
  });
});
app.post('/api/admin/change-password', requireAdmin, (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword||newPassword.length<6) return res.json({ success:false, message:'Min 6 chars' });
  adminDb.update({ _id:'admin' }, { $set:{ password:newPassword } }, {}, () => res.json({ success:true }));
});

// ── FREEZE / UNFREEZE KEY ─────────────────────────────────────────────────────
app.post('/api/admin/keys/:key/freeze', requireAdmin, (req, res) => {
  keysDb.findOne({ key: req.params.key }, (err, doc) => {
    if (!doc) return res.json({ success: false, message: 'Key not found' });
    if (doc.status === 'banned') return res.json({ success: false, message: 'Key is banned, cannot freeze' });
    keysDb.update({ key: req.params.key }, { $set: { status: 'frozen' } }, {}, () => {
      activeSessions.delete(req.params.key);
      log(null, req.params.key, '—', 'ADMIN', 'FREEZE', 'SUCCESS', 'admin', 'Key frozen by admin');
      res.json({ success: true, status: 'frozen' });
    });
  });
});
app.post('/api/admin/keys/:key/unfreeze', requireAdmin, (req, res) => {
  keysDb.findOne({ key: req.params.key }, (err, doc) => {
    if (!doc) return res.json({ success: false, message: 'Key not found' });
    keysDb.update({ key: req.params.key }, { $set: { status: 'active' } }, {}, () => {
      log(null, req.params.key, '—', 'ADMIN', 'UNFREEZE', 'SUCCESS', 'admin', 'Key unfrozen by admin');
      res.json({ success: true, status: 'active' });
    });
  });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, '0.0.0.0', () => console.log('\n  BoostEmpire KeyAuth  |  http://localhost:' + PORT + '\n'));

const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const { randomUUID, createHash, timingSafeEqual } = require('crypto');
const path = require('path');

const app  = express();
const PORT = process.env.PORT || 8080;
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://boostempireapp_db_user:iLtBIzCxsdt8A7Wu@cluster0.3dj2qi7.mongodb.net/?appName=Cluster0';
const DB_NAME   = 'boostempire';

// ── MONGODB CONNECTION ────────────────────────────────────────────────────────
let db;
let keysCol, logsCol, adminCol, appsCol, blocksCol, resellersCol;

async function connectDB() {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  db           = client.db(DB_NAME);
  keysCol      = db.collection('keys');
  logsCol      = db.collection('logs');
  adminCol     = db.collection('admin');
  appsCol      = db.collection('apps');
  blocksCol    = db.collection('blocks');
  resellersCol = db.collection('resellers');

  // Indexes
  await keysCol.createIndex({ key: 1 }, { unique: true });
  await logsCol.createIndex({ timestamp: -1 });
  await appsCol.createIndex({ publicKey: 1 }, { unique: true });
  await blocksCol.createIndex({ ip: 1 }, { unique: true });
  await resellersCol.createIndex({ username: 1 }, { unique: true });

  // Admin setup — seeds on first run, force-updates password on every restart
  const adminDoc = await adminCol.findOne({ _id: 'admin' });
  const ADMIN_HASH = '730aa79139462fd34d63c453a7d8b76da661b1800c6b716ebedd9428f0ce0d7b';
  if (!adminDoc) {
    await adminCol.insertOne({ _id: 'admin', password: ADMIN_HASH, adminToken: null });
  } else if (adminDoc.password !== ADMIN_HASH) {
    // Password changed — update and invalidate any existing session
    await adminCol.updateOne({ _id: 'admin' }, { $set: { password: ADMIN_HASH, adminToken: null } });
    console.log('[auth] Admin password updated on restart');
  } else if (!('adminToken' in adminDoc)) {
    await adminCol.updateOne({ _id: 'admin' }, { $set: { adminToken: null } });
  }

  console.log('[mongodb] Connected to MongoDB Atlas — data is persistent');
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
function genKey()          { return 'BE-' + randomUUID().toUpperCase().replace(/-/g,'').substring(0,20); }
function genSessionToken() { return randomUUID().replace(/-/g,'') + randomUUID().replace(/-/g,''); }
function genPubKey()       { return 'pk_' + randomUUID().replace(/-/g,''); }
function genSecKey()       { return 'sk_' + randomUUID().replace(/-/g,'') + randomUUID().replace(/-/g,''); }
function hashString(s)     { return createHash('sha256').update(s).digest('hex'); }
function safeCompare(a, b) {
  try { return timingSafeEqual(Buffer.from(String(a)), Buffer.from(String(b))); }
  catch { return false; }
}
// Cloudflare IP ranges (used to validate CF-Connecting-IP is trustworthy)
const CF_IP_RANGES = [
  '173.245.48.', '103.21.244.', '103.22.200.', '103.31.4.',
  '141.101.64.', '108.162.192.', '190.93.240.', '188.114.96.',
  '197.234.240.', '198.41.128.', '162.158.', '104.16.',
  '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.',
  '104.23.', '104.24.', '104.25.', '104.26.', '104.27.',
  '172.64.', '172.65.', '172.66.', '172.67.', '172.68.',
  '172.69.', '172.70.', '172.71.',
  '131.0.72.', '2400:cb00:', '2606:4700:', '2803:f800:',
  '2405:b500:', '2405:8100:', '2a06:98c0:', '2c0f:f248:'
];

function isCloudflareIP(ip) {
  return CF_IP_RANGES.some(range => ip.startsWith(range));
}

function getIP(req) {
  // 1. CF-Connecting-IP — most reliable when Cloudflare proxy is ON
  //    Only trust it if the request actually came from a Cloudflare IP
  const cfIP = req.headers['cf-connecting-ip'];
  const socketRaw = (req.socket.remoteAddress || req.connection.remoteAddress || '').replace(/^::ffff:/, '');
  if (cfIP && isCloudflareIP(socketRaw)) return cfIP.trim();

  // 2. x-forwarded-for — used by Render's load balancer and Cloudflare
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();

  // 3. x-real-ip fallback
  const realIP = req.headers['x-real-ip'];
  if (realIP) return realIP.trim();

  // 4. Socket IP fallback
  if (socketRaw === '127.0.0.1' || socketRaw === '::1' || socketRaw === '') {
    const clientReported = (req.body && req.body.real_ip) || '';
    if (clientReported && clientReported !== '127.0.0.1') return clientReported.trim();
  }
  return socketRaw;
}

const https = require('https');
function fetchPublicIP() {
  return new Promise((resolve) => {
    https.get('https://api.ipify.org?format=json', (r) => {
      let d=''; r.on('data', c=>d+=c); r.on('end', ()=>{ try { resolve(JSON.parse(d).ip); } catch { resolve(null); } });
    }).on('error', ()=>resolve(null));
  });
}
async function resolveRealIP(req) {
  const ip = getIP(req);
  if (ip !== '127.0.0.1' && ip !== '::1') return ip;
  return (await fetchPublicIP().catch(()=>null)) || ip;
}

function log(appId, keyVal, hwid, appName, action, result, ip, details='') {
  logsCol.insertOne({
    appId: appId||null, key: keyVal, hwid: hwid||null,
    app_name: appName||'Unknown', action, result,
    ip: ip||null, details, timestamp: new Date().toISOString()
  }).catch(()=>{});
}

// ── RATE LIMITER ──────────────────────────────────────────────────────────────
// ── REPLAY PROTECTION ────────────────────────────────────────────
const nonceCache  = new Map();
const NONCE_TTL   = 5 * 60 * 1000;
const TS_SKEW_MAX = 5 * 60 * 1000;
setInterval(() => { const n=Date.now(); for(const[k,v] of nonceCache) if(n>v) nonceCache.delete(k); }, 60_000);

// ── PER-KEY MISMATCH AUTO-FREEZE ──────────────────────────────────────────
const keyMismatch        = new Map();
const MISMATCH_FREEZE_AT = 8;
const MISMATCH_WINDOW    = 10 * 60 * 1000;
function trackKeyMismatch(key) {
  const now = Date.now();
  const rec = keyMismatch.get(key) || { count: 0, windowStart: now };
  if (now - rec.windowStart > MISMATCH_WINDOW) { rec.count = 1; rec.windowStart = now; }
  else rec.count++;
  keyMismatch.set(key, rec);
  return rec.count;
}

const activeSessions = new Map();
const rateLimitMap   = new Map();
const failCounts     = new Map();
const RATE_WINDOW    = 60 * 1000;
const RATE_MAX       = 30;
const BLOCK_AFTER    = 80;

async function rateLimit(req, res, next) {
  const ip  = getIP(req);
  const now = Date.now();
  const blocked = await blocksCol.findOne({ ip });
  if (blocked) return res.status(429).json({ success:false, code:'IP_BLOCKED', message:'Your IP has been permanently blocked due to abuse' });
  if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
  const hits = rateLimitMap.get(ip).filter(t => now - t < RATE_WINDOW);
  hits.push(now);
  rateLimitMap.set(ip, hits);
  if (hits.length > RATE_MAX) {
    log(null,'—',null,'RATELIMIT','AUTH','RATE_LIMITED',ip,`${hits.length} requests in 60s`);
    return res.status(429).json({ success:false, code:'RATE_LIMITED', message:'Too many requests — slow down', retry_after:60 });
  }
  next();
}
async function trackFail(ip) {
  const count = (failCounts.get(ip)||0)+1;
  failCounts.set(ip, count);
  if (count >= BLOCK_AFTER) {
    const exists = await blocksCol.findOne({ ip });
    if (!exists) await blocksCol.insertOne({ ip, reason:'Auto-blocked: too many failed auth attempts', blockedAt:new Date().toISOString() });
  }
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
async function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.token;
  if (!token) return res.status(401).json({ success:false, message:'Unauthorized' });
  const doc = await adminCol.findOne({ _id: 'admin' });
  if (!doc || !doc.adminToken || !safeCompare(token, doc.adminToken))
    return res.status(401).json({ success:false, message:'Unauthorized' });
  next();
}

async function requireReseller(req, res, next) {
  const token = req.headers['x-reseller-token'] || req.query.token;
  if (!token) return res.status(401).json({ success:false, message:'Unauthorized' });
  const doc = await resellersCol.findOne({ sessionToken: token });
  if (!doc || !doc.active)
    return res.status(401).json({ success:false, message:'Unauthorized or account suspended' });
  req.reseller = doc;
  next();
}

function requireAdminOrReseller(req, res, next) {
  const adminToken    = req.headers['x-admin-token'] || req.query.token;
  const resellerToken = req.headers['x-reseller-token'];
  if (adminToken) return requireAdmin(req, res, next);
  if (resellerToken) return requireReseller(req, res, next);
  return res.status(401).json({ success:false, message:'Unauthorized' });
}

// ── EXPRESS SETUP ─────────────────────────────────────────────────────────────
app.set('trust proxy', true); // Trust Cloudflare + Render proxy headers
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS,PATCH');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-admin-token, x-reseller-token, x-public-key, x-secret-key, x-request-id, x-timestamp, CF-Connecting-IP');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── PUBLIC ────────────────────────────────────────────────────────────────────
app.get('/api/myip', (req, res) => res.json({ ip: getIP(req) }));
app.get('/health',   (req, res) => res.json({ status:'ok', storage:'mongodb' }));
app.get('/',         (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── AUTH ──────────────────────────────────────────────────────────────────────
function authJitter() { return new Promise(r=>setTimeout(r, 80+Math.floor(Math.random()*270))); }

app.post('/api/auth', rateLimit, async (req, res) => {
  await authJitter();
  const { key, hwid, app_name } = req.body;
  const publicKey = req.headers['x-public-key'] || req.body.public_key;
  const ip        = await resolveRealIP(req);

  if (!publicKey||typeof publicKey!=='string'||publicKey.length>200)
    return res.json({ success:false, code:'NO_PUBLIC_KEY', message:'Missing or invalid public API key' });
  if (!key||typeof key!=='string'||key.length>100)
    return res.json({ success:false, code:'NO_KEY', message:'Missing or invalid license key' });
  if (!hwid||typeof hwid!=='string'||hwid.length>200)
    return res.json({ success:false, code:'NO_HWID', message:'Missing or invalid HWID' });
  // Enhanced HWID validation
  const SUSPICIOUS_HWID_PAT = /^(0+|f+|a+|1+|deadbeef|cafebabe|test|fake|crack|bypass|debug|cheat|null|none|unknown|demo|frida|x64dbg|olly|cheatengine|ida|hook|inject|dump|unpack|patch)/i;
  if (hwid.length < 8 || SUSPICIOUS_HWID_PAT.test(hwid)) {
    log(null,key,hwid,app_name,'AUTH','INVALID_HWID',ip,'Suspicious HWID pattern');
    await trackFail(ip);
    return res.json({ success:false, code:'INVALID_HWID', message:'Invalid hardware ID' });
  }
  // Entropy check — low-variety HWIDs are fake
  if (new Set(hwid.replace(/-/g,'')).size < 4) {
    log(null,key,hwid,app_name,'AUTH','INVALID_HWID',ip,'Low-entropy HWID');
    await trackFail(ip);
    return res.json({ success:false, code:'INVALID_HWID', message:'Invalid hardware ID' });
  }
  // Timestamp + nonce replay check
  const clientTs = parseInt(req.headers['x-timestamp'] || req.body.ts || '0', 10);
  if (clientTs && Math.abs(Date.now() - clientTs) > TS_SKEW_MAX) {
    log(null,key,hwid,app_name,'AUTH','REPLAY_REJECTED',ip,'Timestamp expired');
    await trackFail(ip);
    return res.json({ success:false, code:'REPLAY_REJECTED', message:'Request timestamp expired' });
  }
  const nonce = req.headers['x-request-id'] || req.body.nonce;
  if (nonce && typeof nonce === 'string' && nonce.length >= 8 && nonce.length <= 128) {
    if (nonceCache.has(nonce)) {
      log(null,key,hwid,app_name,'AUTH','REPLAY_REJECTED',ip,'Duplicate nonce');
      await trackFail(ip);
      return res.json({ success:false, code:'REPLAY_REJECTED', message:'Duplicate request' });
    }
    nonceCache.set(nonce, Date.now() + NONCE_TTL);
  }

  const appDoc = await appsCol.findOne({ publicKey });
  if (!appDoc) { await trackFail(ip); log(null,key,hwid,app_name,'AUTH','INVALID_PUBLIC_KEY',ip,'Unknown public key'); return res.json({ success:false, code:'INVALID_PUBLIC_KEY', message:'Invalid public API key' }); }
  if (!appDoc.active) return res.json({ success:false, code:'APP_DISABLED', message:'This application is disabled' });

  const doc = await keysCol.findOne({ key, appId: String(appDoc._id) });
  if (!doc) { await trackFail(ip); log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','INVALID_KEY',ip,'Key not found'); return res.json({ success:false, code:'INVALID_KEY', message:'License key not found' }); }
  if (doc.status==='banned') { await trackFail(ip); log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','BANNED',ip); return res.json({ success:false, code:'BANNED', message:'This license key has been banned' }); }
  if (doc.status==='frozen') { log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','FROZEN',ip); return res.json({ success:false, code:'FROZEN', message:'This license key has been temporarily frozen' }); }
  if (doc.expiresAt && new Date(doc.expiresAt)<new Date()) { log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','EXPIRED',ip); return res.json({ success:false, code:'EXPIRED', message:'License key has expired' }); }

  const cpu = req.body.cpu||'';
  if (cpu&&doc.lastCpu&&doc.lastCpu!==cpu) {
    const lastAuthTime = doc.lastUsed ? new Date(doc.lastUsed).getTime() : 0;
    if (Date.now()-lastAuthTime<60000) {
      await keysCol.updateOne({ key }, { $set:{ status:'banned' } });
      activeSessions.delete(key);
      log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','BANNED',ip,'Multi-machine detected');
      return res.json({ success:false, code:'BANNED', message:'License key banned for multi-machine use' });
    }
  }
  if (cpu) await keysCol.updateOne({ key }, { $set:{ lastCpu:cpu } });

  const hwidHash = hashString(hwid+String(appDoc._id));
  if (doc.hwid) {
    if (!safeCompare(doc.hwid, hwidHash)) {
      await trackFail(ip);
      const mCount = trackKeyMismatch(key);
      log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','HWID_MISMATCH',ip,`Attempt #${mCount} | Tried: ${hwid}`);
      if (mCount >= MISMATCH_FREEZE_AT && doc.status === 'active') {
        await keysCol.updateOne({ key }, { $set:{ status:'frozen' } });
        activeSessions.delete(key);
        log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','AUTO_FROZEN',ip,`Auto-frozen after ${mCount} HWID mismatches`);
        keyMismatch.delete(key);
      }
      return res.json({ success:false, code:'HWID_MISMATCH', message:'HWID mismatch — please contact support' });
    }
  } else {
    await keysCol.updateOne({ key }, { $set:{ hwid:hwidHash, hwidRaw:hwid } });
    log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','HWID_BOUND',ip,'HWID locked');
  }

  failCounts.delete(ip);
  const sessionToken = genSessionToken();
  activeSessions.set(key, { token:sessionToken, appId:String(appDoc._id) });
  await keysCol.updateOne({ key }, { $set:{ lastUsed:new Date().toISOString() } });
  log(appDoc._id,key,hwid,app_name||appDoc.name,'AUTH','SUCCESS',ip,'Authenticated');
  res.json({ success:true, code:'OK', message:'Authenticated successfully', session_token:sessionToken, data:{ app:appDoc.name, product:doc.product, label:doc.label, expires_at:doc.expiresAt||null, hwid_locked:true } });
});

// ── HEARTBEAT ─────────────────────────────────────────────────────────────────
app.post('/api/heartbeat', rateLimit, async (req, res) => {
  const { key, session_token } = req.body;
  if (!key||!session_token) return res.json({ valid:false, code:'MISSING_PARAMS' });
  const session = activeSessions.get(key);
  if (!session||session.token!==session_token) return res.json({ valid:false, code:'KICKED', message:'Your session has been terminated by an administrator.' });
  const doc = await keysCol.findOne({ key });
  if (!doc) return res.json({ valid:false, code:'INVALID_KEY' });
  if (doc.status==='banned') { activeSessions.delete(key); return res.json({ valid:false, code:'BANNED', message:'Your license key has been banned.' }); }
  if (doc.status==='frozen') { activeSessions.delete(key); return res.json({ valid:false, code:'FROZEN', message:'Your license key has been temporarily frozen.' }); }
  if (doc.expiresAt&&new Date(doc.expiresAt)<new Date()) { activeSessions.delete(key); return res.json({ valid:false, code:'EXPIRED', message:'Your license key has expired.' }); }
  return res.json({ valid:true, code:'OK' });
});

// ── ADMIN: APPS ───────────────────────────────────────────────────────────────
app.get('/api/admin/apps', requireAdmin, async (req, res) => {
  const apps = await appsCol.find({}).sort({ createdAt:-1 }).toArray();
  res.json({ success:true, apps });
});
app.post('/api/admin/apps', requireAdmin, async (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.json({ success:false, message:'App name required' });
  const doc = { name, description:description||'', publicKey:genPubKey(), secretKey:genSecKey(), active:true, createdAt:new Date().toISOString() };
  const result = await appsCol.insertOne(doc);
  res.json({ success:true, app:{ ...doc, _id:result.insertedId } });
});
app.delete('/api/admin/apps/:id', requireAdmin, async (req, res) => {
  await appsCol.deleteOne({ _id: new ObjectId(req.params.id) });
  res.json({ success:true });
});
app.post('/api/admin/apps/:id/toggle', requireAdmin, async (req, res) => {
  const doc = await appsCol.findOne({ _id: new ObjectId(req.params.id) });
  if (!doc) return res.json({ success:false, message:'Not found' });
  await appsCol.updateOne({ _id: new ObjectId(req.params.id) }, { $set:{ active:!doc.active } });
  res.json({ success:true, active:!doc.active });
});
app.post('/api/admin/apps/:id/rotate', requireAdmin, async (req, res) => {
  const newPub=genPubKey(), newSec=genSecKey();
  await appsCol.updateOne({ _id: new ObjectId(req.params.id) }, { $set:{ publicKey:newPub, secretKey:newSec } });
  res.json({ success:true, publicKey:newPub, secretKey:newSec });
});

// ── ADMIN: KEYS ───────────────────────────────────────────────────────────────
app.get('/api/admin/keys', requireAdmin, async (req, res) => {
  const filter = req.query.appId ? { appId:req.query.appId } : {};
  const keys = await keysCol.find(filter).sort({ createdAt:-1 }).toArray();
  res.json({ success:true, keys });
});
app.post('/api/admin/generate', requireAdmin, async (req, res) => {
  let { count=1, label='', product='Default', max_uses=1, expires_days=null, appId } = req.body;
  if (!appId) return res.json({ success:false, message:'Select an app first' });
  const appDoc = await appsCol.findOne({ _id: new ObjectId(appId) });
  if (!appDoc) return res.json({ success:false, message:'App not found' });
  count = Math.min(parseInt(count)||1, 500);
  const docs=[], keys=[];
  for (let i=0;i<count;i++) {
    const key=genKey();
    const expiresAt=expires_days&&parseInt(expires_days)>0?new Date(Date.now()+parseInt(expires_days)*86400000).toISOString():null;
    docs.push({ key, appId:String(appDoc._id), appName:appDoc.name, label, product, status:'active', hwid:null, hwidRaw:null, max_uses:parseInt(max_uses)||1, uses:0, expiresAt, createdAt:new Date().toISOString(), lastUsed:null, createdBy:'admin' });
    keys.push(key);
  }
  await keysCol.insertMany(docs);
  res.json({ success:true, keys });
});
app.delete('/api/admin/keys/:key', requireAdmin, async (req, res) => {
  await keysCol.deleteOne({ key:req.params.key });
  res.json({ success:true });
});
app.post('/api/admin/keys/:key/reset-hwid', requireAdmin, async (req, res) => {
  await keysCol.updateOne({ key:req.params.key }, { $set:{ hwid:null, hwidRaw:null, uses:0 } });
  activeSessions.delete(req.params.key);
  log(null,req.params.key,'—','ADMIN','HWID_RESET','SUCCESS','admin','Admin reset HWID');
  res.json({ success:true });
});
app.post('/api/admin/keys/:key/toggle', requireAdmin, async (req, res) => {
  const doc = await keysCol.findOne({ key:req.params.key });
  if (!doc) return res.json({ success:false, message:'Not found' });
  const s = doc.status==='active' ? 'banned' : 'active';
  await keysCol.updateOne({ key:req.params.key }, { $set:{ status:s } });
  if (s==='banned') { activeSessions.delete(req.params.key); log(null,req.params.key,'—','ADMIN','BAN','SUCCESS','admin','Admin banned key'); }
  res.json({ success:true, status:s });
});
app.post('/api/admin/keys/:key/freeze', requireAdmin, async (req, res) => {
  const doc = await keysCol.findOne({ key:req.params.key });
  if (!doc) return res.json({ success:false, message:'Key not found' });
  if (doc.status==='banned') return res.json({ success:false, message:'Key is banned, cannot freeze' });
  await keysCol.updateOne({ key:req.params.key }, { $set:{ status:'frozen' } });
  activeSessions.delete(req.params.key);
  log(null,req.params.key,'—','ADMIN','FREEZE','SUCCESS','admin','Key frozen');
  res.json({ success:true, status:'frozen' });
});
app.post('/api/admin/keys/:key/unfreeze', requireAdmin, async (req, res) => {
  const doc = await keysCol.findOne({ key:req.params.key });
  if (!doc) return res.json({ success:false, message:'Key not found' });
  await keysCol.updateOne({ key:req.params.key }, { $set:{ status:'active' } });
  log(null,req.params.key,'—','ADMIN','UNFREEZE','SUCCESS','admin','Key unfrozen');
  res.json({ success:true, status:'active' });
});

// ── ADMIN: LOGS / BLOCKS / STATS ──────────────────────────────────────────────
app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  const filter={};
  if (req.query.result) filter.result=req.query.result;
  if (req.query.appId)  filter.appId=req.query.appId;
  const logs = await logsCol.find(filter).sort({ timestamp:-1 }).limit(500).toArray();
  res.json({ success:true, logs });
});
app.delete('/api/admin/logs', requireAdmin, async (req, res) => {
  await logsCol.deleteMany({});
  res.json({ success:true });
});
app.get('/api/admin/blocks', requireAdmin, async (req, res) => {
  const blocks = await blocksCol.find({}).sort({ blockedAt:-1 }).toArray();
  res.json({ success:true, blocks });
});
app.delete('/api/admin/blocks/:ip', requireAdmin, async (req, res) => {
  await blocksCol.deleteOne({ ip:req.params.ip });
  failCounts.delete(req.params.ip);
  res.json({ success:true });
});
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const hr = new Date(Date.now()-3600000).toISOString();
  const [total, active, banned, used, recentAuths, hwidBlocks, totalApps, blockedIPs, totalResellers] = await Promise.all([
    keysCol.countDocuments({}),
    keysCol.countDocuments({ status:'active' }),
    keysCol.countDocuments({ status:'banned' }),
    keysCol.countDocuments({ uses:{ $gt:0 } }),
    logsCol.countDocuments({ timestamp:{ $gt:hr } }),
    logsCol.countDocuments({ result:'HWID_MISMATCH' }),
    appsCol.countDocuments({}),
    blocksCol.countDocuments({}),
    resellersCol.countDocuments({}),
  ]);
  res.json({ success:true, stats:{ total,active,banned,used,recentAuths,hwidBlocks,totalApps,blockedIPs,totalResellers } });
});
// Admin login brute-force tracking
const adminLoginFails = new Map(); // ip -> { count, lastFail }
const ADMIN_LOCKOUT_FAILS = 10;
const ADMIN_LOCKOUT_MS    = 15 * 60 * 1000; // 15 min

// ── ADMIN: HWID MISMATCHES ────────────────────────────────────────────────────
app.get('/api/admin/hwid-mismatches', requireAdmin, async (req, res) => {
  const mismatches = await logsCol.find({ result:'HWID_MISMATCH' }).sort({ timestamp:-1 }).limit(400).toArray();
  const enriched = await Promise.all(mismatches.map(async l => {
    const keyDoc = await keysCol.findOne({ key: l.key });
    return {
      ...l,
      keyStatus : keyDoc ? keyDoc.status    : 'deleted',
      keyLabel  : keyDoc ? (keyDoc.label  || '') : '',
      hwidBound : keyDoc ? (keyDoc.hwidRaw || '') : '',
      appName   : l.app_name || 'Unknown',
    };
  }));
  res.json({ success:true, mismatches:enriched });
});

app.post('/api/admin/login', async (req, res) => {
  const ip = getIP(req);
  const now = Date.now();
  const failRec = adminLoginFails.get(ip) || { count: 0, lastFail: 0 };
  // Lockout check
  if (failRec.count >= ADMIN_LOCKOUT_FAILS && now - failRec.lastFail < ADMIN_LOCKOUT_MS) {
    return res.status(429).json({ success: false, message: 'Too many failed attempts — wait 15 minutes' });
  }
  await authJitter(); // same timing jitter as auth endpoint
  const doc = await adminCol.findOne({ _id: 'admin' });
  const match = doc && safeCompare(hashString(req.body.password), doc.password);
  if (match) {
    adminLoginFails.delete(ip);
    const token = genSessionToken(); // brand new random token, NOT the password
    await adminCol.updateOne({ _id: 'admin' }, { $set: { adminToken: token } });
    res.json({ success: true, token });
  } else {
    failRec.count++;
    failRec.lastFail = now;
    adminLoginFails.set(ip, failRec);
    res.json({ success: false, message: 'Wrong password' });
  }
});
app.post('/api/admin/change-password', requireAdmin, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.json({ success:false, message:'Min 6 chars' });
  const newToken = genSessionToken(); // rotate session token on password change
  await adminCol.updateOne({ _id:'admin' }, {
    $set: { password: hashString(newPassword), adminToken: newToken }
  });
  res.json({ success:true, token: newToken }); // return new token so UI stays logged in
});

// ── ADMIN: RESELLERS ──────────────────────────────────────────────────────────
const DEFAULT_PERMISSIONS = { viewKeys:false, viewHWID:false, viewIP:false, viewLogs:false, viewBlocks:false, generateKeys:false, banKeys:false, freezeKeys:false, resetHWID:false, deleteKeys:false, viewStats:false };

app.get('/api/admin/resellers', requireAdmin, async (req, res) => {
  const docs = await resellersCol.find({}).sort({ createdAt:-1 }).toArray();
  const safe = docs.map(({ password, ...r }) => r);
  res.json({ success:true, resellers:safe });
});
app.post('/api/admin/resellers', requireAdmin, async (req, res) => {
  const { username, password, displayName, keyQuota, permissions, notes } = req.body;
  if (!username||!password) return res.json({ success:false, message:'Username and password required' });
  if (password.length<6) return res.json({ success:false, message:'Password must be at least 6 characters' });
  const perms = Object.assign({}, DEFAULT_PERMISSIONS, permissions||{});
  const doc = { username:username.toLowerCase().trim(), password:hashString(password), displayName:displayName||username, active:true, keyQuota:parseInt(keyQuota)||0, keysGenerated:0, permissions:perms, notes:notes||'', sessionToken:null, createdAt:new Date().toISOString(), lastLogin:null };
  try {
    const result = await resellersCol.insertOne(doc);
    const { password:p, ...safe } = { ...doc, _id:result.insertedId };
    res.json({ success:true, reseller:safe });
  } catch(e) {
    res.json({ success:false, message: e.message.includes('duplicate') ? 'Username already exists' : e.message });
  }
});
app.patch('/api/admin/resellers/:id', requireAdmin, async (req, res) => {
  const { displayName, password, keyQuota, permissions, notes, active } = req.body;
  const update = {};
  if (displayName !== undefined) update.displayName = displayName;
  if (notes      !== undefined) update.notes = notes;
  if (keyQuota   !== undefined) update.keyQuota = parseInt(keyQuota)||0;
  if (active     !== undefined) update.active = !!active;
  if (permissions !== undefined) update.permissions = Object.assign({}, DEFAULT_PERMISSIONS, permissions);
  if (password && password.length>=6) update.password = hashString(password);
  const result = await resellersCol.updateOne({ _id:new ObjectId(req.params.id) }, { $set:update });
  if (!result.matchedCount) return res.json({ success:false, message:'Reseller not found' });
  res.json({ success:true });
});
app.delete('/api/admin/resellers/:id', requireAdmin, async (req, res) => {
  await resellersCol.deleteOne({ _id:new ObjectId(req.params.id) });
  res.json({ success:true });
});
app.post('/api/admin/resellers/:id/toggle', requireAdmin, async (req, res) => {
  const doc = await resellersCol.findOne({ _id:new ObjectId(req.params.id) });
  if (!doc) return res.json({ success:false, message:'Not found' });
  await resellersCol.updateOne({ _id:new ObjectId(req.params.id) }, { $set:{ active:!doc.active } });
  res.json({ success:true, active:!doc.active });
});

// ── RESELLER AUTH ─────────────────────────────────────────────────────────────
app.post('/api/reseller/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username||!password) return res.json({ success:false, message:'Username and password required' });
  const doc = await resellersCol.findOne({ username:username.toLowerCase().trim() });
  if (!doc||!safeCompare(hashString(password), doc.password)) return res.json({ success:false, message:'Invalid credentials' });
  if (!doc.active) return res.json({ success:false, message:'Your reseller account is suspended.' });
  const token = genSessionToken();
  await resellersCol.updateOne({ _id:doc._id }, { $set:{ sessionToken:token, lastLogin:new Date().toISOString() } });
  res.json({ success:true, token, reseller:{ username:doc.username, displayName:doc.displayName, permissions:doc.permissions, keyQuota:doc.keyQuota, keysGenerated:doc.keysGenerated } });
});
app.post('/api/reseller/logout', requireReseller, async (req, res) => {
  await resellersCol.updateOne({ _id:req.reseller._id }, { $set:{ sessionToken:null } });
  res.json({ success:true });
});

// ── RESELLER: STATS ───────────────────────────────────────────────────────────
app.get('/api/reseller/stats', requireReseller, async (req, res) => {
  const r = req.reseller;
  const [totalKeys, activeKeys, bannedKeys] = await Promise.all([
    keysCol.countDocuments({ createdBy:r.username }),
    keysCol.countDocuments({ createdBy:r.username, status:'active' }),
    keysCol.countDocuments({ createdBy:r.username, status:'banned' }),
  ]);
  res.json({ success:true, stats:{ totalKeys, activeKeys, bannedKeys, keyQuota:r.keyQuota, keysGenerated:r.keysGenerated, slotsLeft:r.keyQuota>0?Math.max(0,r.keyQuota-r.keysGenerated):null } });
});

// ── RESELLER: KEYS ────────────────────────────────────────────────────────────
app.get('/api/reseller/keys', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.viewKeys) return res.status(403).json({ success:false, message:'Access denied' });
  const filter = { createdBy:req.reseller.username };
  if (req.query.appId) filter.appId = req.query.appId;
  const docs = await keysCol.find(filter).sort({ createdAt:-1 }).toArray();
  const perm = req.reseller.permissions;
  const masked = docs.map(k => { const out={...k}; if (!perm.viewHWID) { delete out.hwid; delete out.hwidRaw; } return out; });
  res.json({ success:true, keys:masked });
});
app.post('/api/reseller/generate', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.generateKeys) return res.status(403).json({ success:false, message:'Access denied' });
  let { count=1, label='', product='Default', max_uses=1, expires_days=null, appId } = req.body;
  if (!appId) return res.json({ success:false, message:'Select an app first' });
  count = Math.min(parseInt(count)||1, 100);
  if (req.reseller.keyQuota > 0) {
    const remaining = req.reseller.keyQuota - req.reseller.keysGenerated;
    if (count > remaining) return res.json({ success:false, message:`Quota exceeded. You have ${remaining} key slot(s) remaining.` });
  }
  const appDoc = await appsCol.findOne({ _id:new ObjectId(appId) });
  if (!appDoc) return res.json({ success:false, message:'App not found' });
  const docs=[], keys=[];
  for (let i=0;i<count;i++) {
    const key=genKey();
    const expiresAt=expires_days&&parseInt(expires_days)>0?new Date(Date.now()+parseInt(expires_days)*86400000).toISOString():null;
    docs.push({ key, appId:String(appDoc._id), appName:appDoc.name, label, product, status:'active', hwid:null, hwidRaw:null, max_uses:parseInt(max_uses)||1, uses:0, expiresAt, createdAt:new Date().toISOString(), lastUsed:null, createdBy:req.reseller.username });
    keys.push(key);
  }
  await keysCol.insertMany(docs);
  await resellersCol.updateOne({ _id:req.reseller._id }, { $inc:{ keysGenerated:count } });
  res.json({ success:true, keys });
});

// ── RESELLER: KEY ACTIONS ─────────────────────────────────────────────────────
async function resellerOwnsKey(reseller, key) {
  return keysCol.findOne({ key, createdBy:reseller.username });
}
app.post('/api/reseller/keys/:key/toggle', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.banKeys) return res.status(403).json({ success:false, message:'Access denied' });
  const doc = await resellerOwnsKey(req.reseller, req.params.key);
  if (!doc) return res.json({ success:false, message:'Key not found or not yours' });
  const s = doc.status==='active'?'banned':'active';
  await keysCol.updateOne({ key:req.params.key }, { $set:{ status:s } });
  if (s==='banned') activeSessions.delete(req.params.key);
  res.json({ success:true, status:s });
});
app.post('/api/reseller/keys/:key/freeze', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.freezeKeys) return res.status(403).json({ success:false, message:'Access denied' });
  const doc = await resellerOwnsKey(req.reseller, req.params.key);
  if (!doc) return res.json({ success:false, message:'Key not found or not yours' });
  if (doc.status==='banned') return res.json({ success:false, message:'Key is banned, cannot freeze' });
  await keysCol.updateOne({ key:req.params.key }, { $set:{ status:'frozen' } });
  activeSessions.delete(req.params.key);
  res.json({ success:true, status:'frozen' });
});
app.post('/api/reseller/keys/:key/unfreeze', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.freezeKeys) return res.status(403).json({ success:false, message:'Access denied' });
  const doc = await resellerOwnsKey(req.reseller, req.params.key);
  if (!doc) return res.json({ success:false, message:'Key not found or not yours' });
  await keysCol.updateOne({ key:req.params.key }, { $set:{ status:'active' } });
  res.json({ success:true, status:'active' });
});
app.post('/api/reseller/keys/:key/reset-hwid', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.resetHWID) return res.status(403).json({ success:false, message:'Access denied' });
  const doc = await resellerOwnsKey(req.reseller, req.params.key);
  if (!doc) return res.json({ success:false, message:'Key not found or not yours' });
  await keysCol.updateOne({ key:req.params.key }, { $set:{ hwid:null, hwidRaw:null, uses:0 } });
  activeSessions.delete(req.params.key);
  res.json({ success:true });
});
app.delete('/api/reseller/keys/:key', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.deleteKeys) return res.status(403).json({ success:false, message:'Access denied' });
  const doc = await resellerOwnsKey(req.reseller, req.params.key);
  if (!doc) return res.json({ success:false, message:'Key not found or not yours' });
  await keysCol.deleteOne({ key:req.params.key });
  res.json({ success:true });
});

// ── RESELLER: LOGS / BLOCKS / APPS ───────────────────────────────────────────
app.get('/api/reseller/logs', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.viewLogs) return res.status(403).json({ success:false, message:'Access denied' });
  const myKeys = await keysCol.find({ createdBy:req.reseller.username }, { projection:{ key:1 } }).toArray();
  const myKeySet = new Set(myKeys.map(k=>k.key));
  const filter = {};
  if (req.query.result) filter.result = req.query.result;
  const docs = await logsCol.find(filter).sort({ timestamp:-1 }).limit(300).toArray();
  const perm = req.reseller.permissions;
  const masked = docs.filter(l=>myKeySet.has(l.key)).map(l => {
    const out={...l};
    if (!perm.viewIP) out.ip='—';
    if (!perm.viewHWID) out.hwid='—';
    return out;
  });
  res.json({ success:true, logs:masked });
});
app.get('/api/reseller/blocks', requireReseller, async (req, res) => {
  if (!req.reseller.permissions.viewBlocks) return res.status(403).json({ success:false, message:'Access denied' });
  const docs = await blocksCol.find({}).sort({ blockedAt:-1 }).toArray();
  const perm = req.reseller.permissions;
  const masked = docs.map(b => perm.viewIP ? b : { ...b, ip:'—' });
  res.json({ success:true, blocks:masked });
});
app.get('/api/reseller/apps', requireReseller, async (req, res) => {
  const docs = await appsCol.find({ active:true }).sort({ createdAt:-1 }).toArray();
  const safe = docs.map(({ secretKey, ...a }) => a);
  res.json({ success:true, apps:safe });
});

// ── BACKUP / RESTORE ──────────────────────────────────────────────────────────
app.get('/api/admin/backup', requireAdmin, async (req, res) => {
  const [apps, keys, resellers, blocks, admin] = await Promise.all([
    appsCol.find({}).toArray(),
    keysCol.find({}).toArray(),
    resellersCol.find({}).toArray(),
    blocksCol.find({}).toArray(),
    adminCol.find({}).toArray(),
  ]);
  res.setHeader('Content-Disposition', `attachment; filename="backup-${Date.now()}.json"`);
  res.json({ version:2, exportedAt:new Date().toISOString(), apps, keys, resellers, blocks, admin });
});
app.post('/api/admin/restore', requireAdmin, async (req, res) => {
  const { apps=[], keys=[], resellers=[], blocks=[], admin=[] } = req.body;
  async function insertNew(col, docs) {
    let inserted=0, skipped=0;
    for (const doc of docs) {
      const exists = await col.findOne({ _id:doc._id });
      if (exists) { skipped++; continue; }
      try { await col.insertOne(doc); inserted++; } catch {}
    }
    return { inserted, skipped };
  }
  const [a,k,r,b,ad] = await Promise.all([
    insertNew(appsCol, apps), insertNew(keysCol, keys),
    insertNew(resellersCol, resellers), insertNew(blocksCol, blocks),
    insertNew(adminCol, admin),
  ]);
  res.json({ success:true, restored:{ apps:a, keys:k, resellers:r, blocks:b, admin:ad } });
});

// ── START ─────────────────────────────────────────────────────────────────────
connectDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n  BoostEmpire KeyAuth  |  http://localhost:${PORT}`);
    console.log(`  Storage: MongoDB Atlas (persistent)\n`);
  });
}).catch(err => {
  console.error('[FATAL] MongoDB connection failed:', err.message);
  process.exit(1);
});

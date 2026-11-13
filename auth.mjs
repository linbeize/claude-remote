// 认证：用户名 + 密码（scrypt 哈希）+ 可选 TOTP 两步验证 + 持久化会话 + 登录限速
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const DIR = path.dirname(fileURLToPath(import.meta.url));
export const AUTH_FILE = path.join(DIR, 'data', 'auth.json');
const SESSIONS_FILE = path.join(DIR, 'data', 'sessions.json');
export const SESSION_TTL_MS = 7 * 24 * 3600 * 1000; // 登录有效期 7 天

// ---------- 密码 ----------
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32, SCRYPT);
  return { salt: salt.toString('base64'), hash: hash.toString('base64') };
}
function verifyPassword(password, rec) {
  const hash = crypto.scryptSync(password, Buffer.from(rec.salt, 'base64'), 32, SCRYPT);
  return crypto.timingSafeEqual(hash, Buffer.from(rec.hash, 'base64'));
}
// 用户名不存在时也算一次哈希，避免通过响应时间猜用户名
const DUMMY = hashPassword(crypto.randomBytes(16).toString('hex'));

// ---------- TOTP（RFC 6238，兼容 Google Authenticator / Microsoft Authenticator 等） ----------
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(str) {
  let bits = 0, value = 0; const out = [];
  for (const ch of str.replace(/=+$/, '').toUpperCase()) {
    const i = B32.indexOf(ch);
    if (i < 0) continue;
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
function hotp(secret, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const off = h[h.length - 1] & 15;
  const code = (h.readUInt32BE(off) & 0x7fffffff) % 1_000_000;
  return String(code).padStart(6, '0');
}
// 返回匹配的时间步（用于防重放），不匹配返回 -1
export function verifyTotp(secret, code, now = Date.now()) {
  const step = Math.floor(now / 30_000);
  code = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(code)) return -1;
  for (const d of [-1, 0, 1]) {
    const expect = hotp(secret, step + d);
    if (crypto.timingSafeEqual(Buffer.from(expect), Buffer.from(code))) return step + d;
  }
  return -1;
}

// ---------- 账号文件 ----------
export function loadAuth() {
  try { return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8')); } catch { return null; }
}
export function saveAuth(auth) {
  fs.mkdirSync(path.dirname(AUTH_FILE), { recursive: true });
  fs.writeFileSync(AUTH_FILE, JSON.stringify(auth, null, 2), { mode: 0o600 });
}

// ---------- 会话（只存 sid 的哈希，泄露 sessions.json 也拿不到可用 cookie） ----------
const sessions = new Map(); // sha256(sid) -> { exp, ua, ip, created }
const sidKey = (sid) => crypto.createHash('sha256').update(sid).digest('hex');
try {
  const saved = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
  for (const [k, v] of Object.entries(saved)) if (v.exp > Date.now()) sessions.set(k, v);
} catch { /* 没有就算了 */ }
function persistSessions() {
  fs.mkdirSync(path.dirname(SESSIONS_FILE), { recursive: true });
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(Object.fromEntries(sessions)), { mode: 0o600 });
}
export function createSession(meta) {
  const sid = crypto.randomBytes(32).toString('base64url');
  sessions.set(sidKey(sid), { ...meta, created: Date.now(), exp: Date.now() + SESSION_TTL_MS });
  persistSessions();
  return sid;
}
export function checkSession(sid) {
  if (!sid) return false;
  const s = sessions.get(sidKey(sid));
  if (!s) return false;
  if (s.exp < Date.now()) { sessions.delete(sidKey(sid)); persistSessions(); return false; }
  return true;
}
export function destroySession(sid) {
  if (sid && sessions.delete(sidKey(sid))) persistSessions();
}
export function destroyAllSessions() { sessions.clear(); persistSessions(); }

// ---------- 登录限速 ----------
// 单个 IP：15 分钟内失败 5 次锁 15 分钟；全局：15 分钟内失败 30 次，所有登录暂停 15 分钟（防分布式爆破）
const WINDOW = 15 * 60_000;
const ipFails = new Map();
let globalFails = [];
let globalLockUntil = 0;
export function lockedFor(ip) {
  const now = Date.now();
  if (globalLockUntil > now) return globalLockUntil - now;
  const rec = ipFails.get(ip);
  if (rec?.lockUntil > now) return rec.lockUntil - now;
  return 0;
}
function recordFail(ip) {
  const now = Date.now();
  const rec = ipFails.get(ip) || { times: [], lockUntil: 0 };
  rec.times = rec.times.filter((t) => now - t < WINDOW);
  rec.times.push(now);
  if (rec.times.length >= 5) rec.lockUntil = now + WINDOW;
  ipFails.set(ip, rec);
  globalFails = globalFails.filter((t) => now - t < WINDOW);
  globalFails.push(now);
  if (globalFails.length >= 30) globalLockUntil = now + WINDOW;
}

// 校验登录，返回 { ok } 或 { ok:false, error }
export function attemptLogin(auth, ip, { username, password, code }) {
  const wait = lockedFor(ip);
  if (wait) return { ok: false, status: 429, error: `尝试次数太多，请 ${Math.ceil(wait / 60000)} 分钟后再试` };
  const userOk = typeof username === 'string' && username === auth.username;
  const passOk = verifyPassword(String(password || ''), userOk ? auth : DUMMY) && userOk;
  let totpOk = true;
  let step = -1;
  if (auth.totpSecret) {
    step = verifyTotp(auth.totpSecret, code);
    totpOk = step >= 0 && step > (auth.lastTotpStep || 0); // 同一个验证码不能用两次
  }
  if (!passOk || !totpOk) {
    recordFail(ip);
    return { ok: false, status: 401, error: auth.totpSecret ? '用户名、密码或验证码不对' : '用户名或密码不对' };
  }
  if (auth.totpSecret) { auth.lastTotpStep = step; saveAuth(auth); }
  ipFails.delete(ip);
  return { ok: true };
}

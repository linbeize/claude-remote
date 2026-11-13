// Claude Remote — 一个网页远程访问 Claude Code 的小服务
// 结构：浏览器 <-WebSocket-> 本服务 <-Agent SDK-> Claude Code
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { WebSocketServer } from 'ws';
import { query, listSessions, getSessionMessages } from '@anthropic-ai/claude-agent-sdk';
import { loadAuth, attemptLogin, createSession, checkSession, destroySession, SESSION_TTL_MS } from './auth.mjs';
import { loadCert, needsRenewal, issueCert, handleChallenge, loadAccount } from './tls.mjs';
import { getLimits, getStats, invalidateLimits } from './usage.mjs';
import { initQQBot, getQQStatus, qqAction, stopQQBot, qqRunOptions } from './qqbot.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------- 配置（都可以用环境变量覆盖） ----------
const PORT = Number(process.env.PORT || 3080);
// 默认只监听本机。公网访问推荐用 Cloudflare Tunnel 之类的反向代理接到这个端口，由它提供 HTTPS
const HOST = process.env.HOST || '127.0.0.1';
const WORKDIR = path.resolve(process.env.WORKDIR || process.cwd()); // Claude 干活的目录
const MODEL = process.env.MODEL || undefined; // 不设就用 Claude Code 的默认模型
// 在反向代理（Cloudflare Tunnel / Nginx）后面时设为 1，才会信任它传来的真实 IP 和 https 标记
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
// 设置了域名就直接对公网提供 HTTPS（443）+ 80 端口跳转和证书验证
const TLS_DOMAIN = process.env.TLS_DOMAIN || '';
const HTTPS_PORT = Number(process.env.HTTPS_PORT || 443);
const HTTP_PORT = Number(process.env.HTTP_PORT || 80);
const TLS_BIND = process.env.TLS_BIND || '0.0.0.0'; // HTTPS 模式监听的地址
const COOKIE = 'cr_session';

// 由 run.mjs 守护启动时：守护进程没了（比如计划任务被停止）就跟着退出，免得留下一个占着端口的孤儿进程
const SUPERVISOR_PID = Number(process.env.CR_SUPERVISOR_PID || 0);
if (SUPERVISOR_PID) setInterval(() => { try { process.kill(SUPERVISOR_PID, 0); } catch { process.exit(0); } }, 5000).unref();

const auth = loadAuth();
if (!auth) {
  console.error('\n还没有设置登录账号。请先运行：npm run setup\n');
  process.exit(78); // 78 = 配置不完整，守护进程看到它就不会反复重启
}
let tlsCert = null;
if (TLS_DOMAIN) {
  tlsCert = loadCert(TLS_DOMAIN);
  if (!tlsCert) {
    console.error(`\n还没有 ${TLS_DOMAIN} 的证书。请先运行：npm run cert\n`);
    process.exit(78);
  }
}

// ---------- 小工具 ----------
function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
const sidOf = (req) => parseCookies(req.headers.cookie)[COOKIE];
const isAuthed = (req) => checkSession(sidOf(req));
function clientIp(req) {
  if (TRUST_PROXY) {
    const h = req.headers['cf-connecting-ip'] || String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (h) return h;
  }
  return req.socket.remoteAddress;
}
const isSecure = (req) => Boolean(TLS_DOMAIN) || (TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https');
// HTTPS 模式下只接受用这个域名访问（用 IP 直接扫过来的请求一律拒绝）
const hostOk = (req) => !TLS_DOMAIN || String(req.headers.host || '').replace(/:\d+$/, '').toLowerCase() === TLS_DOMAIN.toLowerCase();
// 防 CSRF：带 Origin 的请求必须同源
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}
function readBody(req, limit = 4096) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > limit) { reject(new Error('too large')); req.destroy(); }
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}
function json(res, status, obj, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(JSON.stringify(obj));
}
function redirect(res, to) { res.writeHead(302, { Location: to }); res.end(); }
// 页面带上 CSP，脚本只允许本页带 nonce 的那一段
function serveHtml(res, file) {
  const nonce = crypto.randomBytes(16).toString('base64');
  const html = fs.readFileSync(path.join(__dirname, 'public', file), 'utf8').replaceAll('<script>', `<script nonce="${nonce}">`);
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
  });
  res.end(html);
}

// ---------- HTTP ----------
async function handle(req, res) {
  if (!hostOk(req)) { res.writeHead(421); return res.end('misdirected request'); }
  // 请求路径只当路径解析：'//xxx' 这类会被 new URL 当成“协议相对地址”去解析主机名，非法时直接抛错
  let url;
  try {
    if (!req.url.startsWith('/')) throw new Error('bad path');
    url = new URL('http://x' + req.url);
  } catch {
    res.writeHead(400); return res.end('bad request');
  }
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  if (isSecure(req)) res.setHeader('Strict-Transport-Security', 'max-age=31536000');

  try {
    if (req.method === 'GET' && url.pathname === '/') {
      return isAuthed(req) ? serveHtml(res, 'index.html') : redirect(res, '/login');
    }
    if (req.method === 'GET' && url.pathname === '/login') {
      return isAuthed(req) ? redirect(res, '/') : serveHtml(res, 'login.html');
    }
    if (req.method === 'GET' && url.pathname === '/api/me') {
      const authed = isAuthed(req);
      return json(res, 200, { authed, workdir: authed ? WORKDIR : undefined, username: authed ? auth.username : undefined });
    }
    if (req.method === 'GET' && url.pathname === '/api/login-config') {
      return json(res, 200, { totp: Boolean(auth.totpSecret), secure: isSecure(req) || ['127.0.0.1', '::1'].includes(req.socket.remoteAddress) && !TRUST_PROXY });
    }
    if (req.method === 'POST' && url.pathname === '/api/login') {
      if (!sameOrigin(req) || !String(req.headers['content-type']).startsWith('application/json')) {
        return json(res, 403, { error: '请求来源不对' });
      }
      let body = {};
      try { body = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: '请求格式不对' }); }
      const ip = clientIp(req);
      const r = attemptLogin(auth, ip, body);
      if (!r.ok) {
        console.log(`[login] 失败 ip=${ip} user=${String(body.username).slice(0, 40)}`);
        return json(res, r.status, { error: r.error });
      }
      const sid = createSession({ ip, ua: String(req.headers['user-agent'] || '').slice(0, 200) });
      console.log(`[login] 成功 ip=${ip}`);
      const secure = isSecure(req) ? '; Secure' : '';
      return json(res, 200, { ok: true }, {
        'Set-Cookie': `${COOKIE}=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}${secure}`,
      });
    }
    if (req.method === 'POST' && url.pathname === '/api/logout') {
      if (!sameOrigin(req)) return json(res, 403, { error: '请求来源不对' });
      const sid = sidOf(req);
      destroySession(sid);
      for (const ws of wss.clients) if (ws.sid === sid) ws.close(4001, 'logged out');
      return json(res, 200, { ok: true }, { 'Set-Cookie': `${COOKIE}=; Path=/; Max-Age=0` });
    }
    // ---------- 用量：套餐限额 / token 统计 ----------
    if (req.method === 'GET' && (url.pathname === '/api/limits' || url.pathname === '/api/stats')) {
      if (!isAuthed(req)) return json(res, 401, { error: '请先登录' });
      if (url.pathname === '/api/limits') {
        if (url.searchParams.get('refresh') === '1') invalidateLimits();
        return json(res, 200, await getLimits(WORKDIR));
      }
      const days = Math.max(0, Math.min(3650, Number(url.searchParams.get('days') ?? 30) || 0));
      return json(res, 200, await getStats(days));
    }
    // ---------- QQ 机器人设置 ----------
    if (url.pathname === '/api/qqbot') {
      if (!isAuthed(req)) return json(res, 401, { error: '请先登录' });
      if (req.method === 'GET') return json(res, 200, getQQStatus());
      if (req.method === 'POST') {
        if (!sameOrigin(req) || !String(req.headers['content-type']).startsWith('application/json')) return json(res, 403, { error: '请求来源不对' });
        let body;
        try { body = JSON.parse(await readBody(req, 8192)); } catch { return json(res, 400, { error: '请求格式不对' }); }
        try { return json(res, 200, await qqAction(body || {})); }
        catch (err) { return json(res, 400, { error: String(err?.message || err) }); }
      }
      return json(res, 405, { error: '不支持的请求' });
    }
    // ---------- 文件：列目录 / 下载 / 上传（都要求已登录，且只能访问工作区里的路径） ----------
    if (['/api/files', '/api/download', '/api/upload', '/api/fs', '/api/preview', '/api/raw'].includes(url.pathname)) {
      if (!isAuthed(req)) return json(res, 401, { error: '请先登录' });
      if (req.method === 'GET' && url.pathname === '/api/preview') return previewFile(res, url.searchParams.get('path'));
      if (req.method === 'GET' && url.pathname === '/api/raw') return rawImage(res, url.searchParams.get('path'));
      if (req.method === 'POST' && url.pathname === '/api/fs') {
        if (!sameOrigin(req) || !String(req.headers['content-type']).startsWith('application/json')) return json(res, 403, { error: '请求来源不对' });
        let body = {};
        try { body = JSON.parse(await readBody(req, 8192)); } catch { return json(res, 400, { error: '请求格式不对' }); }
        return fileOp(res, body);
      }
      if (req.method === 'GET' && url.pathname === '/api/files') return listFiles(res, url.searchParams.get('path'));
      if (req.method === 'GET' && url.pathname === '/api/download') return downloadFile(req, res, url.searchParams.get('path'));
      if (req.method === 'POST' && url.pathname === '/api/upload') {
        if (!sameOrigin(req)) return json(res, 403, { error: '请求来源不对' });
        return uploadFile(req, res, url.searchParams.get('dir'), url.searchParams.get('name'));
      }
    }
    res.writeHead(404); res.end('not found');
  } catch (err) {
    console.error(err);
    if (!res.headersSent) json(res, 500, { error: '服务器出错' });
  }
}

// ---------- 文件操作 ----------
const MAX_UPLOAD = 512 * 1024 * 1024; // 单个文件最大 512MB

function listFiles(res, p) {
  const dir = path.resolve(p || WORKDIR);
  if (!insideWorkspace(dir)) return json(res, 403, { error: '只能浏览工作区里的目录' });
  if (!isDir(dir)) return json(res, 404, { error: '目录不存在' });
  const entries = [];
  for (const d of fs.readdirSync(dir, { withFileTypes: true }).slice(0, 3000)) {
    const full = path.join(dir, d.name);
    let st = null;
    try { st = fs.statSync(full); } catch { continue; }
    entries.push({ name: d.name, dir: st.isDirectory(), size: st.isDirectory() ? null : st.size, mtime: st.mtimeMs });
  }
  entries.sort((a, b) => (b.dir - a.dir) || a.name.localeCompare(b.name));
  const root = [...workspaces].find((r) => insideWorkspaceOf(r, dir));
  const parent = root && path.resolve(dir) !== root ? path.dirname(dir) : null;
  return json(res, 200, { path: dir, root, parent, entries });
}
function insideWorkspaceOf(root, p) {
  const rel = path.relative(root, path.resolve(p));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function downloadFile(req, res, p) {
  if (!p) return json(res, 400, { error: '缺少 path' });
  const file = path.resolve(p);
  if (!insideWorkspace(file)) return json(res, 403, { error: '只能下载工作区里的文件' });
  let st;
  try { st = fs.statSync(file); } catch { return json(res, 404, { error: '文件不存在' }); }
  if (!st.isFile()) return json(res, 400, { error: '不是文件' });
  const name = path.basename(file);
  res.writeHead(200, {
    // 一律当附件下载，不在浏览器里直接打开，避免上传的 html 之类被执行
    'Content-Type': 'application/octet-stream',
    'Content-Length': st.size,
    'Content-Disposition': `attachment; filename="${name.replace(/[^\x20-\x7e]|["\\]/g, '_')}"; filename*=UTF-8''${encodeURIComponent(name)}`,
    'Cache-Control': 'no-store',
  });
  fs.createReadStream(file).pipe(res);
}

// 预览：文本文件返回内容（最多 1MB），图片给前端一个 /api/raw 地址，其他只给基本信息
const IMAGE_TYPES = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp', '.bmp': 'image/bmp', '.ico': 'image/x-icon' };
const PREVIEW_MAX = 1024 * 1024;
function previewFile(res, p) {
  const file = path.resolve(p || '');
  if (!p || !insideWorkspace(file)) return json(res, 403, { error: '只能预览工作区里的文件' });
  let st;
  try { st = fs.statSync(file); } catch { return json(res, 404, { error: '文件不存在' }); }
  if (!st.isFile()) return json(res, 400, { error: '不是文件' });
  const info = { path: file, name: path.basename(file), size: st.size, mtime: st.mtimeMs };
  if (IMAGE_TYPES[path.extname(file).toLowerCase()]) return json(res, 200, { ...info, kind: 'image' });
  const fd = fs.openSync(file, 'r');
  const buf = Buffer.alloc(Math.min(st.size, PREVIEW_MAX));
  fs.readSync(fd, buf, 0, buf.length, 0);
  fs.closeSync(fd);
  if (buf.subarray(0, 8000).includes(0)) return json(res, 200, { ...info, kind: 'binary' });
  return json(res, 200, { ...info, kind: 'text', text: buf.toString('utf8'), truncated: st.size > PREVIEW_MAX });
}
// 只给图片用；不支持 svg（svg 里可以带脚本）
function rawImage(res, p) {
  const file = path.resolve(p || '');
  const type = IMAGE_TYPES[path.extname(file).toLowerCase()];
  if (!p || !type || !insideWorkspace(file)) return json(res, 403, { error: '不支持' });
  let st;
  try { st = fs.statSync(file); } catch { return json(res, 404, { error: '文件不存在' }); }
  res.writeHead(200, { 'Content-Type': type, 'Content-Length': st.size, 'Cache-Control': 'no-store', 'Content-Security-Policy': "default-src 'none'" });
  fs.createReadStream(file).pipe(res);
}

// 新建文件夹 / 重命名 / 删除
function fileOp(res, { op, path: p, name }) {
  const target = path.resolve(String(p || ''));
  if (!p || !insideWorkspace(target)) return json(res, 403, { error: '只能操作工作区里的文件' });
  const isRoot = workspaces.has(target);
  try {
    if (op === 'mkdir') {
      if (!isDir(target)) return json(res, 400, { error: '目标目录不存在' });
      const dir = path.join(target, safeName(name));
      if (fs.existsSync(dir)) return json(res, 409, { error: '已经有同名的文件或文件夹' });
      fs.mkdirSync(dir);
      return json(res, 200, { ok: true, path: dir });
    }
    if (op === 'rename') {
      if (isRoot) return json(res, 400, { error: '不能重命名工作区根目录' });
      if (!fs.existsSync(target)) return json(res, 404, { error: '文件不存在' });
      const to = path.join(path.dirname(target), safeName(name));
      if (fs.existsSync(to)) return json(res, 409, { error: '已经有同名的文件或文件夹' });
      fs.renameSync(target, to);
      return json(res, 200, { ok: true, path: to });
    }
    if (op === 'delete') {
      if (isRoot) return json(res, 400, { error: '不能删除工作区根目录' });
      if (!fs.existsSync(target)) return json(res, 404, { error: '文件不存在' });
      fs.rmSync(target, { recursive: true });
      console.log(`[files] 已删除 ${target}`);
      return json(res, 200, { ok: true });
    }
    return json(res, 400, { error: '未知操作' });
  } catch (err) {
    return json(res, 500, { error: err.message });
  }
}

function safeName(name) {
  const base = path.basename(String(name || '')).replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').replace(/^\.+$/, '_').trim();
  return base.slice(0, 200) || 'file';
}
function uploadFile(req, res, dirParam, nameParam) {
  const dir = path.resolve(dirParam || '');
  if (!dirParam || !insideWorkspace(dir)) return json(res, 403, { error: '只能上传到工作区里' });
  const len = Number(req.headers['content-length'] || 0);
  if (len > MAX_UPLOAD) return json(res, 413, { error: '文件太大（最大 512MB）' });
  fs.mkdirSync(dir, { recursive: true });
  // 重名时自动加序号，不覆盖已有文件
  const name = safeName(nameParam);
  const ext = path.extname(name);
  const stem = name.slice(0, name.length - ext.length);
  let target = path.join(dir, name);
  for (let i = 1; fs.existsSync(target); i++) target = path.join(dir, `${stem} (${i})${ext}`);
  const tmp = target + '.uploading';
  const out = fs.createWriteStream(tmp, { flags: 'wx' });
  let size = 0;
  let failed = false;
  const fail = (status, error) => {
    if (failed) return; failed = true;
    out.destroy(); fs.rm(tmp, { force: true }, () => {});
    if (!res.headersSent) json(res, status, { error });
    req.destroy();
  };
  req.on('data', (chunk) => { size += chunk.length; if (size > MAX_UPLOAD) fail(413, '文件太大（最大 512MB）'); });
  req.on('aborted', () => fail(400, '上传中断'));
  out.on('error', (e) => fail(500, '写入失败：' + e.message));
  out.on('finish', () => {
    if (failed) return;
    fs.renameSync(tmp, target);
    console.log(`[upload] ${target} (${size} bytes)`);
    json(res, 200, { ok: true, path: target, name: path.basename(target), size });
  });
  req.pipe(out);
}

// 任何一个请求出错都只影响这个请求，不能让整个服务崩掉
function safeHandle(req, res) {
  handle(req, res).catch((err) => {
    console.error(`[http] ${req.method} ${String(req.url).slice(0, 200)} 出错：${err?.stack || err}`);
    try { if (!res.headersSent) res.writeHead(500); res.end(); } catch { /* ignore */ }
  });
}
process.on('unhandledRejection', (err) => console.error('[unhandledRejection]', err?.stack || err));

const server = TLS_DOMAIN
  ? https.createServer({ key: tlsCert.key, cert: tlsCert.cert, minVersion: 'TLSv1.2' }, safeHandle)
  : http.createServer(safeHandle);

// ---------- WebSocket ----------
const wss = new WebSocketServer({ noServer: true, maxPayload: 1024 * 1024 });
server.on('upgrade', (req, socket, head) => {
  // 只接受同源 + 已登录的连接
  if (!hostOk(req) || !isAuthed(req) || !sameOrigin(req)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    return socket.destroy();
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.sid = sidOf(req);
    wss.emit('connection', ws, req);
  });
});

function broadcast(msg) {
  const data = JSON.stringify(msg);
  for (const ws of wss.clients) if (ws.readyState === 1) ws.send(data);
}

// 运行中的对话：chatId -> { abort, buffer, pending, sessionId }
// 事件会缓存下来，手机断线重连后可以补发
const runs = new Map();
let permSeq = 0;

const runListeners = new Set(); // 服务端内部订阅对话事件（QQ 机器人用）
function emit(run, chatId, msg) {
  const m = { ...msg, chatId };
  run.buffer.push(m);
  broadcast(m);
  for (const l of runListeners) { try { l(m); } catch (e) { console.error('[run listener]', e); } }
}

// 把 SDK 消息精简成前端要的样子（只保留主对话，不含子 agent 内部细节）
function forward(run, chatId, m) {
  // 用量限额：被拒绝时记下来，这一轮结束后安排自动继续
  if (m.type === 'rate_limit_event') {
    const i = m.rate_limit_info || {};
    if (i.status === 'rejected') run.rateLimited = { resetsAt: i.resetsAt, type: i.rateLimitType };
    return;
  }
  if (m.type === 'assistant' && m.error === 'rate_limit' && !run.rateLimited) run.rateLimited = {};
  if (m.type === 'result' && m.is_error && !run.rateLimited && /usage limit|hit your (usage )?limit|limit reached|rate[ _-]?limit/i.test(String(m.result || ''))) run.rateLimited = {};
  if (m.type === 'system' && m.subtype === 'init') {
    run.sessionId = m.session_id;
    emit(run, chatId, { type: 'session', sessionId: m.session_id, model: m.model, version: m.claude_code_version, mode: m.permissionMode });
    return;
  }
  if (m.parent_tool_use_id) return;
  if (m.type === 'stream_event') {
    const e = m.event;
    trackStats(run, chatId, e);
    if (e.type === 'content_block_delta' && e.delta?.type === 'text_delta') {
      emit(run, chatId, { type: 'delta', text: e.delta.text });
    } else if (e.type === 'content_block_delta' && e.delta?.type === 'thinking_delta' && e.delta.thinking) {
      emit(run, chatId, { type: 'think', text: e.delta.thinking });
    }
    return;
  }
  if (m.type === 'assistant' || m.type === 'user') {
    let content = m.message?.content;
    // Claude Code 自己插进来的“用户”文字（读长图时的尺寸说明、技能说明等），不是用户打的字，不显示；工具结果照常保留
    if (m.type === 'user' && (m.isSynthetic || m.isMeta)) {
      if (!Array.isArray(content)) return;
      content = content.filter((b) => b.type !== 'text');
      if (!content.length) return;
    }
    emit(run, chatId, { type: 'message', role: m.type, content, id: m.message?.id, usage: m.message?.usage, at: Date.now() });
    return;
  }
  if (m.type === 'result') {
    const u = m.usage || {};
    const mu = Object.values(m.modelUsage || {})[0];
    run.contextWindow = mu?.contextWindow;
    emit(run, chatId, {
      type: 'result',
      ok: m.subtype === 'success' && !m.is_error,
      error: m.subtype !== 'success' ? m.subtype : undefined,
      // 和首字时间用同一个时钟：从网页发送到完成（含启动 Claude Code 的一两秒）
      durationMs: Date.now() - run.startedAt,
      // 本轮主对话的 token（不含子 agent）
      inputTokens: (u.input_tokens || 0) + (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0),
      cacheReadTokens: u.cache_read_input_tokens || 0,
      outputTokens: u.output_tokens || 0,
      apiCalls: run.stats.calls,
      ttftMs: run.stats.ttftMs,
      tps: run.stats.genMs > 0 ? run.stats.outTokens / (run.stats.genMs / 1000) : null,
      // SDK 给的费用是整个会话累计的（续聊会带上之前的），只能作为“会话累计”显示
      sessionCost: m.total_cost_usd,
      // 上下文占用：最后一次调用的输入 token / 模型上下文窗口
      contextUsed: run.stats.lastInput, contextWindow: mu?.contextWindow,
      errorText: m.is_error ? String(m.result || '').slice(0, 500) : undefined,
    });
  }
}

// 根据流式事件统计：首字时间、输出 token、生成速度（tok/s）
// 生成时间 = 每次 API 调用从第一个内容块开始到结束，不含排队/预填充时间
function trackStats(run, chatId, e) {
  const s = run.stats;
  const now = Date.now();
  if (e.type === 'message_start') {
    s.cur = { start: now, firstBlock: 0, out: 0 };
    s.calls++;
    const u = e.message?.usage || {};
    s.lastInput = (u.input_tokens || 0) + (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0);
  } else if (e.type === 'content_block_start' && s.cur && !s.cur.firstBlock) {
    s.cur.firstBlock = now;
    if (s.ttftMs == null) s.ttftMs = now - run.startedAt;
  } else if (e.type === 'message_delta' && s.cur) {
    s.cur.out = e.usage?.output_tokens ?? s.cur.out;
  } else if (e.type === 'message_stop' && s.cur) {
    // 用整次调用的时间算速度：思考摘要模式下，思考结束后才开始推送内容，
    // 如果从第一个内容块算起，思考 token 会被算进很短的时间里，速度虚高
    s.genMs += now - s.cur.start;
    s.outTokens += s.cur.out;
    s.cur = null;
    emitStats(run, chatId);
  }
}
function emitStats(run, chatId) {
  const s = run.stats;
  emit(run, chatId, {
    type: 'stats',
    elapsedMs: Date.now() - run.startedAt,
    ttftMs: s.ttftMs, outTokens: s.outTokens, calls: s.calls,
    tps: s.genMs > 0 ? s.outTokens / (s.genMs / 1000) : null,
    contextUsed: s.lastInput,
  });
}

// ---------- 工作区（Claude 可以在哪些目录里干活，文件面板也只能访问这些目录） ----------
const WS_FILE = path.join(__dirname, 'data', 'workspaces.json');
const workspaces = new Set([WORKDIR]);
try { for (const p of JSON.parse(fs.readFileSync(WS_FILE, 'utf8'))) workspaces.add(path.resolve(p)); } catch { /* 没有就算了 */ }
function saveWorkspaces() {
  fs.mkdirSync(path.dirname(WS_FILE), { recursive: true });
  fs.writeFileSync(WS_FILE, JSON.stringify([...workspaces].filter((p) => p !== WORKDIR), null, 2));
}
function insideWorkspace(p) {
  const target = path.resolve(p);
  return [...workspaces].some((root) => {
    const rel = path.relative(root, target);
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
  });
}
const isDir = (p) => { try { return fs.statSync(p).isDirectory(); } catch { return false; } };

const MODELS = ['', 'claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5', 'claude-fable-5-2'];
const MODES = ['default', 'acceptEdits', 'plan', 'bypassPermissions'];

// ---------- 撞到用量限额后自动继续 ----------
// 记在 data/resume.json 里，服务重启后照样会按时继续
const RESUME_FILE = path.join(__dirname, 'data', 'resume.json');
const RESUME_TEXT = '继续刚才没完成的任务。';
const SIMULATE_LIMIT = Number(process.env.CR_SIMULATE_LIMIT_SECONDS || 0);
const resumes = new Map(); // chatId -> { chatId, sessionId, cwd, model, mode, resumeAt, reason }
const resumeTimers = new Map();
const resumeAttempts = new Map(); // 连续撞限额的次数，超过 3 次就不再自动继续，免得死循环
function saveResumes() {
  fs.mkdirSync(path.dirname(RESUME_FILE), { recursive: true });
  fs.writeFileSync(RESUME_FILE, JSON.stringify([...resumes.values()], null, 2));
}
function armResume(r) {
  clearTimeout(resumeTimers.get(r.chatId));
  resumeTimers.set(r.chatId, setTimeout(() => fireResume(r.chatId), Math.max(1000, r.resumeAt - Date.now())));
}
function cancelResume(chatId, why) {
  if (!resumes.has(chatId)) return;
  clearTimeout(resumeTimers.get(chatId));
  resumeTimers.delete(chatId);
  resumes.delete(chatId);
  saveResumes();
  broadcast({ type: 'resume_cleared', chatId, why });
}
async function scheduleResume(chatId, run) {
  if (!run.sessionId) return;
  const n = (resumeAttempts.get(chatId) || 0) + 1;
  resumeAttempts.set(chatId, n);
  if (n > 3) {
    broadcast({ type: 'toast', level: 'error', message: '连续 3 次撞到用量限额，已停止自动继续' });
    return;
  }
  const info = run.rateLimited;
  let delay = null;
  let reason = info.type === 'seven_day' ? '7 天限额' : info.type?.startsWith('seven_day') ? '7 天限额' : '5 小时限额';
  if (info.simulateMs) { delay = info.simulateMs; reason = '模拟限额'; }
  else {
    // 重置时间按 Anthropic 的时钟给，换算成本机时钟（这台电脑时钟可能不准）
    invalidateLimits();
    const L = await getLimits(WORKDIR);
    const skew = L.ok ? L.clockSkewMs || 0 : 0;
    if (info.resetsAt) {
      const ms = info.resetsAt < 1e12 ? info.resetsAt * 1000 : info.resetsAt;
      delay = ms - (Date.now() - skew);
    } else if (L.ok) {
      // 没给重置时间：找已经用满的窗口里最早重置的那个
      const wins = [['5 小时限额', L.fiveHour], ['7 天限额', L.sevenDay], ['7 天 Opus 限额', L.sevenDayOpus], ['7 天 Sonnet 限额', L.sevenDaySonnet], ...(L.models || []).map((m) => [`7 天 ${m.name} 限额`, m])]
        .filter(([, w]) => w && w.pct >= 99 && w.resetsInMs != null)
        .sort((a, b) => a[1].resetsInMs - b[1].resetsInMs);
      if (wins.length) { reason = wins[0][0]; delay = wins[0][1].resetsInMs - (Date.now() - L.fetchedAt); }
    }
    if (delay == null || !(delay > 0)) delay = 30 * 60_000; // 不知道什么时候重置：30 分钟后试一次
    delay += 60_000; // 多等 1 分钟，确保已经重置
  }
  const r = { chatId, sessionId: run.sessionId, cwd: run.cwd, model: run.model, mode: run.mode, resumeAt: Date.now() + delay, reason };
  resumes.set(chatId, r);
  saveResumes();
  armResume(r);
  console.log(`[resume] ${reason}：${Math.round(delay / 60000)} 分钟后自动继续会话 ${run.sessionId}`);
  broadcast({ type: 'resume_scheduled', ...r, serverNow: Date.now() });
}
function fireResume(chatId) {
  const r = resumes.get(chatId);
  resumeTimers.delete(chatId);
  if (!r) return;
  resumes.delete(chatId);
  saveResumes();
  broadcast({ type: 'resume_cleared', chatId, why: 'fired' });
  if (runs.has(chatId)) return; // 已经有人手动继续了
  console.log(`[resume] 自动继续会话 ${r.sessionId}`);
  startRun(chatId, { sessionId: r.sessionId, text: RESUME_TEXT, cwd: r.cwd, model: r.model, mode: r.mode, auto: true })
    .catch((e) => console.error('[resume] 自动继续失败：' + e.message));
}
try { for (const r of JSON.parse(fs.readFileSync(RESUME_FILE, 'utf8'))) { resumes.set(r.chatId, r); armResume(r); } } catch { /* 没有就算了 */ }

async function startRun(chatId, { sessionId, text, cwd, model, mode, auto, origin }) {
  if (runs.has(chatId)) throw new Error('这个对话还在运行中');
  cwd = path.resolve(cwd || WORKDIR);
  if (!workspaces.has(cwd) || !isDir(cwd)) throw new Error('工作区不存在：' + cwd);
  if (!MODELS.includes(model || '')) throw new Error('不支持的模型');
  if (!MODES.includes(mode || 'default')) throw new Error('不支持的权限模式');
  const abort = new AbortController();
  const run = {
    abort, buffer: [], pending: new Map(), sessionId, cwd, startedAt: Date.now(), model: model || '', mode: mode || 'default', auto: Boolean(auto),
    stats: { calls: 0, ttftMs: null, outTokens: 0, genMs: 0, cur: null, lastInput: 0 },
  };
  runs.set(chatId, run);
  emit(run, chatId, { type: 'run_start', text, startedAt: run.startedAt, cwd, model: model || '', mode: mode || 'default', auto: Boolean(auto) });

  // 每次工具调用都会走这里，转发到网页上让人点允许/拒绝
  const canUseTool = (toolName, input, opts) => new Promise((resolve) => {
    const id = String(++permSeq);
    const done = (result, label) => {
      if (!run.pending.has(id)) return;
      run.pending.delete(id);
      emit(run, chatId, { type: 'permission_resolved', id, label });
      resolve(result);
    };
    run.pending.set(id, { done, suggestions: opts.suggestions });
    opts.signal.addEventListener('abort', () => done({ behavior: 'deny', message: '已中止' }, '已中止'));
    emit(run, chatId, {
      type: 'permission_request', id, toolName, input,
      title: opts.title, reason: opts.decisionReason, canAlways: Boolean(opts.suggestions?.length),
    });
  });

  // QQ 发起的对话（和它撞限额后的自动继续）多一个“发文件到 QQ”的工具；网页上接着聊 QQ 会话时没有
  const extra = (origin === 'qq' || auto) ? qqRunOptions(chatId) : null;
  try {
    const q = query({
      prompt: text,
      options: {
        ...(extra || {}),
        cwd,
        resume: sessionId || undefined,
        model: model || MODEL,
        includePartialMessages: true,
        thinking: { type: 'adaptive', display: 'summarized' }, // 让网页能显示思考摘要
        permissionMode: mode || 'default',
        allowDangerouslySkipPermissions: mode === 'bypassPermissions',
        settingSources: ['user', 'project', 'local'],
        canUseTool,
        abortController: abort,
      },
    });
    for await (const m of q) forward(run, chatId, m);
  } catch (err) {
    if (!abort.signal.aborted) emit(run, chatId, { type: 'error', message: String(err?.message || err) });
  } finally {
    for (const p of run.pending.values()) p.done({ behavior: 'deny', message: '已结束' }, '已结束');
    // 测试用：设置 CR_SIMULATE_LIMIT_SECONDS 时，把普通的一轮当成撞到限额（自动继续的那轮除外）
    if (SIMULATE_LIMIT && !run.rateLimited && !run.auto && !abort.signal.aborted) run.rateLimited = { simulateMs: SIMULATE_LIMIT * 1000 };
    emit(run, chatId, { type: 'run_end', sessionId: run.sessionId, aborted: abort.signal.aborted, rateLimited: Boolean(run.rateLimited && !abort.signal.aborted) });
    runs.delete(chatId);
    invalidateLimits(); // 跑完一轮后限额会变，下次读取时重新拉
    if (run.rateLimited && !abort.signal.aborted) {
      scheduleResume(chatId, run).catch((e) => console.error('[resume] 安排自动继续失败：' + e.message));
    } else if (!run.rateLimited) {
      resumeAttempts.delete(chatId);
    }
  }
}

function resolvePermission(chatId, id, decision, message) {
  const p = runs.get(chatId)?.pending.get(String(id));
  if (!p) return false;
  if (decision === 'allow') p.done({ behavior: 'allow' }, '已允许');
  else if (decision === 'always') p.done({ behavior: 'allow', updatedPermissions: p.suggestions }, '已允许（以后总是允许）');
  else p.done({ behavior: 'deny', message: message || '用户拒绝了这次操作' }, '已拒绝');
  return true;
}

// QQ 机器人：复用同一套对话运行逻辑，QQ 上的会话在网页里也能看到、接着聊
initQQBot({
  WORKDIR, workspaces, MODELS, MODES,
  startRun: (chatId, opts) => { cancelResume(chatId, 'manual'); resumeAttempts.delete(chatId); return startRun(chatId, opts); },
  isRunning: (chatId) => runs.has(chatId),
  interrupt: (chatId) => runs.get(chatId)?.abort.abort(),
  resolvePermission,
  onRunEvent: (fn) => runListeners.add(fn),
});
for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => { stopQQBot(); process.exit(0); });

// 服务端也定时 ping，清掉已经断了但没正常关闭的连接（手机断网等）
setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) { ws.terminate(); continue; }
    ws.isAlive = false;
    try { ws.ping(); } catch { /* ignore */ }
  }
}, 30_000).unref();

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  const send = (m) => ws.readyState === 1 && ws.send(JSON.stringify(m));
  send({ type: 'hello', workdir: WORKDIR, serverTime: Date.now() });
  // 补发所有正在运行的对话（断线重连用）
  for (const [chatId, run] of runs) send({ type: 'replay', chatId, sessionId: run.sessionId, cwd: run.cwd, events: run.buffer });
  // 已安排的自动继续
  for (const r of resumes.values()) send({ type: 'resume_scheduled', ...r, serverNow: Date.now() });

  ws.on('message', async (raw) => {
    // 登录过期或被登出后，连接立即失效
    if (!checkSession(ws.sid)) return ws.close(4001, 'session expired');
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    try {
      switch (msg.type) {
        case 'ping': send({ type: 'pong' }); break; // 浏览器端心跳
        case 'list': {
          // 列出所有工作区的会话；只显示已登记的工作区里的会话
          const all = await listSessions({ limit: 500, includeWorktrees: false });
          const sessions = all
            .filter((s) => s.cwd && workspaces.has(path.resolve(s.cwd)))
            .map((s) => ({
              sessionId: s.sessionId, cwd: path.resolve(s.cwd),
              title: s.customTitle || s.summary || s.firstPrompt || '(无标题)',
              lastModified: s.lastModified,
            }));
          // 有会话但还没登记的目录，作为“发现的目录”提供给前端，点一下就能加进来
          const discovered = [...new Set(all.map((s) => s.cwd && path.resolve(s.cwd)).filter((p) => p && !workspaces.has(p) && isDir(p)))];
          send({ type: 'sessions', workspaces: [...workspaces], defaultWorkspace: WORKDIR, sessions, discovered, running: [...runs.keys()] });
          break;
        }
        case 'add_workspace': {
          const p = path.resolve(String(msg.path || ''));
          if (!isDir(p)) return send({ type: 'toast', level: 'error', message: '目录不存在：' + p });
          workspaces.add(p); saveWorkspaces();
          send({ type: 'toast', message: '已添加工作区：' + p });
          break;
        }
        case 'remove_workspace': {
          const p = path.resolve(String(msg.path || ''));
          if (p === WORKDIR) return send({ type: 'toast', level: 'error', message: '默认工作区不能移除' });
          workspaces.delete(p); saveWorkspaces();
          break;
        }
        case 'history': {
          const messages = await getSessionMessages(String(msg.sessionId));
          send({
            type: 'history', sessionId: msg.sessionId,
            messages: messages.filter((m) => !m.parent_tool_use_id).map((m) => ({
              role: m.type, content: m.message?.content, id: m.message?.id, usage: m.message?.usage,
            })),
          });
          break;
        }
        case 'send': {
          const text = String(msg.text || '').trim();
          if (!text || typeof msg.chatId !== 'string') return;
          cancelResume(msg.chatId, 'manual'); // 手动发了消息，就不用再自动继续了
          resumeAttempts.delete(msg.chatId);
          startRun(msg.chatId, { sessionId: msg.sessionId, text, cwd: msg.cwd, model: msg.model, mode: msg.mode })
            .catch((e) => send({ type: 'error', chatId: msg.chatId, message: e.message }));
          break;
        }
        case 'cancel_resume': {
          cancelResume(String(msg.chatId), 'cancelled');
          break;
        }
        case 'interrupt': {
          runs.get(msg.chatId)?.abort.abort();
          break;
        }
        case 'permission': {
          resolvePermission(msg.chatId, msg.id, msg.decision, msg.message);
          break;
        }
      }
    } catch (err) {
      send({ type: 'error', chatId: msg.chatId, message: String(err?.message || err) });
    }
  });
});

// ---------- HTTPS 模式：80 端口负责证书验证和跳转，定时续期 ----------
if (TLS_DOMAIN) {
  const redirectServer = http.createServer((req, res) => {
    if (handleChallenge(req, res)) return;
    const target = `https://${TLS_DOMAIN}${HTTPS_PORT === 443 ? '' : ':' + HTTPS_PORT}${req.url.startsWith('/') ? req.url : '/'}`;
    res.writeHead(301, { Location: target });
    res.end();
  });
  redirectServer.on('error', (e) => console.error(`⚠ ${HTTP_PORT} 端口启动失败（${e.code}），证书将无法自动续期`));
  redirectServer.listen(HTTP_PORT, TLS_BIND);

  const renew = async () => {
    if (!needsRenewal(tlsCert)) return;
    if (!loadAccount()) return console.error('[tls] 证书快到期了，但没有 ACME 账号，请运行 npm run cert');
    try {
      tlsCert = await issueCert({ domain: TLS_DOMAIN });
      server.setSecureContext({ key: tlsCert.key, cert: tlsCert.cert }); // 不用重启就换上新证书
    } catch (err) {
      console.error('[tls] 续期失败，12 小时后重试：' + (err.message || err));
    }
  };
  setInterval(renew, 12 * 3600 * 1000);
  setTimeout(renew, 10_000);

  server.listen(HTTPS_PORT, TLS_BIND, () => {
    console.log(`\nClaude Remote 已启动: https://${TLS_DOMAIN}${HTTPS_PORT === 443 ? '' : ':' + HTTPS_PORT}`);
    console.log(`证书有效期到 ${tlsCert.notAfter.toISOString().slice(0, 10)}（${tlsCert.issuer}），到期前 30 天自动续期`);
    console.log(`工作目录: ${WORKDIR}`);
    console.log(`登录账号: ${auth.username}`);
  });
} else server.listen(PORT, HOST, () => {
  console.log(`\nClaude Remote 已启动: http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`工作目录: ${WORKDIR}`);
  console.log(`登录账号: ${auth.username}${auth.totpSecret ? '（已开启两步验证）' : '（未开启两步验证）'}`);
  if (TRUST_PROXY) console.log('信任反向代理传来的 IP 和 HTTPS 标记（TRUST_PROXY=1）');
  if (HOST !== '127.0.0.1' && HOST !== '::1' && HOST !== 'localhost') {
    console.log('⚠ 正在监听非本机地址，没有 HTTPS 的话密码会明文传输。推荐保持 127.0.0.1，用 Cloudflare Tunnel 对外。');
  }
});

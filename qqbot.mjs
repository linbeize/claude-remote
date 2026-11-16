// QQ 机器人：在 QQ 私聊 / 群里和这台电脑上的 Claude Code 对话
//
// - 连接：@tencent-connect/qqbot-nodejs（WebSocket 长连接，由本机主动连 QQ，不需要开放端口）
// - 绑定：@tencent-connect/qqbot-connector 扫码拿 AppID / AppSecret，也可以手动填
// - 安全：能和机器人对话就等于能在这台电脑上执行命令。默认只允许扫码绑定的那个人；
//         其他人或群要用网页上生成的一次性配对码加入白名单
//
// 配置和凭据保存在 data/qqbot.json（已在 .gitignore 里）
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import QRCode from 'qrcode';
import { z } from 'zod';
import { createSdkMcpServer, tool } from '@anthropic-ai/claude-agent-sdk';
import { getLimits, getStats } from './usage.mjs';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const FILE = path.join(DIR, 'data', 'qqbot.json');
const CHUNK = 1800;                 // 单条消息最多多少字，超过就拆成几条
const PASSIVE_TTL = 55 * 60_000;    // 被动回复窗口（QQ 约 60 分钟），留点余量
const PASSIVE_MAX = 4;              // 同一条消息最多被动回复几次，超过改用主动消息
const PAIR_TTL = 10 * 60_000;       // 配对码 10 分钟有效
const MAX_ATTACH = 50 * 1024 * 1024;
const MODEL_ALIAS = { default: '', 默认: '', opus: 'claude-opus-5-5', sonnet: 'claude-sonnet-5-5', haiku: 'claude-haiku-5-5', fable: 'claude-fable-5-2' };
const MODE_NAMES = { default: '标准', acceptEdits: '自动改文件', plan: '只做计划', bypassPermissions: '完全权限' };

let host = null;     // server.mjs 提供：startRun / interrupt / resolvePermission / onRunEvent / workspaces / WORKDIR / MODELS / MODES / isRunning
let cfg = null;
let bot = null;
let botAbort = null;
let restartTimer = null;
const status = { state: 'unbound', error: null, since: Date.now() };
let bind = null;     // 正在扫码绑定：{ stop, url, svg, state, error }
let pair = null;     // 当前配对码：{ code, expiresAt }

// 每个 QQ 会话对应一个对话（chatId = qq:c2c:<openid> / qq:group:<openid>）
const chats = new Map();   // chatId -> { target, inboundAt, passiveCount, fromQQ, pendingPerm, texts, typingTimer }
const deniedNoticeAt = new Map();

// ---------- 配置 ----------
function defaults() {
  return {
    appId: '', appSecret: '', ownerOpenid: '', enabled: true,
    cwd: '', model: '', mode: 'bypassPermissions',
    markdown: false, streaming: false, // 流式默认关：QQ 客户端显示不稳定（会出现“不支持显示”或重复），官方 dsh 插件实际上也没在用
    c2cAllow: [], groupAllow: [],
    peers: {},       // chatId -> { sessionId, model }
  };
}
function load() {
  try { cfg = { ...defaults(), ...JSON.parse(fs.readFileSync(FILE, 'utf8')) }; } catch { cfg = defaults(); }
}
function save() {
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2));
  fs.renameSync(tmp, FILE);
}
const bound = () => Boolean(cfg.appId && cfg.appSecret);
const workdir = () => (cfg.cwd && host.workspaces.has(cfg.cwd) ? cfg.cwd : host.WORKDIR);
function setStatus(state, error = null) { status.state = state; status.error = error; status.since = Date.now(); }

// ---------- 连接 ----------
async function startBot() {
  stopBot();
  if (!bound()) return setStatus('unbound');
  if (!cfg.enabled) return setStatus('disabled');
  const { QQBot, messageFilter, contentSanitizer } = await import('@tencent-connect/qqbot-nodejs');
  const ac = new AbortController();
  botAbort = ac;
  const b = new QQBot({
    appId: cfg.appId, appSecret: cfg.appSecret, markdownSupport: Boolean(cfg.markdown),
    userAgent: 'claude-remote',
    logger: { debug() {}, info() {}, warn: (...a) => console.warn('[qqbot]', ...a), error: (...a) => console.error('[qqbot]', ...a) },
  });
  bot = b;
  b.use(messageFilter({ skipSelfEcho: true, dedup: { windowMs: 60_000, maxSize: 2000 } }));
  b.use(contentSanitizer({ stripBotMention: true, collapseWhitespace: false }));
  b.on('ready', () => { if (bot === b) { setStatus('ready'); console.log('[qqbot] 已连接'); } });
  b.on('resumed', () => { if (bot === b) setStatus('ready'); });
  b.on('disconnected', ({ willReconnect }) => { if (bot === b) setStatus(willReconnect ? 'connecting' : 'error', willReconnect ? null : '连接被 QQ 关闭'); });
  // SDK 在“取网关地址时 token 已失效”这种情况下不会自己刷新 token，会拿着失效的 token 一直重试。
  // 碰到 token 相关的错误就清掉缓存，下次重连会重新取 token
  let tokenErrors = 0;
  b.on('error', (err) => {
    if (bot !== b) return;
    const m = String(err?.message || err);
    if (/access\s*_?token|token.*(无效|过期|invalid|expired)/i.test(m)) {
      tokenErrors++;
      try { b.tokenManager?.clearCache(cfg.appId); } catch { /* ignore */ }
      if (tokenErrors === 1 || tokenErrors % 10 === 0) console.warn(`[qqbot] token 失效，已清除缓存，重连时重新获取（第 ${tokenErrors} 次）`);
      setStatus('connecting', 'token 失效，正在重新获取');
    }
  });
  b.on('ready', () => { tokenErrors = 0; });
  b.on('message', (ctx, msg) => { onMessage(b, msg).catch((e) => console.error('[qqbot] 处理消息出错：', e)); });
  setStatus('connecting');
  b.start(ac.signal).then(() => {
    if (bot === b && !ac.signal.aborted) setStatus('stopped');
  }).catch((err) => {
    if (bot !== b) return;
    const fatal = err?.code === 'GATEWAY_FATAL_CLOSE';
    const msg = fatal ? `QQ 拒绝连接（${err.closeCode}）：机器人可能已下线、只在沙箱里可用或被封禁` : String(err?.message || err);
    setStatus('error', msg);
    console.error('[qqbot] 连接失败：' + msg);
    if (!fatal) restartTimer = setTimeout(() => startBot().catch(() => {}), 60_000); // 网络问题：1 分钟后再试
  });
}
function stopBot() {
  clearTimeout(restartTimer);
  restartTimer = null;
  if (botAbort) botAbort.abort();
  try { bot?.stop(); } catch { /* ignore */ }
  bot = null; botAbort = null;
  for (const c of chats.values()) clearInterval(c.typingTimer);
}

// ---------- 收消息 ----------
const peerKey = (msg) => (msg.kind === 'group' ? `qq:group:${msg.groupOpenid}` : `qq:c2c:${msg.senderId}`);
function allowed(msg) {
  if (msg.kind === 'group') return cfg.groupAllow.some((g) => g.openid === msg.groupOpenid);
  if (msg.kind === 'c2c') return msg.senderId === cfg.ownerOpenid || cfg.c2cAllow.some((u) => u.openid === msg.senderId);
  return false; // 频道 / 频道私信不支持
}
function chatState(chatId, msg) {
  let c = chats.get(chatId);
  if (!c) { c = { target: null, inboundAt: 0, passiveCount: 0, fromQQ: false, pendingPerm: null, texts: [], typingTimer: null }; chats.set(chatId, c); }
  if (msg) { c.target = msg.replyTarget; c.inboundAt = Date.now(); c.passiveCount = 0; }
  return c;
}

async function onMessage(b, msg) {
  if (b !== bot || !msg.replyTarget) return;
  const text = String(msg.content || '').trim();

  // 配对码：没在白名单里的人 / 群，发对了就加进来
  if (!allowed(msg)) {
    if (pair && Date.now() < pair.expiresAt && text === pair.code) {
      if (msg.kind === 'group') cfg.groupAllow.push({ openid: msg.groupOpenid, name: '', addedAt: Date.now() });
      else cfg.c2cAllow.push({ openid: msg.senderId, name: msg.senderName || '', addedAt: Date.now() });
      pair = null; save();
      console.log(`[qqbot] 配对成功：${msg.kind === 'group' ? '群 ' + msg.groupOpenid : '用户 ' + msg.senderId}`);
      return reply(b, msg.replyTarget, msg.kind === 'group' ? '配对成功，这个群里 @我 就能和 Claude 对话了。发 /help 看可用命令。' : '配对成功，现在可以直接和 Claude 对话了。发 /help 看可用命令。');
    }
    // 陌生人只提示一次（每小时最多一次），免得被刷
    const k = peerKey(msg);
    if (Date.now() - (deniedNoticeAt.get(k) || 0) > 3600_000) {
      deniedNoticeAt.set(k, Date.now());
      return reply(b, msg.replyTarget, '你还没有使用权限。请让机器人主人在网页的“QQ 机器人”设置里生成配对码，把配对码发给我。');
    }
    return;
  }

  const chatId = peerKey(msg);
  const c = chatState(chatId, msg);
  const peer = cfg.peers[chatId] || (cfg.peers[chatId] = {});

  // Claude 在等你回答问题：回复数字选选项，或者直接写答案；“跳过”就跳过
  if (c.pendingQ && !text.startsWith('/')) {
    const { id, questions } = c.pendingQ;
    if (/^(跳过|skip|算了)$/i.test(text.replace(/[。.!！\s]/g, ''))) { c.pendingQ = null; host.answerQuestion(chatId, id, {}); return; }
    const parts = questions.length > 1 ? text.split(/\n+|[;；]/).map((s) => s.trim()).filter(Boolean) : [text];
    if (parts.length < questions.length) return reply(b, msg.replyTarget, `一共有 ${questions.length} 个问题，请每行回答一个（按顺序），或者回复“跳过”。`);
    const answers = {};
    questions.forEach((q, i) => { answers[q.question] = parseAnswer(q, parts[i]); });
    c.pendingQ = null;
    host.answerQuestion(chatId, id, answers);
    return;
  }

  // 正在等待权限确认
  if (c.pendingPerm) {
    const t = text.replace(/[。.!！\s]/g, '').toLowerCase();
    const decision = ['允许', '同意', 'y', 'yes', 'ok', '好'].includes(t) ? 'allow' : ['总是允许', '一直允许', 'always'].includes(t) ? 'always' : ['拒绝', '不', '不行', 'n', 'no'].includes(t) ? 'deny' : null;
    if (decision) {
      const id = c.pendingPerm; c.pendingPerm = null;
      host.resolvePermission(chatId, id, decision);
      return;
    }
    if (!text.startsWith('/')) return reply(b, msg.replyTarget, '还在等你确认上一个操作：回复“允许”“总是允许”或“拒绝”。发 /stop 可以停止这次任务。');
  }

  // 命令
  if (text.startsWith('/')) return command(b, msg, chatId, c, peer, text);

  if (host.isRunning(chatId)) return reply(b, msg.replyTarget, '上一条还在处理中，等它完成再发；发 /stop 可以停止。');

  // 附件：下载到工作区的 uploads 目录，把路径告诉 Claude
  let prompt = text;
  const files = await saveAttachments(msg).catch((e) => { console.error('[qqbot] 下载附件失败：', e.message); return []; });
  if (files.length) prompt = `${prompt}\n\n我通过 QQ 发了这些文件：\n${files.map((f) => '- ' + f).join('\n')}`.trim();
  if (!prompt) return;
  const who = (msg.kind === 'group' ? `（来自 QQ 群，发送者 ${msg.senderName || String(msg.senderId || '').slice(0, 8)}` : '（来自 QQ 私聊') + `。用对方使用的语言回复；要把图片或文件发给对方，用 ${SEND_TOOL} 工具）`;

  c.fromQQ = true; c.texts = [];
  try {
    await host.startRun(chatId, {
      sessionId: peer.sessionId, text: `${prompt}\n\n${who}`, cwd: workdir(),
      model: peer.model ?? cfg.model ?? '', mode: cfg.mode || 'bypassPermissions', origin: 'qq',
    });
  } catch (e) {
    c.fromQQ = false;
    reply(b, msg.replyTarget, '没能开始：' + e.message);
  }
}

async function command(b, msg, chatId, c, peer, text) {
  const [cmd, ...args] = text.slice(1).trim().split(/\s+/);
  const arg = args.join(' ');
  const say = (t) => reply(b, msg.replyTarget, t);
  switch ((cmd || '').toLowerCase()) {
    case 'help': case '帮助':
      return say(['可用命令：', '/new  开始新会话（清空上下文）', '/stop  停止当前任务', '/status  查看当前会话状态', '/usage  查看套餐用量和今天的 token', '/model [opus|sonnet|haiku|fable|default]  查看或切换模型', '', '需要确认的操作会提示你回复“允许”“总是允许”或“拒绝”。'].join('\n'));
    case 'usage': case '用量':
      return say(await usageText());
    case 'new': case 'reset': case 'clear':
      if (host.isRunning(chatId)) return say('还有任务在运行，先发 /stop 停止。');
      delete peer.sessionId; save();
      return say('已开始新会话。');
    case 'stop':
      if (!host.isRunning(chatId)) return say('现在没有在运行的任务。');
      host.interrupt(chatId);
      return say('已停止。');
    case 'status': {
      const m = peer.model ?? cfg.model ?? '';
      return say([
        `会话：${peer.sessionId ? peer.sessionId.slice(0, 8) : '新会话'}`,
        `状态：${host.isRunning(chatId) ? '运行中' : '空闲'}`,
        `工作目录：${workdir()}`,
        `模型：${m || 'Claude Code 默认'}`,
        `权限：${MODE_NAMES[cfg.mode] || cfg.mode}`,
      ].join('\n'));
    }
    case 'model': {
      if (!arg) return say(`当前模型：${(peer.model ?? cfg.model) || 'Claude Code 默认'}\n可选：opus、sonnet、haiku、fable、default`);
      const m = MODEL_ALIAS[arg.toLowerCase()] ?? (host.MODELS.includes(arg) ? arg : null);
      if (m == null) return say('不认识这个模型。可选：opus、sonnet、haiku、fable、default');
      peer.model = m; save();
      return say(`已切换到 ${m || 'Claude Code 默认模型'}，下一条消息开始生效。`);
    }
    default:
      return say('不认识这个命令，发 /help 看可用命令。');
  }
}

// ---------- Claude 提问（AskUserQuestion）在 QQ 里的样子 ----------
const NUM = ['①', '②', '③', '④'];
export function questionText(qs) {
  const lines = ['Claude 想问你：'];
  qs.forEach((q, i) => {
    lines.push('');
    lines.push(`${qs.length > 1 ? NUM[i] + ' ' : ''}${q.header ? `【${q.header}】` : ''}${q.question}${q.multiSelect ? '（可多选）' : ''}`);
    (q.options || []).forEach((o, k) => lines.push(`${k + 1}. ${o.label}${o.description ? ' — ' + o.description : ''}`));
  });
  lines.push('');
  if (qs.length > 1) lines.push('请每行回答一个问题（按顺序）：回复选项数字，或者直接写你的答案。');
  else lines.push(qs[0]?.multiSelect ? '回复选项数字（多选用空格分开，比如“1 3”），或者直接写你的答案。' : '回复选项数字，或者直接写你的答案。');
  lines.push('回复“跳过”可以不回答。');
  return lines.join('\n');
}
// 把一行回复变成答案：全是有效的选项数字就换成选项名称，否则当作自己写的答案
export function parseAnswer(q, reply) {
  const s = String(reply || '').trim();
  const nums = s.split(/[\s,，、]+/).filter(Boolean);
  const opts = q.options || [];
  if (nums.length && nums.every((n) => /^\d+$/.test(n) && +n >= 1 && +n <= opts.length)) {
    const picked = [...new Set(nums.map(Number))];
    return (q.multiSelect ? picked : picked.slice(0, 1)).map((n) => opts[n - 1].label).join(', ');
  }
  return s;
}

// /usage：套餐 5 小时 / 7 天限额 + 今天按 API 价格折算的 token 用量（和网页左下角、Token 统计一致）
const fmtTok = (n) => (n >= 1e9 ? (n / 1e9).toFixed(2) + 'B' : n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'k' : String(Math.round(n)));
const fmtUsd = (v) => (v >= 100 ? `$${v.toFixed(0)}` : v >= 1 ? `$${v.toFixed(2)}` : `$${v.toFixed(3)}`);
function fmtLeft(ms) {
  if (ms == null) return '';
  const m = Math.max(0, Math.round(ms / 60000));
  if (m < 1) return '即将重置';
  const d = Math.floor(m / 1440), h = Math.floor((m % 1440) / 60), mm = m % 60;
  return (d ? `${d} 天 ${h} 小时` : h ? `${h} 小时 ${mm} 分` : `${mm} 分钟`) + '后重置';
}
export async function usageText() {
  const lines = [];
  const [L, S] = await Promise.all([
    getLimits(workdir()).catch((e) => ({ ok: false, error: e.message })),
    getStats(1).catch(() => null),
  ]);
  if (L?.ok) {
    lines.push(`套餐用量${L.plan ? `（${String(L.plan).replace(/^\w/, (c) => c.toUpperCase())}）` : ''}`);
    const elapsed = Date.now() - (L.fetchedAt || Date.now());
    const row = (name, w) => {
      if (!w || w.pct == null) return;
      const pct = Math.round(w.pct);
      const warn = pct >= 95 ? ' ⚠️' : '';
      const left = w.resetsInMs != null ? fmtLeft(w.resetsInMs - elapsed) : '';
      lines.push(`${name}：${pct}%${warn}${left ? '，' + left : ''}`);
    };
    row('5 小时', L.fiveHour);
    row('7 天', L.sevenDay);
    row('7 天 Opus', L.sevenDayOpus);
    row('7 天 Sonnet', L.sevenDaySonnet);
    for (const m of L.models || []) row(`7 天 ${m.name}`, m);
    if (L.extra) lines.push(`额外用量：${L.extra.used ?? 0} / ${L.extra.limit ?? '—'} ${L.extra.currency || ''}`.trim());
    if (lines.length === 1) lines.push('暂时没有限额数据');
  } else {
    lines.push('套餐用量：读取失败' + (L?.error ? `（${L.error}）` : ''));
  }
  if (S?.total) {
    const T = S.total;
    const inAll = T.input + T.cacheRead + T.cacheWrite;
    lines.push('', '今天（本机所有 Claude Code 会话）');
    lines.push(`按 API 价格折算：${fmtUsd(T.cost)}（订阅不按这个收费）`);
    lines.push(`token：${fmtTok(inAll + T.output)}，输出 ${fmtTok(T.output)}，缓存命中 ${inAll ? Math.round(T.cacheRead / inAll * 100) : 0}%`);
    lines.push(`请求：${T.requests} 次`);
  }
  return lines.join('\n');
}

async function saveAttachments(msg) {
  const out = [];
  for (const a of msg.attachments || []) {
    let url = String(a.url || '');
    if (url.startsWith('//')) url = 'https:' + url;
    if (!/^https:\/\//i.test(url)) continue;
    const r = await fetch(url, { signal: AbortSignal.timeout(60_000) });
    if (!r.ok) continue;
    const len = Number(r.headers.get('content-length') || 0);
    if (len > MAX_ATTACH) continue;
    const buf = Buffer.from(await r.arrayBuffer());
    if (buf.length > MAX_ATTACH) continue;
    const ext = (a.filename && path.extname(a.filename)) || ({ 'image/png': '.png', 'image/jpeg': '.jpg', 'image/gif': '.gif', 'image/webp': '.webp' }[a.content_type] || '');
    const base = (a.filename ? path.basename(a.filename, path.extname(a.filename)) : 'qq').replace(/[^\w一-龥.-]+/g, '_').slice(0, 60) || 'qq';
    const dir = path.join(workdir(), 'uploads');
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, `${base}-${Date.now().toString(36)}${crypto.randomBytes(2).toString('hex')}${ext}`);
    fs.writeFileSync(file, buf);
    out.push(file);
  }
  return out;
}

// ---------- 发消息 ----------
// 没有 markdown 权限时，把常见的 markdown 记号去掉，读起来干净些
function plain(md) {
  return String(md)
    .replace(/^```[^\n]*\n?/gm, '')
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .replace(/__(.+?)__/g, '$1')
    .replace(/`([^`\n]+)`/g, '$1')
    .replace(/^#{1,6}\s+/gm, '')
    .replace(/\[([^\]]+)\]\((https?:[^)]+)\)/g, '$1（$2）')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}
function chunks(text) {
  const out = [];
  let rest = text;
  while (rest.length > CHUNK) {
    let cut = rest.lastIndexOf('\n\n', CHUNK);
    if (cut < CHUNK * 0.5) cut = rest.lastIndexOf('\n', CHUNK);
    if (cut < CHUNK * 0.5) cut = CHUNK;
    out.push(rest.slice(0, cut).trim());
    rest = rest.slice(cut).trim();
  }
  if (rest) out.push(rest);
  return out;
}
async function reply(b, target, text) {
  const body = cfg.markdown ? String(text) : plain(text);
  for (const part of chunks(body)) await sendOne(b, target, part);
}
// 优先被动回复（关联用户那条消息）；过期或次数用完就改成主动消息
async function sendOne(b, target, text, chatId) {
  const c = chatId ? chats.get(chatId) : null;
  const passive = target.msgId && (!c || (Date.now() - c.inboundAt < PASSIVE_TTL && c.passiveCount < PASSIVE_MAX));
  const t = passive ? target : { scope: target.scope, targetId: target.targetId };
  try {
    await (cfg.markdown ? b.sendMarkdown(t, text) : b.sendText(t, text));
    if (passive && c) c.passiveCount++;
  } catch (err) {
    if (!passive) throw err;
    console.warn('[qqbot] 被动回复失败，改用主动消息：' + (err?.message || err));
    if (c) c.passiveCount = PASSIVE_MAX;
    await (cfg.markdown ? b.sendMarkdown({ scope: target.scope, targetId: target.targetId }, text) : b.sendText({ scope: target.scope, targetId: target.targetId }, text));
  }
}
async function replyChat(chatId, text) {
  const c = chats.get(chatId);
  if (!bot || !c?.target) return;
  const b = bot;
  const body = cfg.markdown ? String(text) : plain(text);
  try { for (const part of chunks(body)) await sendOne(b, c.target, part, chatId); }
  catch (e) { console.error('[qqbot] 发送回复失败：' + (e?.message || e)); }
}

// ---------- 给 Claude 的工具：把本地文件发到当前 QQ 会话 ----------
const SEND_TOOL = 'mcp__qq__send_to_qq';
const IMAGE_EXTS = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp']);
const VIDEO_EXTS = new Set(['.mp4', '.mov', '.avi', '.mkv', '.webm']);
const VOICE_EXTS = new Set(['.mp3', '.wav', '.ogg', '.aac', '.silk', '.amr']);
const MB = 1024 * 1024;
// 只允许发已添加的工作区里的文件（解析符号链接后再判断），免得被人在群里诱导把系统里的私密文件发出去
function inWorkspace(p) {
  let real;
  try { real = fs.realpathSync(p); } catch { return false; }
  return [...host.workspaces].some((root) => {
    let r; try { r = fs.realpathSync(root); } catch { return false; }
    const rel = path.relative(r, real);
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
  });
}
async function sendFileToChat(chatId, filePath, caption) {
  const c = chats.get(chatId);
  const b = bot;
  if (!b || !c?.target) throw new Error('QQ 机器人没有连接，或者找不到当前 QQ 会话');
  const abs = path.resolve(String(filePath || ''));
  let st;
  try { st = fs.statSync(abs); } catch { throw new Error('文件不存在：' + abs); }
  if (!st.isFile()) throw new Error('不是文件：' + abs);
  if (!inWorkspace(abs)) throw new Error('只能发送已添加的工作区里的文件，可以先把文件复制到工作区再发：' + abs);
  const ext = path.extname(abs).toLowerCase();
  const kind = IMAGE_EXTS.has(ext) ? 'image' : VIDEO_EXTS.has(ext) ? 'video' : VOICE_EXTS.has(ext) ? 'voice' : 'file';
  const limit = { image: 30, video: 100, voice: 20, file: 100 }[kind] * MB;
  if (st.size > limit) throw new Error(`文件太大（${(st.size / MB).toFixed(1)}MB），QQ 限制${kind === 'image' ? '图片' : kind === 'video' ? '视频' : kind === 'voice' ? '语音' : '文件'}最大 ${limit / MB}MB`);
  const send = (t) => {
    const src = { localPath: abs };
    const opts = caption ? { content: String(caption).slice(0, 500) } : {};
    if (kind === 'image') return b.sendImage(t, src, opts);
    if (kind === 'video') return b.sendVideo(t, src, opts);
    if (kind === 'voice') return b.sendVoice(t, src, opts);
    return b.sendFile(t, src, { ...opts, fileName: path.basename(abs) });
  };
  const passive = c.target.msgId && Date.now() - c.inboundAt < PASSIVE_TTL && c.passiveCount < PASSIVE_MAX;
  const proactive = { scope: c.target.scope, targetId: c.target.targetId };
  try {
    await send(passive ? c.target : proactive);
    if (passive) c.passiveCount++;
  } catch (err) {
    if (!passive) throw err;
    c.passiveCount = PASSIVE_MAX;
    await send(proactive);
  }
  console.log(`[qqbot] 已发送${kind === 'image' ? '图片' : '文件'} ${path.basename(abs)}（${st.size} 字节）→ ${c.target.scope}`);
  return { kind, name: path.basename(abs), size: st.size };
}
// startRun 时附加给 QQ 发起的对话（含撞限额后的自动继续）
export function qqRunOptions(chatId) {
  if (!String(chatId).startsWith('qq:')) return null;
  const server = createSdkMcpServer({
    name: 'qq', version: '1.0.0',
    tools: [tool(
      'send_to_qq',
      '把本地文件发到当前的 QQ 会话（发起这次对话的 QQ 私聊或群）。图片（png/jpg/gif/webp/bmp）以图片消息发送，视频、语音按对应类型发送，其他按文件发送。用户让你“发图片 / 发文件 / 把结果发过来”时用它。只能发送已添加的工作区里的文件，别处的文件先复制到工作区。',
      { file_path: z.string().describe('要发送的文件的绝对路径'), caption: z.string().optional().describe('随文件一起发的简短说明（可选）') },
      async ({ file_path, caption }) => {
        try {
          const r = await sendFileToChat(chatId, file_path, caption);
          const size = r.size < 1024 ? `${r.size} 字节` : r.size < MB ? `${(r.size / 1024).toFixed(1)} KB` : `${(r.size / MB).toFixed(1)} MB`;
          return { content: [{ type: 'text', text: `已发送到 QQ：${r.name}（${size}）` }] };
        } catch (err) {
          return { content: [{ type: 'text', text: '发送失败：' + (err?.message || err) }], isError: true };
        }
      },
    )],
  });
  return { mcpServers: { qq: server }, allowedTools: [SEND_TOOL] };
}

// ---------- 对话事件 → QQ ----------
function toolLabel(name, input = {}) {
  const map = { Bash: '运行命令', PowerShell: '运行命令', Write: '写入文件', Edit: '编辑文件', MultiEdit: '编辑文件', NotebookEdit: '编辑笔记本', WebFetch: '读取网页', WebSearch: '搜索网络' };
  const what = input.command || input.file_path || input.url || input.query || input.description || '';
  return `${map[name] || '调用工具 ' + name}${what ? '：' + String(what).slice(0, 300) : ''}`;
}
// ---------- 私聊流式输出 ----------
// 做法参考 dsh-qqbot：QQ 只在私聊开放 stream_messages，而且内容要“只往后追加”——
// 每一帧都是上一帧加上新文字。中途改写或删掉内容，QQ 会显示“此条消息不支持显示”。
// 所以：Claude 每说一段话（两次工具调用之间的文字）就单独开一条流式消息，只追加文字，这段说完就关掉；
// 调用工具期间不开流式，用“正在输入”提示。没能流式发出的最终回答，最后用普通消息补发，保证一定送到。
const STREAM_MAX = 3800;                 // 一条流式消息最多放多少字，超出部分说完后用普通消息续发
const STREAM_THROTTLE = 300;             // QQ 要求最快 300ms 一帧
const STREAM_OPEN_WINDOW = 4.5 * 60_000; // 流式必须挂在 5 分钟内的消息下面
class Segment {
  constructor(b, c) {
    this.b = b; this.c = c;
    this.session = null; this.text = ''; this.sent = 0; this.failed = false; this.done = false;
    this.chain = Promise.resolve(); this.timer = null;
  }
  append(t) {
    if (this.done) return;
    this.text += t;
    if (!this.timer && !this.failed) this.timer = setTimeout(() => { this.timer = null; this.enqueue(this.text.slice(0, STREAM_MAX)); }, STREAM_THROTTLE);
  }
  enqueue(frame) { this.chain = this.chain.then(() => this.send(frame)); return this.chain; }
  async send(frame) {
    if (this.failed || !frame.trim()) return false;
    if (!this.session) {
      try { this.session = this.b.openStream({ target: this.c.target, throttleMs: STREAM_THROTTLE }); this.c.passiveCount++; }
      catch (e) { this.failed = true; console.warn('[qqbot] 开启流式消息失败，改用普通消息：' + (e?.message || e)); return false; }
    }
    try { await this.session.update(frame); this.sent++; return true; }
    catch (e) { console.warn('[qqbot] 流式更新失败：' + (e?.message || e)); return false; }
  }
  // 这段话说完：用完整文字发最后一帧并关闭。返回是否成功送到（成功的话超出 STREAM_MAX 的部分已用普通消息续发）
  async finish(fullText, extra = '') {
    clearTimeout(this.timer); this.timer = null;
    if (this.done) return false;
    this.done = true;
    const text = (fullText ?? this.text) + extra;
    let ok = false;
    if (this.sent > 0 && !this.failed) ok = await this.enqueue(text.slice(0, STREAM_MAX));
    else await this.chain;
    if (this.session) { try { await this.session.complete(); } catch (e) { console.warn('[qqbot] 结束流式消息失败：' + (e?.message || e)); } }
    if (ok && text.length > STREAM_MAX) await replyChat(this.c.chatId, text.slice(STREAM_MAX));
    return ok;
  }
}
// 还能不能再开一条流式消息：开关打开、私聊、挂靠的消息还在 5 分钟内、被动回复次数还留一次给最终回答
function canStream(c) {
  return cfg.streaming === true && bot && c.target?.scope === 'c2c' && c.target.msgId
    && Date.now() - c.inboundAt < STREAM_OPEN_WINDOW && c.passiveCount < PASSIVE_MAX - 1;
}
// 同一个 QQ 会话的发送按顺序排队，保证先说的先到
function queue(c, fn) { c.out = (c.out || Promise.resolve()).then(fn).catch((e) => console.error('[qqbot] 发送出错：', e)); return c.out; }

function onRunEvent(ev) {
  const chatId = ev.chatId;
  if (!String(chatId).startsWith('qq:')) return;
  const c = chats.get(chatId);
  if (!c) return;
  c.chatId = chatId;
  switch (ev.type) {
    case 'run_start':
      // 网页上接着聊这个会话时不推到 QQ；QQ 发起的和撞限额后的自动继续才推
      if (ev.auto) { c.fromQQ = true; c.texts = []; }
      c.seg = null; c.delivered = new Set(); c.anyDelivered = false;
      if (c.fromQQ && c.target?.scope === 'c2c' && bot) {
        const b = bot;
        // 没在流式输出时显示“正在输入”
        const typing = () => { if (!c.seg && Date.now() - c.inboundAt < 5 * 60_000) b.sendTyping(c.target, 30).catch(() => {}); };
        typing();
        clearInterval(c.typingTimer);
        c.typingTimer = setInterval(typing, 25_000);
      }
      break;
    case 'delta':
      if (!c.fromQQ || !ev.text) break;
      if (!c.seg && canStream(c)) c.seg = new Segment(bot, c);
      c.seg?.append(ev.text);
      break;
    case 'session':
      if (ev.sessionId) { const p = cfg.peers[chatId] || (cfg.peers[chatId] = {}); if (p.sessionId !== ev.sessionId) { p.sessionId = ev.sessionId; save(); } }
      break;
    case 'message': {
      if (!c.fromQQ || ev.role !== 'assistant' || !Array.isArray(ev.content)) break;
      const said = ev.content.filter((b) => b.type === 'text' && b.text?.trim()).map((b) => b.text).join('\n\n');
      for (const blk of ev.content) {
        if (blk.type === 'text' && blk.text?.trim()) c.texts.push(blk.text);
        if (blk.type === 'tool_use') c.texts = []; // 只保留最后一次调用工具之后的文字，也就是最终回答
      }
      // 这段话说完了：把流式消息收尾。最后一帧用流式累积的文字，保证跟之前的帧是“只追加”的关系
      const seg = c.seg; c.seg = null;
      if (seg) queue(c, async () => { if (await seg.finish()) { c.delivered.add(said || seg.text); c.anyDelivered = true; } });
      break;
    }
    case 'permission_request':
      if (!c.fromQQ) break;
      c.pendingPerm = ev.id;
      queue(c, () => replyChat(chatId, `Claude 想要${toolLabel(ev.toolName, ev.input)}\n\n回复“允许”“总是允许”或“拒绝”。`));
      break;
    case 'question_request': {
      if (!c.fromQQ) break;
      const qs = (ev.questions || []).slice(0, 4);
      c.pendingQ = { id: ev.id, questions: qs };
      queue(c, () => replyChat(chatId, questionText(qs)));
      break;
    }
    case 'permission_resolved':
      if (c.pendingPerm === ev.id) c.pendingPerm = null;
      if (c.pendingQ?.id === ev.id) c.pendingQ = null;
      break;
    case 'error':
      if (c.fromQQ) queue(c, () => replyChat(chatId, '出错了：' + ev.message));
      break;
    case 'run_end': {
      clearInterval(c.typingTimer); c.typingTimer = null;
      c.pendingPerm = null;
      if (!c.fromQQ) break;
      c.fromQQ = false;
      const finals = c.texts.slice(); c.texts = [];
      const seg = c.seg; c.seg = null;
      const limitNote = '撞到了 Claude 的用量限额，额度恢复后会自动继续，完成后把结果发给你。';
      queue(c, async () => {
        if (ev.aborted) {
          if (seg && await seg.finish(seg.text, '\n\n（已停止）')) return;
          return;
        }
        if (seg && await seg.finish()) { c.delivered.add(seg.text); c.anyDelivered = true; }
        // 最终回答里没能流式送到的部分，用普通消息补发
        const missing = finals.filter((t) => ![...c.delivered].some((d) => d.includes(t.trim())));
        if (missing.length) await replyChat(chatId, missing.join('\n\n'));
        else if (!finals.length && !c.anyDelivered && !ev.rateLimited) await replyChat(chatId, '（已完成，没有文字回复）');
        if (ev.rateLimited) await replyChat(chatId, limitNote);
      });
      break;
    }
  }
}

// ---------- 扫码绑定 ----------
async function startBind() {
  cancelBind();
  const { startQrConnect } = await import('@tencent-connect/qqbot-connector');
  const b = { stop: null, url: null, qr: null, state: 'waiting', error: null };
  bind = b;
  b.stop = startQrConnect({
    onQrDisplayed: async (url) => {
      if (bind !== b) return;
      b.url = url;
      const svg = await QRCode.toString(url, { type: 'svg', margin: 1, errorCorrectionLevel: 'M' }).catch(() => null);
      b.qr = svg ? 'data:image/svg+xml;base64,' + Buffer.from(svg).toString('base64') : null; // 前端用 <img> 显示，不直接插入 SVG
    },
    onQrExpired: () => { if (bind === b) b.state = 'refreshing'; },
    onSuccess: async (list) => {
      if (bind !== b) return;
      const cred = list?.[0];
      if (!cred?.appId || !cred?.appSecret) { b.state = 'failed'; b.error = '没有拿到机器人凭据'; return; }
      const sameBot = cred.appId === cfg.appId;
      cfg.appId = cred.appId; cfg.appSecret = cred.appSecret;
      if (cred.userOpenid) cfg.ownerOpenid = cred.userOpenid;
      if (!sameBot) { cfg.peers = {}; cfg.c2cAllow = []; cfg.groupAllow = []; } // 换了机器人，openid 都变了
      cfg.enabled = true;
      save();
      b.state = 'done';
      console.log(`[qqbot] 扫码绑定成功，AppID ${cred.appId}`);
      await startBot().catch((e) => setStatus('error', e.message));
    },
    onFailure: (err) => { if (bind === b && b.state !== 'done') { b.state = 'failed'; b.error = String(err?.message || err); } },
  }, { displayQrCodeToConsole: false });
}
function cancelBind() {
  if (bind?.stop && bind.state !== 'done') { try { bind.stop(); } catch { /* ignore */ } }
  bind = null;
}

// ---------- 对外 ----------
export function getQQStatus() {
  return {
    bound: bound(), enabled: cfg.enabled, appId: cfg.appId ? cfg.appId : null,
    state: status.state, error: status.error,
    owner: cfg.ownerOpenid ? { id: cfg.ownerOpenid.slice(0, 8), openid: cfg.ownerOpenid } : null,
    cwd: workdir(), model: cfg.model || '', mode: cfg.mode, markdown: Boolean(cfg.markdown), streaming: cfg.streaming === true,
    c2cAllow: cfg.c2cAllow.map((u) => ({ id: u.openid.slice(0, 8), openid: u.openid, name: u.name, addedAt: u.addedAt })),
    groupAllow: cfg.groupAllow.map((g) => ({ id: g.openid.slice(0, 8), openid: g.openid, addedAt: g.addedAt })),
    pair: pair && Date.now() < pair.expiresAt ? { code: pair.code, expiresAt: pair.expiresAt } : null,
    bind: bind ? { state: bind.state, url: /^https:\/\//.test(bind.url || '') ? bind.url : null, qr: bind.qr, error: bind.error } : null,
    serverNow: Date.now(),
  };
}

export async function qqAction(body) {
  const op = String(body.op || '');
  switch (op) {
    case 'bind_start': await startBind(); break;
    case 'bind_cancel': cancelBind(); break;
    case 'manual': {
      const appId = String(body.appId || '').trim(), appSecret = String(body.appSecret || '').trim();
      if (!/^\d{5,20}$/.test(appId)) throw new Error('AppID 应该是一串数字');
      if (appSecret.length < 8 || appSecret.length > 128) throw new Error('AppSecret 格式不对');
      if (appId !== cfg.appId) { cfg.ownerOpenid = ''; cfg.peers = {}; cfg.c2cAllow = []; cfg.groupAllow = []; }
      cfg.appId = appId; cfg.appSecret = appSecret; cfg.enabled = true;
      save(); cancelBind();
      await startBot();
      break;
    }
    case 'unbind':
      cancelBind(); stopBot();
      cfg = { ...defaults(), cwd: cfg.cwd, model: cfg.model, mode: cfg.mode };
      pair = null; chats.clear(); save();
      setStatus('unbound');
      break;
    case 'enable':
      if (!bound()) throw new Error('还没有绑定机器人');
      cfg.enabled = Boolean(body.enabled); save();
      if (cfg.enabled) await startBot(); else { stopBot(); setStatus('disabled'); }
      break;
    case 'reconnect':
      if (!bound()) throw new Error('还没有绑定机器人');
      await startBot();
      break;
    case 'settings': {
      if (body.cwd !== undefined) {
        const p = path.resolve(String(body.cwd));
        if (!host.workspaces.has(p)) throw new Error('只能选择已添加的工作区');
        cfg.cwd = p;
      }
      if (body.model !== undefined) {
        if (!host.MODELS.includes(String(body.model))) throw new Error('不支持的模型');
        cfg.model = String(body.model);
      }
      if (body.mode !== undefined) {
        if (!host.MODES.includes(String(body.mode))) throw new Error('不支持的权限模式');
        cfg.mode = String(body.mode);
      }
      if (body.streaming !== undefined) cfg.streaming = Boolean(body.streaming);
      if (body.markdown !== undefined) {
        cfg.markdown = Boolean(body.markdown);
        save();
        if (bound() && cfg.enabled) await startBot(); // markdownSupport 是构造参数，要重连才生效
        break;
      }
      save();
      break;
    }
    case 'pair': {
      if (!bound()) throw new Error('还没有绑定机器人');
      pair = { code: String(crypto.randomInt(100000, 1000000)), expiresAt: Date.now() + PAIR_TTL };
      break;
    }
    case 'pair_cancel': pair = null; break;
    case 'remove': {
      const openid = String(body.openid || '');
      if (body.kind === 'group') cfg.groupAllow = cfg.groupAllow.filter((g) => g.openid !== openid);
      else if (body.kind === 'owner') cfg.ownerOpenid = '';
      else cfg.c2cAllow = cfg.c2cAllow.filter((u) => u.openid !== openid);
      save();
      break;
    }
    default: throw new Error('未知操作');
  }
  return getQQStatus();
}

export function initQQBot(h) {
  host = h;
  load();
  host.onRunEvent(onRunEvent);
  // 测试用：同一台电脑上再起一个测试服务时设 CR_NO_QQBOT=1，免得用同一个机器人登录、把正式服务挤下线
  if (process.env.CR_NO_QQBOT === '1') { setStatus('disabled', '测试模式（CR_NO_QQBOT=1），QQ 机器人未启动'); return; }
  if (bound() && cfg.enabled) startBot().catch((e) => { setStatus('error', e.message); console.error('[qqbot] 启动失败：' + e.message); });
  else setStatus(bound() ? 'disabled' : 'unbound');
}
export function stopQQBot() { cancelBind(); stopBot(); }

// 仅供自动化测试：注入假的 QQ 客户端，直接驱动收消息 / 对话事件
export const __test = {
  useBot(b) { bot = b; },
  onMessage: (msg) => onMessage(bot, msg),
  onRunEvent,
  setPair(code) { pair = { code, expiresAt: Date.now() + PAIR_TTL }; },
  sendFileToChat,
  setHost(h) { host = h; },
  setCfg(c) { cfg = c; },
  cfg: () => cfg,
  chats,
};

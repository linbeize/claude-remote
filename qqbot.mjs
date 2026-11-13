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
    markdown: false,
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
  const who = (msg.kind === 'group' ? `（来自 QQ 群，发送者 ${msg.senderName || String(msg.senderId || '').slice(0, 8)}` : '（来自 QQ 私聊') + `。要把图片或文件发给对方，用 ${SEND_TOOL} 工具）`;

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
      return say(['可用命令：', '/new  开始新会话（清空上下文）', '/stop  停止当前任务', '/status  查看当前会话状态', '/model [opus|sonnet|haiku|fable|default]  查看或切换模型', '', '需要确认的操作会提示你回复“允许”“总是允许”或“拒绝”。'].join('\n'));
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
function onRunEvent(ev) {
  const chatId = ev.chatId;
  if (!String(chatId).startsWith('qq:')) return;
  const c = chats.get(chatId);
  if (!c) return;
  switch (ev.type) {
    case 'run_start':
      // 网页上接着聊这个会话时不推到 QQ；QQ 发起的和撞限额后的自动继续才推
      if (ev.auto) { c.fromQQ = true; c.texts = []; }
      if (c.fromQQ && c.target?.scope === 'c2c' && bot) {
        const b = bot;
        const typing = () => { if (Date.now() - c.inboundAt < 5 * 60_000) b.sendTyping(c.target, 30).catch(() => {}); };
        typing();
        clearInterval(c.typingTimer);
        c.typingTimer = setInterval(typing, 25_000);
      }
      break;
    case 'session':
      if (ev.sessionId) { const p = cfg.peers[chatId] || (cfg.peers[chatId] = {}); if (p.sessionId !== ev.sessionId) { p.sessionId = ev.sessionId; save(); } }
      break;
    case 'message':
      if (!c.fromQQ || ev.role !== 'assistant' || !Array.isArray(ev.content)) break;
      for (const blk of ev.content) {
        if (blk.type === 'text' && blk.text?.trim()) c.texts.push(blk.text);
        if (blk.type === 'tool_use') c.texts = []; // 只保留最后一次调用工具之后的文字，也就是最终回答
      }
      break;
    case 'permission_request':
      if (!c.fromQQ) break;
      c.pendingPerm = ev.id;
      replyChat(chatId, `Claude 想要${toolLabel(ev.toolName, ev.input)}\n\n回复“允许”“总是允许”或“拒绝”。`);
      break;
    case 'permission_resolved':
      if (c.pendingPerm === ev.id) c.pendingPerm = null;
      break;
    case 'error':
      if (c.fromQQ) replyChat(chatId, '出错了：' + ev.message);
      break;
    case 'run_end': {
      clearInterval(c.typingTimer); c.typingTimer = null;
      c.pendingPerm = null;
      if (!c.fromQQ) break;
      c.fromQQ = false;
      const answer = c.texts.join('\n\n').trim();
      c.texts = [];
      if (ev.aborted) break;
      if (answer) replyChat(chatId, answer);
      else if (!ev.rateLimited) replyChat(chatId, '（已完成，没有文字回复）');
      if (ev.rateLimited) replyChat(chatId, '撞到了 Claude 的用量限额，额度恢复后会自动继续，完成后把结果发给你。');
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
    cwd: workdir(), model: cfg.model || '', mode: cfg.mode, markdown: Boolean(cfg.markdown),
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
  cfg: () => cfg,
  chats,
};

// 用量：订阅套餐的 5 小时 / 7 天限额，以及本机所有 Claude Code 会话的 token 统计和按 API 价格折算的费用
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { query } from '@anthropic-ai/claude-agent-sdk';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const PROJECTS = path.join(process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), '.claude'), 'projects');

// ---------- 套餐限额 ----------
// 用 SDK 的 /usage 控制请求拿，不发任何消息、不消耗额度。这是 SDK 标注为实验性的接口，拿不到就返回 null。
let limitsCache = null;
let limitsAt = 0;
let limitsInflight = null;
const LIMITS_TTL = 60_000;

export function invalidateLimits() { limitsAt = 0; }

export async function getLimits(cwd) {
  if (limitsCache && Date.now() - limitsAt < LIMITS_TTL) return limitsCache;
  if (limitsInflight) return limitsInflight;
  limitsInflight = (async () => {
    let release;
    const idle = { async *[Symbol.asyncIterator]() { await new Promise((r) => { release = r; }); } };
    const q = query({ prompt: idle, options: { cwd } });
    try {
      const fn = q.usage_EXPERIMENTAL_MAY_CHANGE_DO_NOT_RELY_ON_THIS_API_YET;
      if (typeof fn !== 'function') throw new Error('当前 SDK 不支持读取套餐用量');
      const u = await Promise.race([
        fn.call(q, { skipBehaviors: true }),
        new Promise((_, rej) => setTimeout(() => rej(new Error('读取超时')), 20_000)),
      ]);
      const rl = u.rate_limits || {};
      // 倒计时用 Anthropic 那边的时钟算（响应里的 as_of），不依赖本机时钟准不准
      const fetchedAt = Date.now();
      const apiNow = Date.parse(rl.seven_day_breakdown?.as_of || '') || fetchedAt;
      const win = (w) => (w && w.utilization != null ? {
        pct: w.utilization, resetsAt: w.resets_at,
        resetsInMs: w.resets_at ? Math.max(0, Date.parse(w.resets_at) - apiNow) : null,
      } : null);
      limitsCache = {
        ok: true,
        plan: u.subscription_type,
        available: u.rate_limits_available,
        fiveHour: win(rl.five_hour),
        sevenDay: win(rl.seven_day),
        sevenDayOpus: win(rl.seven_day_opus),
        sevenDaySonnet: win(rl.seven_day_sonnet),
        models: (rl.model_scoped || []).map((m) => ({ name: m.display_name, ...win(m) })).filter((m) => m.pct != null),
        extra: rl.extra_usage?.is_enabled ? { used: rl.extra_usage.used_credits, limit: rl.extra_usage.monthly_limit, currency: rl.extra_usage.currency } : null,
        fetchedAt, clockSkewMs: fetchedAt - apiNow,
      };
    } catch (err) {
      limitsCache = { ok: false, error: String(err?.message || err), fetchedAt: Date.now() };
    } finally {
      release?.();
      q.close();
      limitsAt = Date.now();
      limitsInflight = null;
    }
    return limitsCache;
  })();
  return limitsInflight;
}

// ---------- 价格（美元 / 百万 token），按 Anthropic API 公开价折算 ----------
// cacheRead 没写的按输入价 10%；缓存写入：5 分钟缓存 = 输入价 1.25 倍，1 小时缓存 = 2 倍
// 可以用 data/pricing.json 覆盖或补充，格式同下：{ "模型前缀": { "input": 4, "output": 20, "cacheRead": 0.2 } }
const DEFAULT_PRICES = {
  'claude-fable-5-2': { input: 8, output: 40, cacheRead: 0.2 },
  'claude-mythos-5-2': { input: 8, output: 40, cacheRead: 0.2 },
  'claude-fable-5-1': { input: 10, output: 50 },
  'claude-mythos-5-1': { input: 10, output: 50 },
  'claude-fable-5': { input: 10, output: 50 },
  'claude-opus-5-5': { input: 4, output: 20, cacheRead: 0.2 },
  'claude-opus-5': { input: 5, output: 25 },
  'claude-opus-4-8': { input: 5, output: 25 },
  'claude-opus-4-7': { input: 5, output: 25 },
  'claude-opus-4-6': { input: 5, output: 25 },
  'claude-sonnet-5-5': { input: 2, output: 10, cacheRead: 0.1 },
  'claude-sonnet-5': { input: 2, output: 10 },
  'claude-sonnet-4-6': { input: 3, output: 15 },
  'claude-haiku-5-5': { input: 0.1, output: 0.5 },
  'claude-haiku-4-5': { input: 1, output: 5 },
};
function loadPrices() {
  try { return { ...DEFAULT_PRICES, ...JSON.parse(fs.readFileSync(path.join(DIR, 'data', 'pricing.json'), 'utf8')) }; }
  catch { return DEFAULT_PRICES; }
}
// 去掉日期后缀、平台前缀（anthropic. / us.anthropic. 等），取最长匹配的前缀
function priceFor(prices, model) {
  const m = String(model || '').toLowerCase().replace(/^([a-z]+\.)*anthropic\./, '').replace(/-\d{8}$/, '').replace(/@.*$/, '').replace(/\[.*\]$/, '');
  let best = null;
  for (const key of Object.keys(prices)) if ((m === key || m.startsWith(key + '-')) && (!best || key.length > best.length)) best = key;
  return best ? { key: best, ...prices[best] } : null;
}
function costOf(p, u) {
  if (!p) return null;
  const cr = p.cacheRead ?? p.input * 0.1;
  const w5 = u.cw5 ?? 0, w1 = u.cw1 ?? 0, wOther = Math.max(0, u.cacheWrite - w5 - w1);
  const usd = (u.input * p.input + u.output * p.output + u.cacheRead * cr + (w5 + wOther) * p.input * 1.25 + w1 * p.input * 2) / 1e6;
  return u.fast ? usd * 2 : usd; // 快速模式按 2 倍
}

// ---------- 扫描会话记录 ----------
// 每个文件按 修改时间+大小 缓存解析结果，只重新解析变了的文件
const fileCache = new Map();
function listJsonl(dir, out = []) {
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) listJsonl(p, out);
    else if (e.name.endsWith('.jsonl')) out.push(p);
  }
  return out;
}
async function parseFile(file) {
  const rows = new Map(); // 同一条回复会按内容块写多行，按 消息id+请求id 去重，保留最后一行（用量最完整）
  const rl = readline.createInterface({ input: fs.createReadStream(file, 'utf8'), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.includes('"usage"') || !line.includes('"assistant"')) continue;
    let o;
    try { o = JSON.parse(line); } catch { continue; }
    const msg = o.message;
    const u = msg?.usage;
    if (o.type !== 'assistant' || !u || !msg.model || msg.model === '<synthetic>') continue;
    const cc = u.cache_creation || {};
    rows.set(`${msg.id}:${o.requestId || ''}`, {
      ts: Date.parse(o.timestamp) || 0,
      model: msg.model,
      cwd: o.cwd || '',
      session: o.sessionId || '',
      input: u.input_tokens || 0,
      output: u.output_tokens || 0,
      cacheRead: u.cache_read_input_tokens || 0,
      cacheWrite: u.cache_creation_input_tokens || 0,
      cw5: cc.ephemeral_5m_input_tokens, cw1: cc.ephemeral_1h_input_tokens,
      fast: u.speed === 'fast',
    });
  }
  return rows;
}
async function allRows() {
  const files = listJsonl(PROJECTS);
  const seen = new Set(files);
  for (const f of fileCache.keys()) if (!seen.has(f)) fileCache.delete(f);
  for (const f of files) {
    let st;
    try { st = fs.statSync(f); } catch { continue; }
    const c = fileCache.get(f);
    if (c && c.mtime === st.mtimeMs && c.size === st.size) continue;
    fileCache.set(f, { mtime: st.mtimeMs, size: st.size, rows: await parseFile(f) });
  }
  const merged = new Map();
  for (const c of fileCache.values()) for (const [k, r] of c.rows) merged.set(k, r);
  return [...merged.values()];
}

const localDay = (ts) => { const d = new Date(ts); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
const blank = () => ({ requests: 0, input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0, unpriced: 0 });
function add(acc, r, cost) {
  acc.requests++; acc.input += r.input; acc.output += r.output; acc.cacheRead += r.cacheRead; acc.cacheWrite += r.cacheWrite;
  if (cost == null) acc.unpriced++; else acc.cost += cost;
}

// days: 1 = 今天，7 / 30 / 90，0 = 全部
export async function getStats(days) {
  const prices = loadPrices();
  const rows = await allRows();
  const now = new Date();
  const start = days > 0 ? new Date(now.getFullYear(), now.getMonth(), now.getDate() - (days - 1)).getTime() : 0;
  const total = blank();
  const byDay = new Map(), byModel = new Map(), byProject = new Map();
  for (const r of rows) {
    if (r.ts < start) continue;
    const p = priceFor(prices, r.model);
    const cost = costOf(p, r);
    add(total, r, cost);
    const day = localDay(r.ts);
    if (!byDay.has(day)) byDay.set(day, blank());
    add(byDay.get(day), r, cost);
    if (!byModel.has(r.model)) byModel.set(r.model, { ...blank(), priced: Boolean(p) });
    add(byModel.get(r.model), r, cost);
    const proj = r.cwd || '(未知目录)';
    if (!byProject.has(proj)) byProject.set(proj, blank());
    add(byProject.get(proj), r, cost);
  }
  // 补齐没有用量的日子，图表才连续
  const daysList = [];
  if (byDay.size) {
    const first = days > 0 ? start : Math.min(...rows.map((r) => r.ts).filter(Boolean));
    for (let d = new Date(first); d <= now; d.setDate(d.getDate() + 1)) {
      const k = localDay(d.getTime());
      daysList.push({ day: k, ...(byDay.get(k) || blank()) });
    }
  }
  const sorted = (m, key) => [...m.entries()].map(([k, v]) => ({ [key]: k, ...v })).sort((a, b) => b.cost - a.cost || b.requests - a.requests);
  return {
    days, generatedAt: Date.now(),
    total,
    byDay: daysList.slice(-120),
    byModel: sorted(byModel, 'model'),
    byProject: sorted(byProject, 'project').slice(0, 30),
    prices: Object.entries(prices).map(([model, p]) => ({ model, input: p.input, output: p.output, cacheRead: p.cacheRead ?? p.input * 0.1, cacheWrite5m: p.input * 1.25, cacheWrite1h: p.input * 2 })),
  };
}

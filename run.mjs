// 守护进程：启动 server.mjs，崩溃后自动重启。用法：npm run serve
// - 连续崩溃时等待时间逐步加长（1、2、4……最多 30 秒），稳定运行 1 分钟后重新计数
// - 账号或证书没配置好（退出码 78）时不重启，直接退出并提示
// - 输出同时写到终端和 data/logs/server.log（超过 10MB 时把旧日志改名为 server.log.1）
// - Ctrl+C 正常停止，不会重启
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const LOG_DIR = path.join(DIR, 'data', 'logs');
const LOG = path.join(LOG_DIR, 'server.log');
const CONFIG_ERROR = 78;
const STABLE_MS = 60_000;
const MAX_DELAY = 30_000;
const LOG_MAX = 10 * 1024 * 1024;

fs.mkdirSync(LOG_DIR, { recursive: true });
let logStream = null;
function openLog() {
  try { if (fs.statSync(LOG).size > LOG_MAX) fs.renameSync(LOG, LOG + '.1'); } catch { /* 还没有日志 */ }
  logStream = fs.createWriteStream(LOG, { flags: 'a' });
}
openLog();
let written = 0;
function write(chunk, toErr) {
  (toErr ? process.stderr : process.stdout).write(chunk);
  logStream.write(chunk);
  written += chunk.length;
  if (written > LOG_MAX) { written = 0; logStream.end(); openLog(); }
}
const stamp = () => new Date().toLocaleString('zh-CN', { hour12: false });
const note = (msg) => write(`[守护 ${stamp()}] ${msg}\n`, false);

let child = null;
let stopping = false;
let attempt = 0;
let timer = null;

function start() {
  timer = null;
  const startedAt = Date.now();
  child = spawn(process.execPath, ['--env-file-if-exists=.env', 'server.mjs'], {
    cwd: DIR, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, CR_SUPERVISOR_PID: String(process.pid) }, windowsHide: true,
  });
  note(`服务已启动（进程 ${child.pid}）`);
  child.stdout.on('data', (d) => write(d, false));
  child.stderr.on('data', (d) => write(d, true));
  child.on('exit', (code, signal) => {
    child = null;
    if (stopping) { note('服务已停止'); return finish(0); }
    if (code === CONFIG_ERROR) { note('配置不完整，不再自动重启。按上面的提示处理后，再运行 npm run serve'); return finish(1); }
    if (Date.now() - startedAt > STABLE_MS) attempt = 0;
    const delay = Math.min(MAX_DELAY, 1000 * 2 ** attempt);
    attempt++;
    note(`服务退出了（${signal ? '信号 ' + signal : '退出码 ' + code}），${delay / 1000} 秒后自动重启（第 ${attempt} 次）`);
    timer = setTimeout(start, delay);
  });
}

function finish(code) { logStream.end(() => process.exit(code)); }

function stop() {
  if (stopping) return;
  stopping = true;
  note('收到停止信号，正在关闭…');
  if (timer) { clearTimeout(timer); return finish(0); }
  if (!child) return finish(0);
  child.kill();
  setTimeout(() => { if (child) child.kill('SIGKILL'); }, 5000).unref();
}
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
process.on('SIGHUP', stop); // 关掉终端窗口

start();

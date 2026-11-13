// 设置登录账号（用户名 + 密码）：npm run setup
// 会写入 data/auth.json，并让所有已登录设备下线
import readline from 'node:readline';
import { hashPassword, saveAuth, loadAuth, destroyAllSessions, AUTH_FILE } from './auth.mjs';

const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
let muted = false;
rl._writeToOutput = (s) => { if (!muted || s.includes('\n')) rl.output.write(muted ? '\n' : s); };

const ask = (q) => new Promise((r) => rl.question(q, r));
async function askHidden(q) {
  process.stdout.write(q);
  muted = true;
  const ans = await ask('');
  muted = false;
  return ans;
}

console.log('\n=== Claude Remote 账号设置 ===');
if (loadAuth()) console.log(`已存在账号（${AUTH_FILE}），继续会覆盖它，并让所有已登录设备下线。\n`);

let username = '';
while (!/^[\w.@-]{3,32}$/.test(username)) {
  username = (await ask('用户名（3-32 位字母数字）: ')).trim();
}

let password = '';
for (;;) {
  password = await askHidden('密码（至少 12 位）: ');
  if (password.length < 12) { console.log('太短了，至少 12 位。'); continue; }
  const again = await askHidden('再输一次: ');
  if (again !== password) { console.log('两次不一致，重来。'); continue; }
  break;
}

// 两步验证暂时关闭（auth.mjs 里的 TOTP 校验代码保留，以后要开再加回设置步骤即可）
const auth = { username, ...hashPassword(password), createdAt: new Date().toISOString() };

saveAuth(auth);
destroyAllSessions();
rl.close();
console.log(`\n✓ 已保存到 ${AUTH_FILE}`);
console.log('重启服务（npm start）后生效。\n');

// 第一次申请 Let's Encrypt 证书：npm run cert
// 需要：域名已解析到本机、80 端口没被占用且防火墙已放行。之后由服务自动续期。
import http from 'node:http';
import readline from 'node:readline/promises';
import { getTermsUrl, issueCert, handleChallenge } from './tls.mjs';

const domain = process.env.TLS_DOMAIN;
const staging = process.argv.includes('--staging');
if (!domain) {
  console.error('请在 .env 里设置 TLS_DOMAIN=你的域名');
  process.exit(1);
}

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
console.log(`\n=== 为 ${domain} 申请 Let's Encrypt 证书${staging ? '（测试环境，证书浏览器不信任）' : ''} ===\n`);
console.log('申请证书需要同意 Let\'s Encrypt 订户协议：');
console.log('  ' + await getTermsUrl(staging));
const yes = (await rl.question('\n你同意这份协议吗？[y/N]: ')).trim().toLowerCase();
if (yes !== 'y') { console.log('已取消。'); process.exit(1); }
const email = (await rl.question('邮箱（可选，证书快到期还没续上时 Let\'s Encrypt 会提醒你，直接回车跳过）: ')).trim();
rl.close();

// 临时在 80 端口回应验证请求
const srv = http.createServer((req, res) => { if (!handleChallenge(req, res)) { res.writeHead(404); res.end(); } });
await new Promise((resolve, reject) => {
  srv.once('error', (e) => reject(e.code === 'EADDRINUSE' ? new Error('80 端口被占用了，先把正在运行的服务停掉（Ctrl+C）再试') : e));
  srv.listen(80, '0.0.0.0', resolve);
});

try {
  await issueCert({ domain, email, agreeTos: true, staging });
  console.log('\n✓ 完成。现在运行 npm start，打开 https://' + domain);
} catch (err) {
  console.error('\n✗ 申请失败：' + (err.message || err));
  console.error('常见原因：防火墙没放行 80 端口、域名没解析到本机、短时间内失败次数太多（可以先加 --staging 测试）。');
  process.exitCode = 1;
} finally {
  srv.close();
}

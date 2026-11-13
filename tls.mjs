// Let's Encrypt 证书：HTTP-01 验证（需要 80 端口能从公网访问）
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as acme from 'acme-client';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'data', 'tls');
const ACCOUNT_KEY = path.join(DIR, 'account.key');
const ACCOUNT_JSON = path.join(DIR, 'account.json');
const RENEW_BEFORE_MS = 30 * 24 * 3600 * 1000; // 到期前 30 天续期

// HTTP-01 验证用：token -> keyAuthorization，由 80 端口的服务读取
export const challenges = new Map();

export function directoryUrl(staging) {
  return staging ? acme.directory.letsencrypt.staging : acme.directory.letsencrypt.production;
}

const certFile = (domain) => path.join(DIR, `${domain}.crt`);
const keyFile = (domain) => path.join(DIR, `${domain}.key`);

export function loadCert(domain) {
  try {
    const cert = fs.readFileSync(certFile(domain), 'utf8');
    const key = fs.readFileSync(keyFile(domain), 'utf8');
    const info = acme.crypto.readCertificateInfo(cert);
    return { cert, key, notAfter: info.notAfter, issuer: info.issuer.commonName };
  } catch {
    return null;
  }
}
export const needsRenewal = (c) => !c || c.notAfter.getTime() - Date.now() < RENEW_BEFORE_MS;

export function loadAccount() {
  try { return JSON.parse(fs.readFileSync(ACCOUNT_JSON, 'utf8')); } catch { return null; }
}

// 处理 80 端口上的验证请求，返回 true 表示已处理
export function handleChallenge(req, res) {
  const prefix = '/.well-known/acme-challenge/';
  if (!req.url.startsWith(prefix)) return false;
  const keyAuth = challenges.get(req.url.slice(prefix.length));
  res.writeHead(keyAuth ? 200 : 404, { 'Content-Type': 'text/plain' });
  res.end(keyAuth || 'not found');
  return true;
}

async function client({ staging, accountUrl }) {
  fs.mkdirSync(DIR, { recursive: true });
  let accountKey;
  if (fs.existsSync(ACCOUNT_KEY)) accountKey = fs.readFileSync(ACCOUNT_KEY);
  else {
    accountKey = await acme.crypto.createPrivateEcdsaKey();
    fs.writeFileSync(ACCOUNT_KEY, accountKey, { mode: 0o600 });
  }
  return new acme.Client({ directoryUrl: directoryUrl(staging), accountKey, accountUrl });
}

export async function getTermsUrl(staging) {
  return (await client({ staging })).getTermsOfServiceUrl();
}

// 申请或续期证书。第一次必须由用户本人同意 Let's Encrypt 订户协议（agreeTos）
export async function issueCert({ domain, email, agreeTos, staging, log = console.log }) {
  const account = loadAccount();
  if (!agreeTos && !account?.tosAgreedAt) throw new Error('还没有同意 Let\'s Encrypt 订户协议，请先运行 npm run cert');
  const useStaging = staging ?? account?.staging ?? false;
  // 测试环境和正式环境的账号不通用，切换时让它用同一把密钥重新查找/注册
  const c = await client({ staging: useStaging, accountUrl: account?.staging === useStaging ? account.url : undefined });
  const [key, csr] = await acme.crypto.createCsr({ commonName: domain, altNames: [domain] }, await acme.crypto.createPrivateEcdsaKey());
  log(`[tls] 正在为 ${domain} 申请证书${useStaging ? '（测试环境）' : ''}…`);
  const cert = await c.auto({
    csr,
    email: email || account?.email || undefined,
    termsOfServiceAgreed: true,
    challengePriority: ['http-01'],
    challengeCreateFn: async (_authz, challenge, keyAuthorization) => { challenges.set(challenge.token, keyAuthorization); },
    challengeRemoveFn: async (_authz, challenge) => { challenges.delete(challenge.token); },
  });
  fs.writeFileSync(keyFile(domain), key, { mode: 0o600 });
  fs.writeFileSync(certFile(domain), cert);
  fs.writeFileSync(ACCOUNT_JSON, JSON.stringify({
    url: c.getAccountUrl(),
    email: email || account?.email || null,
    staging: useStaging,
    tosAgreedAt: account?.tosAgreedAt || new Date().toISOString(),
  }, null, 2));
  const info = loadCert(domain);
  log(`[tls] 证书已保存，有效期到 ${info.notAfter.toISOString().slice(0, 10)}（签发者 ${info.issuer}）`);
  return info;
}

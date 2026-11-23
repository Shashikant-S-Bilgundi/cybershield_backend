// Test configuration: a throwaway database on the local MongoDB.
process.env.NODE_ENV = 'test';
process.env.MONGODB_URI = process.env.TEST_MONGODB_URI ?? 'mongodb://127.0.0.1:27017/shieldops_test';
process.env.APP_URL = 'http://localhost:5173';
process.env.ENCRYPTION_KEY = Buffer.alloc(32, 7).toString('base64');
process.env.COOKIE_SECURE = 'false';
process.env.TRUST_PROXY = '0';

// Phase 5: a test GitHub App. Its key pair is made fresh for each run; the fake GitHub API checks
// ShieldOps' app tokens with the public half.
import { generateKeyPairSync } from 'node:crypto';
import { existsSync } from 'node:fs';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
process.env.GITHUB_APP_ID = '12345';
process.env.GITHUB_APP_SLUG = 'shieldops-test';
process.env.GITHUB_APP_PRIVATE_KEY = privateKey.replace(/\n/g, '\\n');
process.env.TEST_GITHUB_PUBLIC_KEY = publicKey;
process.env.GITHUB_WEBHOOK_SECRET = 'whsec-test-secret';
process.env.GITHUB_API_URL = 'http://127.0.0.1:47321';
process.env.GITHUB_WEB_URL = 'https://github.example';
process.env.GITHUB_CLONE_BASE = 'file:///tmp/so-fake-gh';
process.env.DOCKERHUB_AUTH_URL = 'http://127.0.0.1:47321/dockerauth';
// Use locally installed scanners when present (TEST_SCANNER_BIN_DIR or /tmp/scan/bin).
const scanners = process.env.TEST_SCANNER_BIN_DIR ?? '/tmp/scan/bin';
if (existsSync(scanners)) process.env.SCANNER_BIN_DIR = scanners;
process.env.SCAN_CACHE_DIR = process.env.SCAN_CACHE_DIR ?? '/tmp/so-scan-cache';

// Phase 6: a private certificate authority for the HTTPS webhook receiver in the tests.
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
try {
  const d = '/tmp/so-test-ca';
  if (!existsSync(`${d}/leaf.pem`)) {
    mkdirSync(d, { recursive: true });
    const ossl = (...a: string[]) => execFileSync('openssl', a, { cwd: d, stdio: 'ignore' });
    ossl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', '/CN=ShieldOps Test CA', '-keyout', 'ca.key', '-out', 'ca.pem');
    writeFileSync(`${d}/san.cnf`, 'subjectAltName=IP:127.0.0.1,DNS:localhost\n');
    ossl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=127.0.0.1', '-keyout', 'leaf.key', '-out', 'leaf.csr');
    ossl('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '30', '-extfile', 'san.cnf', '-out', 'leaf.pem');
  }
  process.env.WEBHOOK_CA_FILE = `${d}/ca.pem`;
} catch {
  // openssl not available: the webhook delivery test skips itself.
}

// Phase 7: fake AI providers (see test/phase7.test.ts). Azure is left unset to test "not configured".
process.env.OPENAI_API_KEY = 'sk-test-openai-key-0000000000';
process.env.OPENAI_BASE_URL = 'http://127.0.0.1:47324/openai';
process.env.ANTHROPIC_API_KEY = 'sk-ant-test-key-0000000000';
process.env.ANTHROPIC_BASE_URL = 'http://127.0.0.1:47324/anthropic';

// Phase 8 part B: one fake server stands in for the identity provider, Jira, Cloudflare, Google, Entra and AWS STS.
process.env.SSO_ENDPOINT_BASE = 'http://127.0.0.1:47330/oidc';
process.env.CLOUDFLARE_API_BASE = 'http://127.0.0.1:47330/cf';
process.env.GOOGLE_TOKEN_URL = 'http://127.0.0.1:47330/google/token';
process.env.GOOGLE_ADMIN_API = 'http://127.0.0.1:47330/google';
process.env.ENTRA_LOGIN_BASE = 'http://127.0.0.1:47330/entra';
process.env.GRAPH_API_BASE = 'http://127.0.0.1:47330/graph';
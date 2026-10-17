// Regenerate docs/img/*.png from FalkorDB Browser (http://localhost:3000, graph `iam` loaded).
// npm i playwright-core && node scripts/screenshots.mjs   (CHROME=<path> to override the browser)
import { chromium } from 'playwright-core';
const REL = 'MEMBER_OF|HAS_POLICY|GRANTS|CAN_ASSUME|ASSUMES_AWS|USES|BOUND_TO';
const cases = [
  ['role-chain', 'User', 'dev-intern', 'prod-db-credentials'],
  ['passrole-lambda', 'User', 'data-analyst', 'customer-pii'],
  ['stale-trust', 'User', 'contractor-bob', 'prod-backups'],
  ['wildcard-secrets', 'User', 'support-jane', 'payment-api-key'],
  ['irsa-wildcard', 'Pod', 'web-frontend', 'prod-db-credentials'],
  ['k8s-secrets-cluster', 'Pod', 'ci-runner', 'stripe-webhook-key'],
].map(([f, ...r]) => [`docs/img/${f}.png`, ...r]);
const b = await chromium.launch({ executablePath: process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true });
const p = await b.newPage({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 2 });
await p.goto('http://localhost:3000', { waitUntil: 'networkidle' });
await p.getByRole('button', { name: 'Log in' }).click();
await p.waitForURL('**/graph'); await p.waitForTimeout(2000);
await p.getByRole('button', { name: 'Skip Tutorial' }).click().catch(()=>{});
await p.keyboard.press('Escape');
await p.getByRole('button', { name: 'Close', exact: true }).first().click().catch(()=>{});
await p.waitForTimeout(500);
for (const [file, label, src, dst] of cases) {
  const q = `MATCH (s:${label} {name:'${src}'}), (t:Resource {name:'${dst}'}) WITH shortestPath((s)-[:${REL}*1..12]->(t)) AS p RETURN p`;
  const ed = p.locator('.monaco-editor').first();
  await ed.click();
  await p.keyboard.press('Meta+A'); await p.keyboard.press('Backspace');
  await p.keyboard.insertText(q);
  await p.locator('button', { hasText: 'RUN' }).first().click();
  await p.waitForTimeout(6000);
  await p.getByRole('button', { name: 'Fit graph to screen' }).click();
  await p.waitForTimeout(1500);
  for (let i = 0; i < 2; i++) { await p.getByRole('button', { name: 'Zoom in' }).click(); await p.waitForTimeout(500); }
  await p.waitForTimeout(1000);
  await p.screenshot({ path: file });
  console.log('shot', file);
}
await b.close();

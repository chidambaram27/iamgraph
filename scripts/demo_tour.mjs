// Guided tour of the web UI for recording the demo video (Recordly or any screen recorder).
//   npm i --no-save playwright-core
//   uv run iamgraph web &              # http://localhost:8000
//   node scripts/demo_tour.mjs         # Enter = next shot; narration lines print here, not on screen
//   AUTO=1 node scripts/demo_tour.mjs  # no Enter needed: waits ~reading time per shot
// Env: URL (default http://localhost:8000), CHROME (browser path), W/H (window size, default 1600x1000),
//      SNAP=<dir> saves a screenshot after each shot (dry-run check).
import { chromium } from 'playwright-core';
import readline from 'node:readline/promises';

const URL = process.env.URL || 'http://localhost:8000';
const AUTO = !!process.env.AUTO;
const [W, H] = [+(process.env.W || 1600), +(process.env.H || 1000)];
const wait = ms => new Promise(r => setTimeout(r, ms));
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

const CURSOR = `
  addEventListener('DOMContentLoaded', () => {
    const c = document.createElement('div');
    c.id = '__cur';
    c.style.cssText = 'position:fixed;left:0;top:0;width:22px;height:22px;z-index:99999;pointer-events:none;' +
      'transition:transform .7s cubic-bezier(.4,0,.2,1);transform:translate(800px,500px)';
    c.innerHTML = '<svg width="22" height="22" viewBox="0 0 24 24"><path d="M4 2l16 9-7 2-3 7z" fill="#fff" stroke="#000" stroke-width="1.5"/></svg>';
    document.body.appendChild(c);
    window.__cur = (x, y) => { c.style.transform = 'translate(' + x + 'px,' + y + 'px)'; };
    window.__ripple = (x, y) => {
      const r = document.createElement('div');
      r.style.cssText = 'position:fixed;z-index:99998;pointer-events:none;border:2px solid #4f8cff;border-radius:50%;' +
        'left:' + (x - 6) + 'px;top:' + (y - 6) + 'px;width:12px;height:12px;transition:all .5s ease-out;opacity:1';
      document.body.appendChild(r);
      requestAnimationFrame(() => { r.style.transform = 'scale(4)'; r.style.opacity = '0'; });
      setTimeout(() => r.remove(), 600);
    };
  });`;

const ctx = await chromium.launchPersistentContext('.demo-profile', {
  executablePath: process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  headless: false, viewport: null, ignoreDefaultArgs: ['--enable-automation'],
  args: [`--app=${URL}`, `--window-size=${W},${H}`, '--window-position=40,40'],
});
const p = ctx.pages()[0] || await ctx.newPage();
await p.addInitScript(CURSOR);
await p.goto(URL, { waitUntil: 'networkidle' });
await p.waitForTimeout(2500);

async function point(sel) {
  const el = p.locator(sel).first();
  await el.scrollIntoViewIfNeeded();
  const b = await el.boundingBox();
  const [x, y] = [b.x + Math.min(b.width / 2, 60), b.y + b.height / 2];
  await p.evaluate(([x, y]) => window.__cur(x, y), [x, y]);
  await wait(800);
  return [x, y, el];
}
async function click(sel, pause = 400) {
  const [x, y, el] = await point(sel);
  await p.evaluate(([x, y]) => window.__ripple(x, y), [x, y]);
  await el.click();
  await wait(pause);
}
async function idle() { await p.waitForFunction(() => ![...document.querySelectorAll('.btn')].some(b => b.disabled), null, { timeout: 120000 }); }
async function scrollPanel(sel, to) {
  await p.evaluate(([s, t]) => {
    const sec = document.querySelector('aside section.on');
    const el = t === 'bottom' ? null : document.querySelector(t);
    sec.scrollTo({ top: el ? el.offsetTop - 140 : sec.scrollHeight, behavior: 'smooth' });
  }, [sel, to]);
  await wait(1200);
}

const shots = [
  ['Intro', 'Cloud permissions are a graph problem. This is one FalkorDB graph: an AWS account\'s IAM and an EKS cluster\'s Kubernetes RBAC, joined by IRSA. Every permission is an edge, not a JSON blob.',
    async () => { await point('#legend'); await wait(1500); await point('#net'); }],
  ['Attack path', 'Can the intern reach the production database credentials? One click runs a shortest-path query in FalkorDB: seven hops. Developers group, AssumeRole on ci-star, ci-deploy, prod-admin, AdministratorAccess.',
    async () => { await click('.chip[data-s="dev-intern"]'); await idle(); }],
  ['Verified fix', 'It doesn\'t just answer, it acts. Propose fix tries cutting every edge on the path on a copy of the graph and keeps the cut with the least collateral: remove the DeployToProd statement. Eighteen exposures removed, no legitimate access lost, and the path query re-run on the copy confirms it\'s gone.',
    async () => { await click('#go-fix'); await idle(); await wait(800);
      await scrollPanel('', 'details'); await click('details summary', 1200);
      await scrollPanel('', 'pre'); await wait(1500); await scrollPanel('', 'bottom'); }],
  ['Pod into AWS', 'Now across the boundary. The web-frontend pod runs as its service account, which assumes an AWS role through IRSA, straight to the same secret. Same unchanged path query.',
    async () => { await scrollPanel('', '#src'); await click('.chip[data-s="web-frontend"]'); await idle(); }],
  ['IRSA fix', 'The bug: the role trusts every service account in the shop namespace. The fix narrows the trust to orders-api and removes the annotation, so the legitimate orders-api pod keeps working.',
    async () => { await click('#go-fix'); await idle(); await wait(600); await scrollPanel('', 'pre'); }],
  ['Who can reach', 'Flip the question: who can reach the prod database? Eight actors. The admins and orders-api are expected; five are not.',
    async () => { await click('nav button[data-tab="who"]', 600); await click('#go-who'); await idle(); await point('td.bad'); }],
  ['Scan + chokepoints', 'A full scan finds every exposure across the account and the cluster. Betweenness centrality ranks the chokepoints, the nodes most attack paths flow through, so you know where one fix closes the most doors.',
    async () => { await click('nav button[data-tab="scan"]', 600); await click('#go-scan'); await idle(); await wait(1200);
      await scrollPanel('', 'tr[data-focus]'); await click('tr[data-focus]', 1500); }],
  ['Ask the agent', 'And you can just ask. The agent picks the graph tools itself: find the path, propose the fix, then explain it in plain words, here a Kubernetes-only path through a cluster-wide secret reader role.',
    async () => { await click('nav button[data-tab="ask"]', 600); await click('#golden .chip >> nth=2', 600); await click('#go-ask');
      await p.waitForSelector('.answer, #out-ask .card.bad', { timeout: 120000 }); await wait(1000);
      await scrollPanel('', '.answer'); await wait(2500); await scrollPanel('', 'bottom'); }],
  ['Outro', 'Every tool is a Cypher query on FalkorDB, every fix is checked by simulation, and six planted attack paths are covered by tests. One docker compose command runs it from a clean clone.',
    async () => { await click('#reset', 1500); }],
];

console.log(`\n${shots.length} shots. Start recording the Chrome window now.${AUTO ? '' : ' Press Enter to begin.'}`);
if (!AUTO) await rl.question('');
for (const [i, [title, say, act]] of shots.entries()) {
  console.log(`\n\x1b[1m[${i + 1}/${shots.length}] ${title}\x1b[0m\n\x1b[36m${say}\x1b[0m`);
  await act();
  if (process.env.SNAP) await p.screenshot({ path: `${process.env.SNAP}/${i + 1}.png` });
  if (AUTO) await wait(Math.max(2000, say.split(' ').length * 330));
  else if (i < shots.length - 1) await rl.question('\x1b[2m(Enter for next shot)\x1b[0m');
}
console.log('\nDone. Stop recording, then press Enter to close the browser.');
if (!AUTO) await rl.question(''); else await wait(3000);
rl.close();
await ctx.close();

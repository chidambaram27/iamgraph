// Guided tour of the web UI for recording a silent demo video (Recordly or any screen recorder).
// Subtitles and title cards are drawn inside the page, so they are part of the recording.
//   npm i --no-save playwright-core
//   uv run iamgraph web &              # http://localhost:8000
//   node scripts/demo_tour.mjs         # Enter to start; then runs on its own, pacing each subtitle
//   STEP=1 node scripts/demo_tour.mjs  # also wait for Enter between shots
//   AUTO=1 node scripts/demo_tour.mjs  # no key presses at all (dry runs, with SNAP)
// Env: URL (default http://localhost:8000), CHROME (browser path), W/H (window size, default 1600x1000),
//      PACE (subtitle hold multiplier, default 1; 1.3 = slower), SNAP=<dir> saves a screenshot after each shot.
import { chromium } from 'playwright-core';
import readline from 'node:readline/promises';

const URL = process.env.URL || 'http://localhost:8000';
const AUTO = !!process.env.AUTO, STEP = !!process.env.STEP && !AUTO;
const PACE = +(process.env.PACE || 1);
const [W, H] = [+(process.env.W || 1600), +(process.env.H || 1000)];
const wait = ms => new Promise(r => setTimeout(r, ms));
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

const OVERLAY = `
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

    const s = document.createElement('div');
    s.style.cssText = 'position:fixed;left:440px;right:0;bottom:34px;z-index:99990;pointer-events:none;' +
      'display:flex;justify-content:center;padding:0 40px';
    s.innerHTML = '<div id="__sub" style="max-width:980px;background:rgba(8,10,15,.88);border:1px solid #2a2f3d;' +
      'border-radius:10px;padding:12px 20px;font:500 22px/1.4 system-ui,sans-serif;color:#fff;text-align:center;' +
      'box-shadow:0 8px 30px rgba(0,0,0,.5);opacity:0;transition:opacity .35s"><div id="__chap" style="font-size:12px;' +
      'letter-spacing:.08em;text-transform:uppercase;color:#4f8cff;margin-bottom:3px"></div><div id="__txt"></div></div>';
    document.body.appendChild(s);
    const sub = s.firstChild;
    window.__sub = (chap, html) => {
      if (!html) { sub.style.opacity = 0; return; }
      sub.style.opacity = 0;
      setTimeout(() => { sub.querySelector('#__chap').textContent = chap;
        sub.querySelector('#__txt').innerHTML = html; sub.style.opacity = 1; }, 250);
    };

    const k = document.createElement('div');
    k.style.cssText = 'position:fixed;inset:0;z-index:100000;pointer-events:none;background:rgba(15,17,23,.96);' +
      'display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;opacity:0;' +
      'transition:opacity .6s;font-family:system-ui,sans-serif;color:#fff;text-align:center';
    document.body.appendChild(k);
    window.__card = html => { if (html) k.innerHTML = html; k.style.opacity = html ? 1 : 0; };
  });`;

const ctx = await chromium.launchPersistentContext('.demo-profile', {
  executablePath: process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  headless: false, viewport: null, ignoreDefaultArgs: ['--enable-automation'],
  args: [`--app=${URL}`, `--window-size=${W},${H}`, '--window-position=40,40'],
});
const p = ctx.pages()[0] || await ctx.newPage();
await p.addInitScript(OVERLAY);
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

let chapter = '';
const words = s => s.replace(/<[^>]+>/g, ' ').split(/\s+/).filter(Boolean).length;
const hold = s => Math.max(2400, 900 + words(s) * 340) * PACE;
// Show a subtitle; `wait=false` shows it and returns at once (e.g. while the agent is thinking).
async function sub(html, { wait: w = true } = {}) {
  console.log(`  \x1b[36m${html.replace(/<[^>]+>/g, '')}\x1b[0m`);
  await p.evaluate(([c, h]) => window.__sub(c, h), [chapter, html]);
  if (w) await wait(hold(html) + 250);
}
async function card(html, ms) {
  await p.evaluate(h => window.__card(h), html);
  await wait(ms * PACE);
  await p.evaluate(() => window.__card(null));
  await wait(700);
}
const b = s => `<b style="color:#f5c451">${s}</b>`;
const bad = s => `<b style="color:#ff5c6c">${s}</b>`;
const ok = s => `<b style="color:#3ecf8e">${s}</b>`;

const shots = [
  ['Intro', async () => {
    await card(`<div style="font-size:56px;font-weight:700">iamgraph</div>
      <div style="font-size:24px;color:#d8dbe3">Find and fix cloud attack paths with an agent on FalkorDB</div>
      <div style="font-size:15px;color:#8a90a2">AWS IAM + Kubernetes RBAC · one graph · verified least-privilege fixes</div>`, 4000);
    await point('#legend');
    await sub(`One FalkorDB graph: an AWS account's ${b('IAM')} and an EKS cluster's ${b('Kubernetes RBAC')}, joined by IRSA`);
    await point('#net');
    await sub(`Every permission is an ${b('edge')}, not a JSON blob, so "who can reach what" is a graph query`);
  }],
  ['Attack path', async () => {
    await sub(`Question: can the ${b('intern')} reach the ${b('production database credentials')}?`);
    await click('.chip[data-s="dev-intern"]'); await idle();
    await sub(`${bad('Yes.')} One shortest-path query in FalkorDB finds a ${bad('7-hop')} path`);
    await sub(`Developers group → AssumeRole on ${b('ci-*')} → ci-deploy → ${b('prod-admin')} → AdministratorAccess`);
  }],
  ['Verified fix', async () => {
    await sub(`It doesn't just answer, it ${b('acts')}: Propose fix tries cutting each edge on a copy of the graph`, { wait: false });
    await click('#go-fix'); await idle(); await wait(2400 * PACE);
    await sub(`Least-collateral cut: remove the ${b('DeployToProd')} statement from ci-deploy-policy`);
    await scrollPanel('', 'details'); await click('details summary', 600);
    await sub(`Every alternative is scored: exposures removed vs legitimate access lost`);
    await scrollPanel('', 'pre');
    await sub(`The exact policy diff to apply`);
    await scrollPanel('', 'bottom');
    await sub(`${ok('Verified')}: the path query re-runs on the copy and the path is gone. ${b('18')} exposures closed, ${ok('no')} legit access lost`);
  }],
  ['Pod into AWS', async () => {
    await sub(`Now across the boundary: can the ${b('web-frontend')} Kubernetes pod reach the same secret?`, { wait: false });
    await scrollPanel('', '#src'); await click('.chip[data-s="web-frontend"]'); await idle(); await wait(1800);
    await sub(`Pod → ServiceAccount → ${b('IRSA')} → AWS role → prod-db-credentials. Same, unchanged path query`);
  }],
  ['IRSA fix', async () => {
    await sub(`The bug: the AWS role trusts ${bad('every')} service account in the shop namespace (${b('shop:*')})`, { wait: false });
    await click('#go-fix'); await idle(); await wait(2600);
    await scrollPanel('', 'pre');
    await sub(`Fix: narrow the trust to ${b('orders-api-sa')} and remove the pod's role annotation`);
    await sub(`The legitimate ${ok('orders-api')} pod keeps its access`);
  }],
  ['Who can reach', async () => {
    await sub(`Flip the question: ${b('who')} can reach the prod database?`, { wait: false });
    await click('nav button[data-tab="who"]', 600); await click('#go-who'); await idle(); await wait(1500);
    await point('td.bad');
    await sub(`${b('8')} actors. The admins and orders-api are expected; ${bad('5 are not')}`);
  }],
  ['Scan + chokepoints', async () => {
    await sub(`A full scan of the account ${b('and')} the cluster`, { wait: false });
    await click('nav button[data-tab="scan"]', 600); await click('#go-scan'); await idle(); await wait(1800);
    await sub(`${bad('27')} exposures, from users and pods`);
    await scrollPanel('', 'tr[data-focus]');
    await sub(`${b('Betweenness centrality')} ranks the chokepoints: the nodes most attack paths flow through`);
    await click('tr[data-focus]', 800);
    await sub(`Fix a chokepoint and one change closes the most doors`);
  }],
  ['Ask the agent', async () => {
    await sub(`Or just ${b('ask')} in plain English`, { wait: false });
    await click('nav button[data-tab="ask"]', 600); await click('#golden .chip >> nth=2', 900);
    await click('#go-ask');
    await sub(`The agent (an LLM) picks the graph tools itself: find the path, propose a fix, explain it`, { wait: false });
    await p.waitForSelector('.answer, #out-ask .card.bad', { timeout: 120000 }); await wait(1000);
    await sub(`Tool calls on the left; the path and the ${bad('✂ cut')} edge in the graph`);
    await scrollPanel('', '.answer');
    await sub(`A Kubernetes-only path: a ${b('cluster-wide secret-reader')} role. The answer is in plain words`);
    await scrollPanel('', 'bottom');
    await sub(`…with a verified RBAC fix: restrict the rule with ${b('resourceNames')}`);
  }],
  ['Outro', async () => {
    await p.evaluate(() => window.__sub('', null));
    await click('#reset', 1500);
    await card(`<div style="font-size:30px;font-weight:600">Every tool is a Cypher query on FalkorDB</div>
      <div style="font-size:22px;color:#d8dbe3">Every fix is verified by simulation on a graph copy</div>
      <div style="font-size:22px;color:#d8dbe3">6 planted attack paths, all found and fixed in tests</div>
      <div style="font-size:16px;color:#8a90a2;margin-top:18px">github.com/chidambaram27/iamgraph · <code>docker compose</code> from a clean clone</div>`, 6000);
  }],
];

console.log(`\n${shots.length} shots. Start recording the Chrome window now.${AUTO ? '' : ' Press Enter to begin.'}`);
if (!AUTO) await rl.question('');
for (const [i, [title, act]] of shots.entries()) {
  chapter = `${i + 1}/${shots.length} · ${title}`;
  console.log(`\n\x1b[1m[${chapter}]\x1b[0m`);
  await act();
  if (process.env.SNAP) await p.screenshot({ path: `${process.env.SNAP}/${i + 1}.png` });
  if (STEP && i < shots.length - 1) await rl.question('\x1b[2m(Enter for next shot)\x1b[0m');
}
console.log('\nDone. Stop recording, then press Enter to close the browser.');
if (!AUTO) await rl.question(''); else await wait(3000);
rl.close();
await ctx.close();

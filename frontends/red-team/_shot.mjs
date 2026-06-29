import { chromium } from 'playwright';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const b = await chromium.launch();
const p = await b.newPage({ viewport: { width: 1440, height: 820 } });
const errs = [];
p.on('console', m => { if (m.type()==='error') errs.push('CONSOLE: '+m.text()); });
p.on('pageerror', e => errs.push('PAGEERR: '+e.message));
const D = dirname(fileURLToPath(import.meta.url));
const canvasInfo = () => p.evaluate(() => {
  const c=document.querySelector('#hero-canvas canvas');
  const w=document.querySelector('#hero-canvas')?.parentElement;
  return { canvas: c?`${c.width}x${c.height}`:'NO CANVAS', display: w?getComputedStyle(w).display:'?', top: w?w.getBoundingClientRect().top:'?' };
});

// 1) Home page nav
await p.goto('http://localhost:3000/', { waitUntil: 'load' });
await p.waitForTimeout(2500);
await p.screenshot({ path: join(D, '_home_shot.png') });

// 2) First Gauntlet visit (full load)
await p.goto('http://localhost:3000/gauntlet', { waitUntil: 'load' });
await p.waitForTimeout(4000);
await p.screenshot({ path: join(D, '_g1_shot.png') });
const f1 = await canvasInfo();

// 3) SPA navigate away then back (RangeLayout stays mounted)
await p.locator('a[href="/modules"]').click({ force: true, noWaitAfter: true });
await p.waitForTimeout(1500);
await p.locator('a[href="/gauntlet"]').click({ force: true, noWaitAfter: true });
await p.waitForTimeout(3500);
await p.screenshot({ path: join(D, '_g2_shot.png') });
const f2 = await canvasInfo();

console.log('ERRORS:', errs.length ? errs.join('\n') : 'none');
console.log('visit#1:', JSON.stringify(f1));
console.log('visit#2:', JSON.stringify(f2));
await b.close();

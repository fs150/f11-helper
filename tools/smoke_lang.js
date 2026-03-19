/*
  Smoke test: language switching + upload labels.

  Usage:
    node tools/smoke_lang.js "http://127.0.0.1:3000"
*/

const fs = require('fs/promises');
const path = require('path');
const { chromium } = require('playwright');

function ts() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  const ms = String(d.getMilliseconds()).padStart(3, '0');
  return [
    d.getFullYear(),
    pad(d.getMonth() + 1),
    pad(d.getDate()),
    '-',
    pad(d.getHours()),
    pad(d.getMinutes()),
    pad(d.getSeconds()),
    ms,
    '-',
    process.pid
  ].join('');
}

async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
}

async function main() {
  const baseURL = (process.argv[2] || 'http://127.0.0.1:3000').replace(/\/$/, '') + '/';
  const outDir = path.join(process.cwd(), 'artifacts', `smoke_lang_${ts()}`);
  await ensureDir(outDir);

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 430, height: 820 }, deviceScaleFactor: 2 });
  const page = await context.newPage();

  const consoleLines = [];
  page.on('console', (msg) => consoleLines.push(`[${msg.type()}] ${msg.text()}`));
  page.on('pageerror', (err) => consoleLines.push(`[pageerror] ${String(err && err.message ? err.message : err)}`));

  await page.goto(baseURL, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForFunction(() => !!window.DalyApp, null, { timeout: 30000 });

  const langs = ['ar', 'en', 'pt'];
  const results = [];

  for (const lang of langs) {
    await page.locator(`.lang-btn[data-lang=\"${lang}\"]`).click();
    await page.waitForTimeout(250);

    const snap = await page.evaluate(() => {
      const t = (id) => {
        const el = document.getElementById(id);
        return el ? String(el.textContent || '').trim() : '';
      };
      return {
        dir: document.documentElement.dir,
        uploadLabel: t('uploadLabel'),
        galleryLabel: t('uploadGalleryLabel'),
        gallerySub: t('uploadGallerySub'),
        ctaPill: t('uploadCtaPill'),
        replace: t('uploadReplaceBtn'),
        remove: t('uploadRemoveBtn'),
        ticker: (document.querySelector('.ticker-text')?.textContent || '').trim()
      };
    });

    results.push({ lang, ...snap });
    await page.screenshot({ path: path.join(outDir, `lang_${lang}.png`), fullPage: true });
  }

  const output = { baseURL, outDir, capturedAt: new Date().toISOString(), results, consoleLines };
  await fs.writeFile(path.join(outDir, 'result.json'), JSON.stringify(output, null, 2), 'utf8');
  await fs.writeFile(path.join(outDir, 'console.log'), consoleLines.join('\n') + '\n', 'utf8');

  await context.close();
  await browser.close();

  process.stdout.write(path.join(outDir, 'result.json'));
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});

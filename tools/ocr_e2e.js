/*
  E2E OCR test for Daly Alpha.
  - Launches Chromium
  - Loads the site
  - Uploads a local image
  - Waits for OCR to finish
  - Captures debug info + screenshots

  Usage:
    node tools/ocr_e2e.js "http://127.0.0.1:3000" "C:\\Users\\Admin\\Desktop\\px\\888.png"
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
  const imagePath = process.argv[3] || 'C:\\Users\\Admin\\Desktop\\px\\888.png';

  const outDir = path.join(process.cwd(), 'artifacts', `ocr_e2e_run_${ts()}`);
  await ensureDir(outDir);

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 430, height: 932 },
    deviceScaleFactor: 2,
    locale: 'en-US'
  });
  const page = await context.newPage();

  const consoleLines = [];
  page.on('console', (msg) => consoleLines.push(`[${msg.type()}] ${msg.text()}`));
  page.on('pageerror', (err) => consoleLines.push(`[pageerror] ${String(err && err.message ? err.message : err)}`));

  await page.goto(baseURL, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForFunction(() => !!window.DalyApp, null, { timeout: 30000 });

  // Instrumentation to capture raw OCR text + toast messages (without changing files).
  await page.evaluate(() => {
    window.__ocrDebug = {
      rawText: '',
      toasts: [],
      tesseractLoaded: false,
      patched: false
    };

    const app = window.DalyApp;
    if (app && typeof app.toast === 'function') {
      const origToast = app.toast.bind(app);
      app.toast = (message) => {
        try { window.__ocrDebug.toasts.push(String(message)); } catch (_) {}
        return origToast(message);
      };
    }

    if (app && typeof app.loadTesseract === 'function') {
      const origLoad = app.loadTesseract.bind(app);
      app.loadTesseract = async () => {
        const res = await origLoad();
        window.__ocrDebug.tesseractLoaded = true;

        if (window.Tesseract && !window.__ocrDebug.patched) {
          window.__ocrDebug.patched = true;
          const origCreateWorker = window.Tesseract.createWorker;
          window.Tesseract.createWorker = async (...args) => {
            const worker = await origCreateWorker(...args);
            const origRecognize = worker.recognize.bind(worker);
            worker.recognize = async (...rargs) => {
              const r = await origRecognize(...rargs);
              try { window.__ocrDebug.rawText = (r && r.data && r.data.text) ? r.data.text : ''; } catch (_) {}
              return r;
            };
            return worker;
          };
        }

        return res;
      };
    }
  });

  await page.screenshot({ path: path.join(outDir, '01_home.png'), fullPage: true });

  // Upload file (triggers OCR automatically on change)
  const fileInput = page.locator('#uploadInput');
  await fileInput.setInputFiles(imagePath);

  // Give preview a moment to render.
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(outDir, '02_preview.png'), fullPage: true });

  // Wait for OCR to run (loading overlay toggles .active)
  await page.waitForFunction(() => document.querySelector('#loadingOverlay')?.classList.contains('active') || true, null, { timeout: 5000 }).catch(() => {});
  await page.waitForFunction(() => !document.querySelector('#loadingOverlay')?.classList.contains('active'), null, { timeout: 180000 });

  // Allow any auto-analysis UI updates to settle.
  await page.waitForTimeout(1200);
  await page.screenshot({ path: path.join(outDir, '03_result.png'), fullPage: true });

  const result = await page.evaluate(() => {
    const v = (id) => {
      const el = document.getElementById(id);
      return el && 'value' in el ? String(el.value || '') : '';
    };
    const toast = document.getElementById('toast');
    return {
      inputs: {
        sniper: v('inputSni'),
        fighter: v('inputInf'),
        cavalry: v('inputCav')
      },
      toastText: toast ? String(toast.textContent || '') : '',
      debug: {
        hook: window.__ocrDebug || null,
        app: (window.DalyApp && window.DalyApp._lastOcrDebug) ? window.DalyApp._lastOcrDebug : null
      },
      bodyText: String(document.body.innerText || '').slice(0, 5000)
    };
  });

  const output = {
    baseURL,
    imagePath,
    outDir,
    capturedAt: new Date().toISOString(),
    result,
    consoleLines
  };

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

const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

const SITE_URL = 'http://localhost:3000/';
const IMAGES_FOLDER = 'C:\\Users\\Admin\\Desktop\\px';
const RESULTS_FOLDER = 'C:\\Users\\Admin\\Desktop\\px\\results';

async function testImage(browser, imgPath, retryCount = 0) {
  const fileName = path.basename(imgPath);
  const page = await browser.newPage();

  page.on('console', msg => {
    const t = msg.text();
    if (t.includes('OCR-DEBUG')) console.log('  LOG:', t);
  });

  try {
    const client = await page.target().createCDPSession();
    await client.send('Network.clearBrowserCache');
    await client.send('ServiceWorker.enable');
    await client.send('ServiceWorker.stopAllWorkers');

    await page.goto(SITE_URL, { waitUntil: 'networkidle2', timeout: 30000 });

    await page.evaluate(async () => {
      if ('serviceWorker' in navigator) {
        const regs = await navigator.serviceWorker.getRegistrations();
        for (const reg of regs) await reg.unregister();
      }
      ['onboardingDismiss','tickerDismiss'].forEach(id => document.getElementById(id)?.click());
    });

    await new Promise(r => setTimeout(r, 1000));

    const fileInput = await page.$('#uploadInput');
    await fileInput.uploadFile(imgPath);

    // Poll every 1s up to 50s
    let values = { snipers:'', fighters:'', cavalry:'' };
    let gotError = false;

    page.on('pageerror', () => { gotError = true; });

    for (let i = 1; i <= 50; i++) {
      await new Promise(r => setTimeout(r, 1000));
      values = await page.evaluate(() => ({
        snipers:  document.getElementById('inputSni')?.value || '',
        fighters: document.getElementById('inputInf')?.value || '',
        cavalry:  document.getElementById('inputCav')?.value || ''
      }));
      if (values.snipers || values.fighters || values.cavalry) {
        console.log('  ✅ OCR done (' + i + 's)');
        break;
      }
      if (i % 5 === 0) console.log('  ⏳ ' + i + 's...');
    }

    await page.close();

    // Retry once if empty and haven't retried yet
    if (!values.snipers && !values.fighters && !values.cavalry && retryCount === 0) {
      console.log('  🔄 Retrying...');
      return await testImage(browser, imgPath, 1);
    }

    return values;

  } catch(e) {
    await page.close();
    throw e;
  }
}

async function main() {
  if (!fs.existsSync(RESULTS_FOLDER)) fs.mkdirSync(RESULTS_FOLDER, { recursive: true });

  const images = fs.readdirSync(IMAGES_FOLDER)
    .filter(f => /\.(png|jpg|jpeg)$/i.test(f))
    .map(f => path.join(IMAGES_FOLDER, f));

  console.log('\n🚀 Daly Alpha OCR Tester');
  console.log('🔍 Found ' + images.length + ' images\n');

  const browser = await puppeteer.launch({
    headless: false,
    defaultViewport: { width: 390, height: 844 },
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });

  const results = [];

  for (const imgPath of images) {
    const fileName = path.basename(imgPath);
    console.log('📸 Testing: ' + fileName);
    console.log('  ✅ Page loaded');
    console.log('  ✅ Uploaded');
    console.log('  ⏳ Waiting for OCR...');

    try {
      const values = await testImage(browser, imgPath);

      const issues = [];
      if (!values.fighters && !values.snipers && !values.cavalry) issues.push('All EMPTY');
      ['fighters','snipers','cavalry'].forEach(k => {
        if (values[k]?.toLowerCase().endsWith('m') && parseFloat(values[k]) > 50)
          issues.push(k + ':' + values[k] + '>50m');
      });

      const result = {
        file: fileName,
        fighters: values.fighters || 'EMPTY',
        snipers:  values.snipers  || 'EMPTY',
        cavalry:  values.cavalry  || 'EMPTY',
        status: issues.length === 0 ? 'PASS' : 'FAIL',
        issue: issues.join('; ')
      };
      results.push(result);

      console.log('  Fighters: ' + result.fighters);
      console.log('  Snipers:  ' + result.snipers);
      console.log('  Cavalry:  ' + result.cavalry);
      console.log('  ' + result.status + (result.issue ? ' - ' + result.issue : '') + '\n');

    } catch(e) {
      console.log('  ❌ ' + e.message + '\n');
      results.push({ file:fileName, fighters:'ERROR', snipers:'ERROR', cavalry:'ERROR', status:'ERROR', issue:e.message });
    }
  }

  await browser.close();
  fs.writeFileSync(path.join(RESULTS_FOLDER, 'report.json'), JSON.stringify(results, null, 2));
  const passed = results.filter(r => r.status==='PASS').length;
  console.log('='.repeat(40));
  console.log('✅ PASS: ' + passed + '/' + results.length);
  console.log('❌ FAIL: ' + (results.length-passed) + '/' + results.length + '\n');
}

main().catch(console.error);

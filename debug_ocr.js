const puppeteer = require('puppeteer');
const path = require('path');

const SITE_URL = 'http://localhost:3000/';
const IMG_PATH = 'C:\\Users\\Admin\\Desktop\\px\\999.png';

async function main() {
  const browser = await puppeteer.launch({
    headless: false,
    defaultViewport: { width: 390, height: 844 },
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();

  // Capture ALL console messages and errors
  page.on('pageerror', err => console.log('  ❌ PAGE ERROR:', err.message));
  page.on('console', msg => {
    const text = msg.text();
    // Show everything
    if (msg.type() === 'error') console.log('  🔴 ERROR:', text);
    if (msg.type() === 'warn')  console.log('  🟡 WARN:', text);
    if (text.includes('OCR') || text.includes('Tesseract') || text.includes('ocr') || text.includes('SW')) {
      console.log('  📋 LOG:', text);
    }
  });

  await page.goto(SITE_URL, { waitUntil: 'networkidle2', timeout: 30000 });
  console.log('✅ Page loaded');

  await page.evaluate(async () => {
    if ('serviceWorker' in navigator) {
      const regs = await navigator.serviceWorker.getRegistrations();
      for (const reg of regs) await reg.unregister();
      console.log('[SW] Unregistered ' + regs.length + ' service workers');
    }
    ['onboardingDismiss','tickerDismiss'].forEach(id => document.getElementById(id)?.click());
  });

  await new Promise(r => setTimeout(r, 1000));

  console.log('\n📸 Uploading 999.png...');
  const fileInput = await page.$('#uploadInput');
  if (!fileInput) { console.log('❌ uploadInput not found!'); await browser.close(); return; }
  
  await fileInput.uploadFile(IMG_PATH);
  console.log('✅ File uploaded\n');
  console.log('⏳ Waiting 35s for OCR...\n');

  // Poll every second for first 35s
  for (let i = 1; i <= 35; i++) {
    await new Promise(r => setTimeout(r, 1000));
    const vals = await page.evaluate(() => ({
      sni: document.getElementById('inputSni')?.value || '',
      inf: document.getElementById('inputInf')?.value || '',
      cav: document.getElementById('inputCav')?.value || '',
      loading: document.getElementById('loadingOverlay')?.style?.display !== 'none'
    }));
    
    if (i <= 5 || i % 5 === 0) {
      console.log('  [' + i + 's] sni=' + (vals.sni||'_') + ' inf=' + (vals.inf||'_') + ' cav=' + (vals.cav||'_') + ' loading=' + vals.loading);
    }
    
    if (vals.sni || vals.inf || vals.cav) {
      console.log('\n✅ Got values at ' + i + 's!');
      break;
    }
  }

  const values = await page.evaluate(() => ({
    snipers:  document.getElementById('inputSni')?.value || '',
    fighters: document.getElementById('inputInf')?.value || '',
    cavalry:  document.getElementById('inputCav')?.value || ''
  }));

  console.log('\n📊 Final Results:');
  console.log('  Fighters:', values.fighters || 'EMPTY');
  console.log('  Snipers: ', values.snipers  || 'EMPTY');
  console.log('  Cavalry: ', values.cavalry  || 'EMPTY');

  await page.screenshot({ path: 'C:\\Users\\Admin\\Desktop\\px\\results\\888_debug.png' });
  console.log('\n📷 Screenshot saved');

  await browser.close();
}

main().catch(console.error);

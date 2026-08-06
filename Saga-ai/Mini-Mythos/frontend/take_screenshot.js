import puppeteer from 'puppeteer';

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 800 });

  await page.goto('http://localhost:5173', { waitUntil: 'networkidle0', timeout: 10000 });
  await page.screenshot({ path: 'screenshot.png', fullPage: true });

  await browser.close();
  console.log('Screenshot saved to screenshot.png');
})();

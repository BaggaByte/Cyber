import puppeteer from 'puppeteer';

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();

  await page.goto('http://localhost:5173', { waitUntil: 'networkidle0', timeout: 10000 });

  const rootHtml = await page.evaluate(() => document.getElementById('root').innerHTML);
  console.log('[ROOT HTML]', rootHtml.slice(0, 500));
  
  const hasReactElement = await page.evaluate(() => document.getElementById('root').children.length);
  console.log('[ROOT CHILDREN]', hasReactElement);

  await browser.close();
})();

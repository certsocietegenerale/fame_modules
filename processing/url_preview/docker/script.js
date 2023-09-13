const puppeteer = require('/usr/local/lib/node_modules/puppeteer');
const fse = require('/usr/local/lib/node_modules/fs-extra');
var userurl = process.argv[2];
var userwait = Number(process.argv[3]);

(async () => {
    const browser = await puppeteer.launch({args: ['--no-sandbox', '--disable-setuid-sandbox'], headless: 'new'});
    const page = await browser.newPage();
    await page.setViewport({'width': 1920, 'height': 1080});
    await page.setRequestInterception(true)
    page.on('request', request => {
      // Capture any request that is a navigation requests that attempts to load a new document
      // This will capture HTTP Status 301, 302, 303, 307, 308, HTML, and Javascript redirects
      if (request.isNavigationRequest() && request.resourceType() === 'document') {
        console.log('redirect ' + request.url())
      }
      request.continue()
    });
    try
    {
      await page.goto(userurl, {
        waitUntil: 'networkidle0',
        timeout: userwait
      });
      console.log('target ' + page.url());
      let bodyHTML = await page.evaluate(() => document.body.innerHTML);
      fse.outputFile("./output/output.html", bodyHTML);
      await page.screenshot({path: './output/output.png'});
    }
    catch (error)
    {
      console.log('warning ' + error);
    }
    await browser.close();
})();

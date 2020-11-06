const puppeteer = require('puppeteer');
const fse = require('fs-extra');
var userurl = process.argv[2];
var userwait = Number(process.argv[3]);

(async () => {

  // template comes from https://github.com/GoogleChrome/puppeteer/issues/1353#issuecomment-356561654
  // Page considered as loaded when idle between 2 requests exceed 'user' delay
  function waitForNetworkIdle(page, timeout, maxInflightRequests = 0) {
    // add listeners

    page.on('request', onRequestStarted);
    page.on('requestfinished', onRequestFinished);
    page.on('requestfailed', onRequestFinished);
    page.on('framenavigated', onRedirectFrame);
    page.on('response', onResponse);

    let inflight = 0;
    let fulfill;
    let promise = new Promise(x => fulfill = x);
    let timeoutId = setTimeout(onTimeoutDone, timeout);
    return promise;

    function onTimeoutDone() {
      // remove listeners
      page.removeListener('request', onRequestStarted);
      page.removeListener('requestfinished', onRequestFinished);
      page.removeListener('requestfailed', onRequestFinished);
      page.removeListener('framenavigated', onRedirectFrame);
      page.removeListener('response', onResponse);
      fulfill();
    }

    // get server-side redirections
    function onRedirectFrame(redirect){
      if (redirect.parentFrame() === null)
            console.log('redirect '+redirect.url());
    }

    // get client-side redirections
    function onResponse(response) {
      let code = response.status();
      if (response.request().frame().parentFrame() === null && response.request().isNavigationRequest() && code >= 300 && code <= 399)
            console.log('redirect '+response.url());
    }

    // clear timeout
    function onRequestStarted(request) {
      ++inflight;
      if (inflight > maxInflightRequests)
        clearTimeout(timeoutId);
    }

    // set timeout
    function onRequestFinished() {
      if (inflight === 0)
        return;
      --inflight;
      if (inflight === maxInflightRequests)
        timeoutId = setTimeout(onTimeoutDone, timeout);
    }
  }

  const browser = await puppeteer.launch({args: ['--no-sandbox', '--disable-setuid-sandbox']});
  const page = await browser.newPage();
  await page.setViewport({'width': 1920, 'height': 1080});

  try {
    await Promise.all([
      page.goto(userurl),
      waitForNetworkIdle(page, userwait, 0),
    ]);
  } catch (error) {
    console.log(error)
  }

  let bodyHTML = await page.evaluate(() => document.body.innerHTML);
  fse.outputFile("./output/output.html", bodyHTML);
  await page.screenshot({path: './output/output.png'});

  await browser.close();
})();

/* Real Chromium checks. Run: node tests/report.cjs REPORT.html [CHROMIUM_PATH]. */
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const {pathToFileURL}=require('node:url');
const {chromium}=require('playwright');

(async()=>{
    const source=path.resolve(process.argv[2]);
    const browser=await chromium.launch({headless:true,executablePath:process.argv[3]||undefined,args:['--no-sandbox']});
    const page=await browser.newPage({viewport:{width:1320,height:850}});
    const errors=[];page.on('pageerror',e=>errors.push(String(e)));
    try{
        await page.goto(pathToFileURL(source).href);
        const total=await page.evaluate(()=>data.rows.length);
        assert(total>0);
        assert.equal(await page.locator('.item').count(),Math.min(total,200));
        await page.locator('#search').fill('ImageBase');
        await page.waitForFunction(()=>document.querySelectorAll('.item').length===1);
        await page.locator('.item').click();
        assert.match(await page.locator('#detail').innerText(),/0x/);
        await page.locator('#collapse').click();assert.equal(await page.locator('.item').count(),0);
        await page.locator('#expand').click();assert.equal(await page.locator('.item').count(),1);
        await page.locator('#search').fill('');
        await page.waitForFunction(()=>document.querySelectorAll('.item').length>1);
        await page.locator('#nav button').filter({hasText:'Headers'}).click();
        assert(await page.locator('.item').count()>1);
        await page.locator('[data-sort="address"]').click();
        const addresses=await page.locator('.item .address').allTextContents();
        assert.deepEqual(addresses,addresses.slice().sort((a,b)=>BigInt(a)<BigInt(b)?-1:BigInt(a)>BigInt(b)?1:0));
        await page.locator('#status').selectOption('error');assert.equal(await page.locator('.item').count(),0);
        await page.locator('#status').selectOption('');
        await page.locator('#nav button').first().click();
        const downloadPromise=page.waitForEvent('download');await page.locator('#download').click();
        const download=await downloadPromise;const exported=JSON.parse(await fs.readFile(await download.path(),'utf8'));
        assert.equal(exported.rows.length,total);
        await page.keyboard.press('Control+f');assert.equal(await page.locator('#search').evaluate(e=>e===document.activeElement),true);
        const old=await page.locator('.detail-pane').evaluate(e=>e.clientHeight);
        await page.locator('#splitter').focus();await page.keyboard.press('ArrowUp');
        assert((await page.locator('.detail-pane').evaluate(e=>e.clientHeight))>old);
        await page.setViewportSize({width:950,height:650});
        assert(await page.locator('#download').isVisible());
        // A larger synthetic report checks paging independently of the sample's size.
        const html=await fs.readFile(source,'utf8');
        const payload=await page.evaluate(()=>data);
        payload.rows=Array.from({length:451},(_,i)=>({...payload.rows[0],id:i+1,name:'record-'+i}));
        payload.counts=[451,0,0,0,0];
        const large=await browser.newPage();
        await large.setContent(html.replace(/(<script id="payload" type="application\/json">)[\s\S]*?(<\/script>)/,
            (_,start,end)=>start+JSON.stringify(payload).replace(/</g,'\\u003c')+end));
        assert.equal(await large.locator('.item').count(),200);
        await large.locator('#next').click();assert.equal(await large.locator('.item').count(),200);
        await large.locator('#next').click();assert.equal(await large.locator('.item').count(),51);
        assert(await large.locator('#next').isDisabled());await large.close();
        assert.deepEqual(errors,[]);
        console.log('Report: selection, search, group collapse, category/status filters, numeric sort, export, keyboard, splitter and pagination passed.');
    }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});

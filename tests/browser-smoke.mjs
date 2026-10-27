import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright-core');
const base=process.argv[2];
if(!base)throw new Error('base URL required');
const browser=await chromium.launch({executablePath:process.env.CHROME_PATH||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:390,height:844}});const provider=[],errors=[];page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(/cloudflare\.com/.test(r.url()))provider.push(r.url())});
 await page.goto(base,{waitUntil:'networkidle'});
 await page.locator('.wz-conn .wz-pill.off',{hasText:'Not connected'}).waitFor({state:'visible'});
 if(!(await page.locator('#signin',{hasText:'Connect'}).isVisible()))throw new Error('Connect is the one primary action when signed out');
 if(await page.locator('#accounts-sec').isVisible())throw new Error('accounts section visible with no accounts');
 const text=await page.evaluate(()=>document.body.innerText.trim());
 for(const banned of ['PKCE','grant','Approvals','MCP','token','link','URL','Refresh','Prepare'])if(text.toLowerCase().includes(banned.toLowerCase()))throw new Error('noisy word on screen: '+banned);
 const words=text.split(/\s+/).filter(Boolean).length;if(words>20)throw new Error('too many words: '+words+' '+text);
 if(!(await page.locator('#approvals').isHidden()))throw new Error('approvals visible with nothing waiting');
 if(await page.evaluate(()=>window.__wizardCloseOverlay()))throw new Error('root Back should leave the app');
 if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw new Error('horizontal overflow');
 if(provider.length||errors.length)throw new Error('provider traffic or page errors: '+provider.concat(errors).join(' '));
 console.log('browser smoke ok: '+words+' words: '+text.replace(/\s+/g,' '));
}finally{await browser.close()}

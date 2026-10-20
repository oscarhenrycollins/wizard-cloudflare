import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createRequire} from 'node:module';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const {chromium}=createRequire(import.meta.url)(process.env.PLAYWRIGHT_MODULE||'playwright-core');
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const child=spawn('python3',[resolve(root,'tests/functional_fixture.py')],{env:{...process.env,CF_FIXTURE_OAUTH:'1',PYTHONDONTWRITEBYTECODE:'1'},stdio:['pipe','pipe','pipe']});
let browser,stderr='';child.stderr.on('data',x=>stderr+=x);
try{
 const url=await new Promise((ok,no)=>{let text='';const timer=setTimeout(()=>no(Error('fixture startup timeout')),10000);child.stdout.on('data',x=>{text+=x;if(text.includes('\n')){clearTimeout(timer);ok(JSON.parse(text.split('\n')[0]).url)}});child.once('exit',()=>no(Error('fixture exited')))});
 browser=await chromium.launch({headless:true,executablePath:process.env.CHROME_PATH||'/usr/bin/google-chrome',args:['--no-sandbox','--disable-dev-shm-usage']});
 const context=await browser.newContext(),page=await context.newPage();let blockedProvider=0;await context.route('**/*',route=>{if(route.request().url().startsWith(url))return route.continue();blockedProvider++;return route.abort()});
 await page.goto(url+'qa-host.html');const app=page.frameLocator('#app');
 const popupPromise=page.waitForEvent('popup');await app.getByRole('button',{name:'Sign in with Cloudflare',exact:true}).click();await popupPromise;
 await app.getByText('Waiting for Cloudflare…').waitFor();
 assert.equal(await app.locator('a').count(),0,'no visible link while waiting');
 assert.equal(page.url(),url+'qa-host.html');assert.equal((await context.cookies()).filter(x=>x.name==='cf_session').length,1);const originalCookie=(await context.cookies()).find(x=>x.name==='cf_session').value;
 await page.reload();await app.getByText('Waiting for Cloudflare…').waitFor();assert.equal((await context.cookies()).find(x=>x.name==='cf_session').value,originalCookie);
 let fail=true;await context.route('**/api/oauth/cancel',route=>fail?route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{message:'Synthetic cancellation unavailable'}})}):route.continue());
 await app.getByRole('button',{name:'Cancel',exact:true}).click();await app.locator('#status').filter({hasText:'Synthetic cancellation unavailable'}).waitFor();assert(await app.locator('#waiting').isVisible());
 const frame=page.frames().find(f=>f.url()===url);let status=await frame.evaluate(async()=>await (await fetch('api/oauth/status')).json());assert.equal(status.flows[0].status,'pending');
 fail=false;await app.getByRole('button',{name:'Cancel',exact:true}).click();await app.locator('#signed-out').waitFor();status=await frame.evaluate(async()=>await (await fetch('api/oauth/status')).json());assert.equal(status.flows[0].status,'cancelled');assert(blockedProvider>=1);
 await context.close();console.log(JSON.stringify({passed:true,provider_navigation:'blocked by fixture',hosted_stays_local:true,popup:true,waiting_has_no_link:true,reload_keeps_waiting:true,cancel_failure_keeps_waiting:true,cancel_success_readback:true}));
}finally{if(browser)await browser.close();child.kill('SIGTERM');if(child.exitCode===null)await new Promise(r=>child.once('exit',r));if(stderr)console.error(stderr)}

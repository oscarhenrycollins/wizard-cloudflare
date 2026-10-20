import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright-core');
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const out=process.env.CF_QA_DIR;
assert(out,'Set CF_QA_DIR outside the source for private evidence');
await mkdir(out,{recursive:true,mode:0o700});
const child=spawn('python3',[resolve(root,'tests/functional_fixture.py')],{cwd:root,env:{...process.env,PYTHONDONTWRITEBYTECODE:'1',CF_FIXTURE_CONNECTED:'1',CF_FIXTURE_APPROVAL:'1'},stdio:['pipe','pipe','pipe']});
let browser,stderr='';child.stderr.on('data',x=>{stderr+=String(x)});
const text=page=>page.evaluate(()=>document.body.innerText);
try {
 const url=await new Promise((ok,no)=>{let s='';const timer=setTimeout(()=>no(Error('Fixture startup timeout')),10000);child.stdout.on('data',x=>{s+=x;if(s.includes('\n')){clearTimeout(timer);try{ok(JSON.parse(s.split('\n')[0]).url)}catch(e){no(e)}}});child.once('exit',code=>{clearTimeout(timer);no(Error(`Fixture exited ${code}`))})});
 browser=await chromium.launch({headless:true,executablePath:process.env.CHROME_PATH||'/usr/bin/google-chrome',args:['--no-sandbox','--disable-dev-shm-usage']});
 const results=[];
 for(const width of [390,1280]){
  const context=await browser.newContext({viewport:{width,height:900}}),page=await context.newPage(),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await context.route('**/*',route=>route.request().url().startsWith(url)?route.continue():route.abort());
  await page.goto(url);await page.waitForLoadState('networkidle');
  if(width===390){ // approval card: plain words, details hidden, decline works
   await page.getByText('Oscar wants to create the storage bucket fixture-created-never-submitted').waitFor();
   assert.equal(await page.locator('.ask pre').isVisible(),false,'payload hidden behind Details');
   await page.screenshot({path:resolve(out,'functional-approval-390.png')});
   await page.getByRole('button',{name:'Decline',exact:true}).click();await page.locator('#approvals').waitFor({state:'hidden'});
  }
  await page.getByRole('button',{name:/Synthetic account A/}).click();
  for(const s of ['Storage','Workers','Domains'])await page.getByRole('button',{name:new RegExp('^'+s)}).waitFor();
  assert.match(await text(page),/Billing ↗/);
  await page.getByRole('button',{name:/^Storage/}).click();await page.getByRole('button',{name:/fixture-bucket/}).click();await page.getByText('encrypted-snapshot.bin').waitFor();assert.match(await text(page),/42 B/);
  assert.equal(await page.evaluate(()=>window.__wizardCloseOverlay()),true);await page.getByRole('button',{name:/fixture-bucket/}).waitFor();
  await page.evaluate(()=>window.__wizardCloseOverlay());
  await page.getByRole('button',{name:/^Workers/}).click();await page.getByText('fixture-worker').waitFor();await page.evaluate(()=>window.__wizardCloseOverlay());
  await page.getByRole('button',{name:/^Domains/}).click();await page.getByRole('button',{name:/fixture\.example/}).click();await page.getByText('192.0.2.1').waitFor();await page.evaluate(()=>window.__wizardCloseOverlay());
  await page.getByLabel('Find a domain').fill('fixture-domain.example');await page.keyboard.press('Enter');await page.getByText('Taken').waitFor();
  while(await page.evaluate(()=>window.__wizardCloseOverlay()));
  await page.locator('#signed-in').waitFor();assert.match(await text(page),/Synthetic account B/);
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);assert.equal(overflow,false);
  for(const banned of ['PKCE','grant','MCP','token','Prepare','Refresh'])assert(!(await text(page)).includes(banned),banned);
  await page.screenshot({path:resolve(out,`functional-${width}.png`),fullPage:true});assert.deepEqual(errors,[]);results.push({width,drilldowns:true,approval_decline:width===390,no_horizontal_overflow:true});await context.close();
 }
 const context=await browser.newContext({viewport:{width:1000,height:900}}),page=await context.newPage();await context.route('**/*',route=>route.request().url().startsWith(url)?route.continue():route.abort());await page.goto(url+'qa-host.html');const frame=page.frameLocator('#app');
 await frame.getByRole('button',{name:/Synthetic account A/}).click();await frame.getByRole('button',{name:/^Domains/}).click();await frame.getByLabel('Find a domain').fill('Theme-preserved draft');const history=await page.evaluate(()=>history.length);
 const skins=['nebula','grove','tide','ember','signal'];let revision=1;
 for(const skin of skins)for(const colorScheme of ['light','dark'])for(const presentation of ['window','immersive']){
  const appearance={version:1,revision:revision++,skin,colorScheme,presentation,tokens:{canvas:colorScheme==='dark'?'#111111':'#fafafa',surface:'#666666','surface-raised':'#777777',text:colorScheme==='dark'?'#ffffff':'#111111','text-secondary':'#888888','text-muted':'#999999',border:'#777777',accent:'#aa66dd','accent-soft':'#665588','on-accent':'#ffffff','reader-surface':'#555555'}};
  await page.evaluate(a=>document.querySelector('#app').contentWindow.postMessage({type:'wizard:appearance',appearance:a},location.origin),appearance);
  await frame.locator(`html[data-skin=${skin}][data-color-scheme=${colorScheme}][data-presentation=${presentation}]`).waitFor();assert.equal(await frame.getByLabel('Find a domain').inputValue(),'Theme-preserved draft');
 }
 assert.equal(await page.evaluate(()=>history.length),history);assert.equal(await frame.locator('body').evaluate(x=>getComputedStyle(x).backgroundColor),'rgba(0, 0, 0, 0)');
 assert.equal(await frame.locator('html').evaluate(()=>window.__wizardCloseOverlay()),true);assert.equal(await frame.locator('html').evaluate(()=>window.__wizardCloseOverlay()),true);assert.equal(await frame.locator('html').evaluate(()=>window.__wizardCloseOverlay()),false);
 await page.screenshot({path:resolve(out,'hosted-signal.png'),fullPage:true});await context.close();
 await writeFile(resolve(out,'functional-browser.json'),JSON.stringify({provider:'synthetic fail-closed transport only',results,hosted_appearance_cases:20,skins,draft_survives:true,hosted_transparent:true,history_unchanged:true,root_nested_back:true},null,2));console.log(JSON.stringify({passed:true,functional_viewports:2,hosted_appearance_cases:20}));
}finally{if(browser)await browser.close();child.kill('SIGTERM');await new Promise(r=>child.once('exit',r));if(stderr)await writeFile(resolve(out,'fixture-stderr.log'),stderr)}

import assert from 'node:assert/strict';
import worker,{parseState} from './worker.mjs';
const encode=r=>'wcf1.'+Buffer.from(JSON.stringify({n:'a'.repeat(43),r})).toString('base64url');
const good='https://owner.tailtest.ts.net:8444/wizard-cloudflare/oauth/callback';
assert.equal(parseState(encode(good)).href,good);
for(const r of ['http://owner.tailtest.ts.net/wizard-cloudflare/oauth/callback','https://evil.example/wizard-cloudflare/oauth/callback','https://user@owner.tailtest.ts.net/wizard-cloudflare/oauth/callback','https://owner.tailtest.ts.net/evil','https://owner.tailtest.ts.net/wizard-cloudflare/oauth/callback?evil=1','javascript:alert(1)','https://owner.tailtest.ts.net.evil.example/wizard-cloudflare/oauth/callback','https://owner.tailtest.ts.net/wizard-cloudflare/oauth/callback#x'])assert.throws(()=>parseState(encode(r)));
const call=q=>worker.fetch(new Request('https://www.aiwizards.com/wizard-cloudflare/auth/callback?'+q));
const valid=new URLSearchParams({state:encode(good),code:'fake-code'}); let response=await call(valid); assert.equal(response.status,200);assert.equal(response.headers.get('location'),null);let html=await response.text();assert.match(html,/Continue only if/);assert.match(html,/Return to Wizard/);assert(!html.includes('<script'));assert.equal(response.headers.get('cache-control'),'no-store');assert.equal(response.headers.get('referrer-policy'),'no-referrer');
for(const q of ['state=bad&code=x',valid+'&code=y',valid+'&error=denied',new URLSearchParams({state:encode(good)})])assert.equal((await call(q)).status,400);
// Cloudflare appends scope/iss to the callback: accept them, but never forward them to the box.
response=await call(valid+'&scope=offline_access%20zone.read&iss=https%3A%2F%2Fdash.cloudflare.com');assert.equal(response.status,200);html=await response.text();assert(!html.includes('scope'));assert(!html.includes('iss='));
assert.equal((await call(new URLSearchParams({state:encode(good),error:'access_denied'}))).status,200);
console.log('relay: target restrictions, query validation, explicit click, security headers PASS');

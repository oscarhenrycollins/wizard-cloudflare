// No storage, analytics, outbound fetch, or token handling. Authorization codes pass through this page.
import {logo} from './logo.mjs';
const PREFIX='/wizard-cloudflare/auth/';
const headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action https://*.ts.net; base-uri 'none'; frame-ancestors 'none'"};
const escape=s=>s.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function parseState(state) {
 if(typeof state!=='string'||state.length>512||!/^wcf1\.[A-Za-z0-9_-]+$/.test(state))throw Error('state');
 const encoded=state.slice(5); const raw=atob(encoded.replace(/-/g,'+').replace(/_/g,'/')); const data=JSON.parse(raw);
 if(Object.keys(data).sort().join(',')!=='n,r'||!/^[A-Za-z0-9_-]{43}$/.test(data.n)||typeof data.r!=='string')throw Error('state');
 const target=new URL(data.r);
 // A deliberate user click is mandatory. Never redirect automatically, even to a tailnet host.
 if(target.protocol!=='https:'||target.username||target.password||target.search||target.hash||target.pathname!=='/wizard-cloudflare/oauth/callback'||!/^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.ts\.net$/.test(target.hostname)||target.href!==data.r)throw Error('target');
 return target;
}
function page(status,body){return new Response('<!doctype html><html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Wizard Cloudflare</title><main><h1>Wizard Cloudflare</h1>'+body+'</main></html>',{status,headers:{...headers,'Content-Type':'text/html; charset=utf-8'}})}
export default {async fetch(request){
 const url=new URL(request.url);
 if(request.method!=='GET')return page(405,'<p>Not available.</p>');
 if(url.pathname===PREFIX+'logo.png')return new Response(Uint8Array.from(atob(logo),c=>c.charCodeAt(0)),{headers:{...headers,'Content-Type':'image/png'}});
 if(url.pathname===PREFIX||url.pathname===PREFIX+'privacy')return page(200,'<p>Read-only Cloudflare connection for your private Wizard. Testing release.</p><p>Credentials stay on your box. This stateless sign-in return page sees the authorization code and return address, but cannot exchange it without the private verifier held by your box. No storage, request logging or analytics. Your box contacts Cloudflare directly.</p><p>Cloudflare hosts account signup, consent and billing. Provider changes and purchases are disabled. No backup scheduler is included.</p><p><a href="https://github.com/oscarhenrycollins/wizard-cloudflare">Source and installation</a></p>');
 if(url.pathname!==PREFIX+'callback')return page(404,'<p>Not found.</p>');
 try {
  if([...url.searchParams.keys()].some(k=>!['state','code','error','error_description','error_uri'].includes(k))||['state','code','error'].some(k=>url.searchParams.getAll(k).length>1))throw Error('query');
  const state=url.searchParams.get('state'); const target=parseState(state);
  const code=url.searchParams.get('code'); const error=url.searchParams.get('error');
  if(Boolean(code)===Boolean(error)||code&&(!/^[\x21-\x7e]{1,4096}$/.test(code))||error&&!/^[a-zA-Z0-9_]{1,80}$/.test(error))throw Error('response');
  // No untrusted state is claimed authentic here: the box validates the entire state hash, cookie and one-use flow.
  target.searchParams.set('state',state); target.searchParams.set(code?'code':'error',code||error);
  return page(200,'<p>Return to your Wizard at <strong>'+escape(target.host)+'</strong>.</p><p>Continue only if this is your own Wizard address.</p><p><a rel="noreferrer" href="'+escape(target.href)+'">Return to Wizard</a></p>');
 }catch{return page(400,'<p>Invalid sign-in return. Start again from your Wizard.</p>');}
}};

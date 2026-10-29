import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { Provider, interactionPolicy, type Configuration } from 'oidc-provider';
import type { Storage } from './storage.js';
import type { Config } from './config.js';
import { adapter } from './storage.js';
import { InvalidDcrMetadataError, parseDcrMetadata, REGISTRATION_BODY_LIMIT } from './registration.js';
import { CONFIRMATION_BODY_LIMIT, InvalidConfirmationError, isConfirmationId, parseCancelRequest, parseConfirmationRequest, parseConsumeRequest } from './confirmation.js';
import type { Confirmation } from './storage.js';

const random=()=>randomBytes(32).toString('base64url');
const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
const escape=(s:string)=>s.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const equal=(a:string,b:string)=>{const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y);};
const sessionSecret=(value:string)=>/^[A-Za-z0-9_-]{43}$/u.test(value)&&Buffer.from(value,'base64url').length===32&&Buffer.from(value,'base64url').toString('base64url')===value;
const SESSION_COOKIE='__Secure-gate_session';
const LOGIN_COOKIE='__Host-gate_login';
const IDENTITY_COOKIE='__Host-gate_identity';

class HttpFailure extends Error {
  constructor(readonly status:number) { super('Request failed'); }
}

function oneHeader(req:IncomingMessage,name:string):string|undefined {
  const values:string[]=[];
  for(let index=0;index<req.rawHeaders.length;index+=2) if(req.rawHeaders[index]!.toLowerCase()===name.toLowerCase()) values.push(req.rawHeaders[index+1]!);
  if(values.length>1)throw new HttpFailure(400);
  return values[0];
}

function cookie(req:IncomingMessage,name:string):string|undefined {
  const header=req.headers.cookie;
  if(!header)return undefined;
  const values:string[]=[];
  for(const item of header.split(';')) {
    const entry=item.trim();const equals=entry.indexOf('=');
    if(equals<0)continue;
    if(entry.slice(0,equals).trim()===name)values.push(entry.slice(equals+1));
  }
  if(values.length>1)throw new HttpFailure(400);
  if(values.length===0)return undefined;
  const value=values[0]!;
  if(!value)throw new HttpFailure(401);
  if((name===SESSION_COOKIE||name===LOGIN_COOKIE||name===IDENTITY_COOKIE)&&!sessionSecret(value))throw new HttpFailure(401);
  return value;
}

function authCookies(req:IncomingMessage) {
  return {session:cookie(req,SESSION_COOKIE),binding:cookie(req,LOGIN_COOKIE),identity:cookie(req,IDENTITY_COOKIE)};
}

function encode(value:string) {return encodeURIComponent(value).replace(/[!'()*]/g,char=>`%${char.charCodeAt(0).toString(16).toUpperCase()}`).replace(/%20/g,'+');}

// One stylesheet for every page. The CSP admits it by hash, so pages load nothing else and need no inline style attributes.
const PAGE_STYLE=`*{box-sizing:border-box}body{margin:0;background:#F6F6F3;color:#1C1D1F;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}a{color:#2346B8}a:hover{color:#18307F}.bar{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:16px 20px;background:#FFFFFF;border-bottom:1px solid #DADBD6}.brand{display:flex;align-items:center;gap:8px;font-weight:600}.who{font-size:13px;color:#5B5F66}main{max-width:560px;margin:0 auto;padding:32px 20px;display:flex;flex-direction:column;gap:20px}h1{margin:0;font-size:26px;line-height:1.25;font-weight:600}h2{margin:0;font-size:17px;font-weight:600}p{margin:0}form{margin:0}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;overflow-wrap:anywhere}.lead{color:#3A3D42}.muted{font-size:14px;color:#5B5F66}.facts{margin:0;display:flex;flex-direction:column;gap:10px;font-size:14px}.facts div{display:flex;gap:12px}.facts dt{width:84px;flex-shrink:0;color:#5B5F66}.facts dd{margin:0;min-width:0;display:flex;flex-wrap:wrap;align-items:center;gap:6px;overflow-wrap:anywhere}.tag{font-size:12px;padding:2px 8px;border-radius:999px;background:#FFF1D6;color:#7A4B00}.card{background:#FFFFFF;border:1px solid #DADBD6;border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:10px}.card.row{flex-direction:row;align-items:center;gap:12px}.grow{flex-grow:1;min-width:0;display:flex;flex-direction:column;gap:4px}.name{display:flex;flex-wrap:wrap;align-items:center;gap:6px;font-weight:600;overflow-wrap:anywhere}.label,.eyebrow{margin:0;font-size:12px;letter-spacing:.04em;text-transform:uppercase;color:#5B5F66;font-weight:500}.lines{margin:0;padding-left:18px;display:flex;flex-direction:column;gap:6px;font-size:14px;overflow-wrap:anywhere}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:#5B5F66}section{display:flex;flex-direction:column;gap:10px}.actions{display:flex;flex-direction:column;gap:10px}button,.button{min-height:48px;padding:0 16px;border-radius:10px;font:inherit;font-weight:600;cursor:pointer}.primary{border:0;background:#2346B8;color:#FFFFFF}.secondary{border:1px solid #B9BBB5;background:#FFFFFF;color:#1C1D1F}.danger{min-height:44px;border:1px solid #D9A39C;background:#FFFFFF;color:#A1271B;font-weight:500}.button{display:flex;align-items:center;justify-content:center;text-decoration:none;background:#1C1D1F;color:#FFFFFF}.button:hover{color:#FFFFFF}.icon{width:52px;height:52px;border-radius:26px;display:flex;align-items:center;justify-content:center}.ok{background:#DDEEDF}.no{background:#E7E8E3}.warn{background:#FFF1D6}footer{max-width:560px;margin:0 auto;padding:14px 20px;border-top:1px solid #DADBD6;display:flex;justify-content:space-between;gap:12px;font-size:13px;color:#5B5F66}`;
const PAGE_STYLE_SOURCE=`'sha256-${createHash('sha256').update(PAGE_STYLE).digest('base64')}'`;
const SHIELD='<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#1C1D1F" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3z"/></svg>';
const ICONS={
  ok:'<div class="icon ok"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#1E6B3A" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg></div>',
  no:'<div class="icon no"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#3A3D42" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 7l10 10"/><path d="M17 7L7 17"/></svg></div>',
  warn:'<div class="icon warn"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#7A4B00" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5v5"/><path d="M12 16.2v0.1"/></svg></div>',
};

interface PageOptions { status?: number; account?: string; lead?: string; footer?: string }

function page(res:ServerResponse,title:string,body:string,formActionOrigin?:string,options:PageOptions={}) {
  const formAction=formActionOrigin?`'self' ${formActionOrigin}`:"'self'";
  res.writeHead(options.status??200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store','content-security-policy':`default-src 'none'; style-src ${PAGE_STYLE_SOURCE}; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,'x-content-type-options':'nosniff'});
  const account=options.account?`<span class="who">${escape(options.account)}</span>`:'';
  res.end(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title><style>${PAGE_STYLE}</style><body><header class="bar"><span class="brand">${SHIELD}Gate</span>${account}</header><main>${options.lead??''}<h1>${title}</h1>${body}</main>${options.footer??''}</body></html>`);
}

const utc=(value:{toDate():Date})=>`${value.toDate().toISOString().slice(0,16).replace('T',' ')} UTC`;
const shortId=(value:string)=>value.length>12?`${value.slice(0,4)}…${value.slice(-4)}`:value;

function json(res:ServerResponse,status:number,value:unknown) {
  res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'});
  res.end(JSON.stringify(value));
}

function jsonFailure(res:ServerResponse,status:number) { json(res,status,{error:status===401?'unauthorized':status===403?'forbidden':'request_failed'}); }

function setCookies(res:ServerResponse,cookies:string[]) {res.setHeader('set-cookie',cookies);}
function identityCookie(value:string) {return `${IDENTITY_COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`;}
function loginCookie(value:string) {return `${LOGIN_COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`;}
function clearLoginCookie() {return `${LOGIN_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;}
function clearIdentityCookie() {return `${IDENTITY_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;}
function sessionCookie(value:string,config:Config) {return `${SESSION_COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Domain=${config.sessionCookieDomain}; Max-Age=${config.browserSessionTtlSeconds}`;}
function clearSessionCookie(config:Config) {return `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Domain=${config.sessionCookieDomain}; Max-Age=0`;}

async function body(req:IncomingMessage,limit=8192) {
  const chunks:Buffer[]=[];let size=0;
  for await(const chunk of req) {const bytes=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk);size+=bytes.length;if(size>limit)throw new HttpFailure(413);chunks.push(bytes);}
  return Buffer.concat(chunks).toString('utf8');
}

async function form(req:IncomingMessage) {
  const type=oneHeader(req,'content-type')?.split(';',1)[0]?.trim().toLowerCase();
  if(type!=='application/x-www-form-urlencoded')throw new HttpFailure(400);
  return new URLSearchParams(await body(req));
}

async function jsonBody(req:IncomingMessage,limit=8192) {
  const type=oneHeader(req,'content-type')?.split(';',1)[0]?.trim().toLowerCase();
  if(type!=='application/json')throw new HttpFailure(400);
  const raw=await body(req,limit);
  let value:unknown;
  try {value=JSON.parse(raw);} catch {throw new HttpFailure(400);}
  if(typeof value!=='object'||value===null||Array.isArray(value))throw new HttpFailure(400);
  return value as Record<string,unknown>;
}

function registeredRedirectOrigin(client:{redirectUriAllowed(redirectUri:string):boolean}|undefined,redirectUri:unknown) {
  if(!client||typeof redirectUri!=='string'||redirectUri.includes('*')||!client.redirectUriAllowed(redirectUri))return undefined;
  try {
    const target=new URL(redirectUri);
    const loopback=target.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(target.hostname);
    if(target.href!==redirectUri||target.username||target.password||target.hash||redirectUri.includes('#')||(target.protocol!=='https:'&&!loopback))return undefined;
    return target.origin;
  } catch { return undefined; }
}

function browserApp(config:Config,appId:string|undefined,redirectUri:string|undefined) {
  if(!appId||!redirectUri)return undefined;
  const app=config.browserApps.find(candidate=>candidate.app_id===appId);
  if(!app?.redirect_uris.includes(redirectUri))return undefined;
  return app;
}

function browserOrigin(req:IncomingMessage,res:ServerResponse,config:Config) {
  const origin=oneHeader(req,'origin');
  if(!origin||!config.browserOrigins.includes(origin))throw new HttpFailure(403);
  res.setHeader('access-control-allow-origin',origin);
  res.setHeader('access-control-allow-credentials','true');
  res.setHeader('vary','Origin');
  return origin;
}

function preflight(req:IncomingMessage,res:ServerResponse,config:Config,path:string) {
  browserOrigin(req,res,config);
  const method=oneHeader(req,'access-control-request-method');
  const allowedMethod=path==='/browser/session'?'GET':path==='/browser/logout'?'POST':undefined;
  const headers=(oneHeader(req,'access-control-request-headers')??'').split(',').map(value=>value.trim().toLowerCase()).filter(Boolean);
  const allowedHeaders=new Set(['content-type','x-csrf-token']);
  if(!allowedMethod||method!==allowedMethod||headers.some(header=>!allowedHeaders.has(header)))throw new HttpFailure(403);
  res.setHeader('access-control-allow-methods',allowedMethod);
  if(headers.length)res.setHeader('access-control-allow-headers',[...new Set(headers)].sort().join(', '));
  res.setHeader('access-control-max-age','600');
  res.setHeader('vary','Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
  res.writeHead(204,{'cache-control':'no-store'});res.end();
}

function registeredResource(req:IncomingMessage,config:Config) {
  const header=oneHeader(req,'authorization');
  if(!header)return undefined;
  for(const resource of config.resources) {
    const expected=`Basic ${Buffer.from(`${encode(resource.client_id)}:${encode(resource.client_secret)}`,'utf8').toString('base64')}`;
    if(equal(header,expected))return resource;
  }
  return undefined;
}

function deviceLabel(req:IncomingMessage) {
  const raw=oneHeader(req,'user-agent')??'';
  const clean=raw.replace(/[\u0000-\u001f\u007f]/gu,' ').trim().slice(0,160);
  return clean||'This browser';
}

export interface GitHubIdentity { exchange(code:string):Promise<string>; }
export function githubIdentity(config:Config):GitHubIdentity {
  return {async exchange(code) {
    const response=await fetch('https://github.com/login/oauth/access_token',{method:'POST',redirect:'error',signal:AbortSignal.timeout(10000),headers:{accept:'application/json','content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:config.githubClientId,client_secret:config.githubClientSecret,code,redirect_uri:`${config.issuer}/github/callback`})});
    const token=await response.json() as {access_token?:string};
    if(!response.ok||!token.access_token)throw new Error('GitHub login failed');
    const user=await fetch('https://api.github.com/user',{redirect:'error',signal:AbortSignal.timeout(10000),headers:{authorization:`Bearer ${token.access_token}`,accept:'application/vnd.github+json','x-github-api-version':'2022-11-28'}});
    const data=await user.json() as {id?:number};
    if(!user.ok||!Number.isSafeInteger(data.id))throw new Error('GitHub identity unavailable');
    return String(data.id);
  }};
}

export async function createService(config:Config,storage:Storage,identity:GitHubIdentity=githubIdentity(config)) {
  const accountId=`github:${config.githubUserId}`;
  const policy=interactionPolicy.base();
  policy.get('consent')!.checks.add(new interactionPolicy.Check('connection_approval','Approve a new connection',ctx=>!ctx.oidc.result?.consent?.grantId));
  let provider:Provider;
  const settings:Configuration={
    adapter:adapter(storage), clients:config.resources.map(r=>({client_id:r.client_id,client_secret:r.client_secret,grant_types:[],response_types:[],redirect_uris:[],token_endpoint_auth_method:'client_secret_basic' as const})),
    jwks:config.jwks,cookies:{keys:config.cookieKeys},claims:{openid:['sub']},scopes:['openid'],
    responseTypes:['code'],pkce:{required:()=>true},
    features:{devInteractions:{enabled:false},registration:{enabled:true,initialAccessToken:false,issueRegistrationAccessToken:false},registrationManagement:{enabled:false},clientIdMetadataDocument:{enabled:false},revocation:{enabled:true},introspection:{enabled:true,allowedPolicy:async(_ctx,client,token)=>{
      if(token.kind!=='AccessToken'||typeof token.grantId!=='string'||typeof token.accountId!=='string'||typeof token.clientId!=='string')return false;
      const resource=config.resources.find(r=>r.client_id===client.clientId&&r.audience===token.aud);
      if(!resource)return false;
      const registered=await provider.Client.find(token.clientId);
      if(!registered||registered.tokenEndpointAuthMethod!=='none'||!registered.grantTypeAllowed('authorization_code'))return false;
      return storage.hasActiveOAuthConnection(token.grantId,token.accountId,token.clientId);
    }},resourceIndicators:{enabled:true,defaultResource:()=>config.resources[0]!.audience,useGrantedResource:()=>true,getResourceServerInfo:(_ctx,resource)=>{const r=config.resources.find(r=>r.audience===resource);if(!r)throw new Error('Unknown resource');return {scope:'',audience:r.audience,accessTokenFormat:'opaque'};}}},
    interactions:{policy,url:(_ctx,interaction)=>`/interaction/${interaction.uid}`},
    findAccount:(_ctx,id)=>id===accountId?{accountId:id,claims:async()=>({sub:id})}:undefined,
    loadExistingGrant:async ctx=>{const id=ctx.oidc.result?.consent?.grantId;return id?provider.Grant.find(id):undefined;},
    expiresWithSession:()=>false,
    issueRefreshToken:(_ctx,client)=>client.grantTypeAllowed('refresh_token'),
    // client_name relays the client's own registration name for resource display only; it is unverified and grants nothing.
    extraTokenClaims:async(_ctx,token)=>{const clientName=token.clientId?(await provider.Client.find(token.clientId))?.clientName:undefined;return {connection_id:'grantId' in token?token.grantId:undefined,azp:token.clientId,gate_approved:true,...(typeof clientName==='string'?{client_name:clientName}:{})};},
    ttl:{AccessToken:300,IdToken:300,AuthorizationCode:60,Grant:30*86400,RefreshToken:30*86400,Session:86400,Interaction:600},
  };
  provider=new Provider(config.issuer,settings);
  provider.proxy=config.issuer.startsWith('https:');
  provider.use(async(ctx,next)=>{
    if(ctx.method!=='POST'||ctx.path!=='/reg')return next();
    const contentType=ctx.get('content-type');
    if(!/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(contentType)) {
      ctx.status=400;ctx.set('cache-control','no-store');ctx.body={error:'invalid_client_metadata'};return;
    }
    const declaredLength=ctx.get('content-length');
    if(declaredLength&&(!/^\d+$/u.test(declaredLength)||Number(declaredLength)>REGISTRATION_BODY_LIMIT)) {
      ctx.status=413;ctx.set('cache-control','no-store');ctx.body={error:'invalid_client_metadata'};return;
    }
    const chunks:Buffer[]=[];let size=0;
    try {
      for await(const chunk of ctx.req) {
        const bytes=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk);size+=bytes.length;
        if(size>REGISTRATION_BODY_LIMIT) {ctx.status=413;ctx.set('cache-control','no-store');ctx.body={error:'invalid_client_metadata'};return;}
        chunks.push(bytes);
      }
      const metadata=parseDcrMetadata(Buffer.concat(chunks));
      (ctx.req as IncomingMessage&{body?:unknown}).body=metadata;
      (ctx.request as typeof ctx.request&{body?:unknown}).body=metadata;
      Object.defineProperty(ctx.req,'readable',{configurable:true,value:false});
    } catch(error) {
      if(!(error instanceof InvalidDcrMetadataError))throw error;
      ctx.status=400;ctx.set('cache-control','no-store');ctx.body={error:'invalid_client_metadata'};return;
    }
    await next();
  });

  async function currentIdentity(req:IncomingMessage) {
    const value=cookie(req,IDENTITY_COOKIE);
    return value?storage.identity(value):undefined;
  }
  async function currentBrowser(req:IncomingMessage) {
    const value=cookie(req,SESSION_COOKIE);
    return value?storage.browser(value):undefined;
  }
  async function startIdentityLogin(res:ServerResponse,interaction?:string,confirmation?:string) {
    const state=random(),binding=random();
    setCookies(res,[loginCookie(binding)]);
    await storage.saveLogin(hash(state),{binding:hash(binding),...(interaction?{interaction}:{}),...(confirmation?{confirmation}:{})});
    const target=new URL('https://github.com/login/oauth/authorize');
    target.search=new URLSearchParams({client_id:config.githubClientId,redirect_uri:`${config.issuer}/github/callback`,state}).toString();
    res.writeHead(303,{location:target.href,'cache-control':'no-store'});res.end();
  }
  async function startBrowserLogin(req:IncomingMessage,res:ServerResponse,url:URL) {
    const appIds=url.searchParams.getAll('app_id'),redirects=url.searchParams.getAll('redirect_uri');
    if(appIds.length!==1||redirects.length!==1||url.searchParams.size!==2)throw new HttpFailure(400);
    const app=browserApp(config,appIds[0],redirects[0]);
    if(!app)throw new HttpFailure(400);
    const cookies=authCookies(req);
    if(cookies.session) {
      const active=await storage.browser(cookies.session);
      if(active) {res.writeHead(303,{location:redirects[0],'cache-control':'no-store'});res.end();return;}
    }
    const identitySession=cookies.identity?await storage.identity(cookies.identity):undefined;
    const binding=cookies.binding??random();
    if(identitySession) {
      const transaction=random(),csrf=random();
      await storage.saveBrowserApproval(transaction,{appId:app.app_id,appName:app.app_name,redirectUri:redirects[0]!,bindingHash:hash(binding),userId:identitySession.userId,csrf,deviceLabel:deviceLabel(req)});
      const headers:string[]=[];
      if(!cookies.binding)headers.push(loginCookie(binding));
      if(headers.length)setCookies(res,headers);
      res.writeHead(303,{location:`/browser/approve?transaction=${encodeURIComponent(transaction)}`,'cache-control':'no-store'});res.end();return;
    }
    const state=random();
    await storage.saveBrowserLogin(state,{appId:app.app_id,appName:app.app_name,redirectUri:redirects[0]!,deviceLabel:deviceLabel(req),bindingHash:hash(binding)});
    const target=new URL('https://github.com/login/oauth/authorize');
    target.search=new URLSearchParams({client_id:config.githubClientId,redirect_uri:`${config.issuer}/github/callback`,state}).toString();
    setCookies(res,[loginCookie(binding)]);
    res.writeHead(303,{location:target.href,'cache-control':'no-store'});res.end();
  }
  async function browserApprovalPage(req:IncomingMessage,res:ServerResponse,url:URL) {
    const ids=url.searchParams.getAll('transaction');
    if(ids.length!==1||url.searchParams.size!==1)throw new HttpFailure(400);
    const cookies=authCookies(req);
    const identitySession=cookies.identity?await storage.identity(cookies.identity):undefined;
    if(!identitySession||!cookies.binding)throw new HttpFailure(401);
    const approval=await storage.browserApproval(ids[0]!,cookies.binding,identitySession.userId);
    if(!approval)throw new HttpFailure(403);
    const body=`<p>${escape(approval.appName)} requested a shared browser session.</p><p>Approving creates a device connection with full access to registered suite resources. Device: ${escape(approval.deviceLabel)}.</p><form method="post" class="actions"><input type="hidden" name="transaction" value="${escape(ids[0]!)}"><input type="hidden" name="csrf" value="${escape(approval.csrf)}"><button class="primary" name="decision" value="approve">Approve this device</button><button class="secondary" name="decision" value="deny">Deny</button></form>`;
    const redirectOrigin=new URL(approval.redirectUri).origin;
    page(res,'Approve device',body,redirectOrigin);
  }
  async function submitBrowserApproval(req:IncomingMessage,res:ServerResponse) {
    const origin=oneHeader(req,'origin');
    if(origin!==config.issuer)throw new HttpFailure(403);
    const values=await form(req);
    if(values.getAll('transaction').length!==1||values.getAll('csrf').length!==1||values.getAll('decision').length!==1||[...values.keys()].some(key=>!['transaction','csrf','decision'].includes(key)))throw new HttpFailure(400);
    const transaction=values.get('transaction')!,csrf=values.get('csrf')!,decision=values.get('decision');
    if(decision!=='approve'&&decision!=='deny')throw new HttpFailure(400);
    const cookies=authCookies(req);
    const identitySession=cookies.identity?await storage.identity(cookies.identity):undefined;
    if(!identitySession||!cookies.binding)throw new HttpFailure(401);
    const approval=await storage.browserApproval(transaction,cookies.binding,identitySession.userId);
    if(!approval||!equal(approval.csrf,csrf))throw new HttpFailure(403);
    if(decision==='deny') {
      const redirect=await storage.denyBrowserApproval(transaction,cookies.binding,identitySession.userId);
      if(!redirect)throw new HttpFailure(403);
      setCookies(res,[clearLoginCookie()]);
      res.writeHead(303,{location:redirect,'cache-control':'no-store'});res.end();return;
    }
    const secret=random(),connectionId=random(),csrfToken=random();
    const result=await storage.completeBrowserApproval(transaction,cookies.binding,identitySession.userId,secret,{userId:identitySession.userId,connectionId,csrf:csrfToken},config.browserSessionTtlSeconds);
    if(!result)throw new HttpFailure(403);
    setCookies(res,[sessionCookie(secret,config),clearLoginCookie()]);
    res.writeHead(303,{location:result.redirectUri,'cache-control':'no-store'});res.end();
  }
  async function browserIntrospection(req:IncomingMessage,res:ServerResponse) {
    const resource=registeredResource(req,config);
    if(!resource) {jsonFailure(res,401);return;}
    const request=await jsonBody(req);
    if(Object.keys(request).length!==2||typeof request.session!=='string'||typeof request.resource!=='string')throw new HttpFailure(400);
    if(request.resource!==resource.audience) {jsonFailure(res,403);return;}
    if(!sessionSecret(request.session)) {json(res,200,{active:false});return;}
    const session=await storage.browser(request.session);
    if(!session) {json(res,200,{active:false});return;}
    const exp=Math.floor(session.expiresAt.toMillis()/1000);
    if(exp<=Date.now()/1000||!sessionSecret(session.csrf)) {json(res,200,{active:false});return;}
    json(res,200,{active:true,iss:config.issuer,sub:session.userId,connection_id:session.connectionId,client_id:resource.browser_client_id,aud:resource.audience,exp,gate_approved:true,session_type:'browser',csrf_token:session.csrf});
  }
  async function browserSession(req:IncomingMessage,res:ServerResponse) {
    browserOrigin(req,res,config);
    authCookies(req);
    if(oneHeader(req,'authorization')!==undefined)throw new HttpFailure(401);
    const session=await currentBrowser(req);
    if(!session) {jsonFailure(res,401);return;}
    json(res,200,{csrf_token:session.csrf});
  }
  async function browserLogout(req:IncomingMessage,res:ServerResponse) {
    browserOrigin(req,res,config);
    authCookies(req);
    if(oneHeader(req,'authorization')!==undefined)throw new HttpFailure(401);
    const request=await jsonBody(req);
    if(Object.keys(request).length!==0)throw new HttpFailure(400);
    const csrf=oneHeader(req,'x-csrf-token');
    if(!csrf)throw new HttpFailure(403);
    const secret=cookie(req,SESSION_COOKIE);
    const session=secret?await storage.browser(secret):undefined;
    if(!secret||!session||!equal(session.csrf,csrf)) {jsonFailure(res,403);return;}
    if(!await storage.logoutBrowser(secret,session.connectionId)) {jsonFailure(res,401);return;}
    // Signing out a device also ends Gate sign-in on this browser, so a shared browser cannot approve it again without GitHub.
    const identity=cookie(req,IDENTITY_COOKIE);
    if(identity)await storage.deleteIdentity(identity);
    res.writeHead(204,{'cache-control':'no-store','set-cookie':[clearSessionCookie(config),clearIdentityCookie()]});res.end();
  }
  /** Ends Gate sign-in and this browser's device session; other devices and AI connections stay active. */
  async function signOut(req:IncomingMessage,res:ServerResponse) {
    if(oneHeader(req,'origin')!==config.issuer)throw new HttpFailure(403);
    const cookies=authCookies(req),values=await form(req);
    if(values.getAll('csrf').length!==1||[...values.keys()].some(key=>key!=='csrf'))throw new HttpFailure(400);
    const identitySession=cookies.identity?await storage.identity(cookies.identity):undefined;
    if(identitySession&&!equal(identitySession.csrf,values.get('csrf')!))throw new HttpFailure(403);
    if(cookies.identity)await storage.deleteIdentity(cookies.identity);
    const browser=cookies.session?await storage.browser(cookies.session):undefined;
    if(cookies.session&&browser)await storage.logoutBrowser(cookies.session,browser.connectionId);
    setCookies(res,[clearIdentityCookie(),clearLoginCookie(),...(browser?[clearSessionCookie(config)]:[])]);
    res.writeHead(303,{location:'/signed-out','cache-control':'no-store'});res.end();
  }

  const account=`GitHub user ${config.githubUserId}`;
  const signedInFooter='<footer><span>Signed in</span><a href="/connections">Connections</a></footer>';
  function resourceLabel(confirmation:Confirmation) {
    const audience=new URL(confirmation.audience);
    return {host:audience.host,target:`${audience.host}${audience.pathname==='/'?'':audience.pathname}`};
  }
  const requester=(confirmation:Confirmation)=>escape(confirmation.clientName??'No name supplied');
  function invalidConfirmationPage(res:ServerResponse,status:number) {
    page(res,'This request is no longer valid','<p class="lead">It was already used or cancelled, or the AI\'s connection to Gate ended. Nothing was changed.</p><p class="lead">If you still want this change, ask your AI to request it again.</p>',undefined,{status,lead:ICONS.warn});
  }
  function confirmationPage(res:ServerResponse,id:string,confirmation:Confirmation,csrf:string) {
    const resource=resourceLabel(confirmation);
    const summary=confirmation.summary!;
    const body=`<dl class="facts"><div><dt>From</dt><dd><strong>${requester(confirmation)}</strong><span class="tag">Unverified name</span></dd></div><div><dt>To</dt><dd>${escape(resource.target)}</dd></div><div><dt>Requested</dt><dd>${utc(confirmation.createdAt)}</dd></div></dl>`+
      `<section class="card" aria-labelledby="change-title"><p class="eyebrow">Change described by ${escape(resource.host)}</p><h2 id="change-title">${escape(summary.title)}</h2><ul class="lines">${summary.lines.map(line=>`<li>${escape(line)}</li>`).join('')}</ul></section>`+
      '<p class="lead">Approving lets this service apply exactly this change as you. Approve only if you asked for it.</p>'+
      `<form method="post" action="/confirm" class="actions"><input type="hidden" name="id" value="${escape(id)}"><input type="hidden" name="csrf" value="${escape(csrf)}"><button class="primary" name="decision" value="approve">Approve</button><button class="secondary" name="decision" value="deny">Deny</button></form>`;
    page(res,'Approve a change',body,undefined,{account,footer:signedInFooter});
  }
  function approvedPage(res:ServerResponse,confirmation:Confirmation) {
    const body='<p class="lead">Nothing has changed yet. Return to your AI and tell it you approved. It will then apply exactly this change.</p>'+
      `<div class="card"><p class="eyebrow">Approved change</p><h2>${escape(confirmation.summary?.title??'Change')}</h2><p class="muted">From ${requester(confirmation)} · ${utc(confirmation.decidedAt??confirmation.createdAt)}</p></div>`+
      '<p class="muted">You can close this page. To withdraw access from this AI, revoke it in <a href="/connections">Connections</a>.</p>';
    page(res,'Approved',body,undefined,{account,lead:ICONS.ok});
  }
  function deniedPage(res:ServerResponse,confirmation:Confirmation) {
    const body='<p class="lead">Nothing was changed. Your AI will see that you denied this request when it checks.</p>'+
      `<div class="card"><p class="eyebrow">Denied request</p><p class="muted">From ${requester(confirmation)} · ${utc(confirmation.decidedAt??confirmation.createdAt)}</p></div>`+
      '<p class="muted">If you did not expect this request, review the AI in <a href="/connections">Connections</a> and revoke it.</p>';
    page(res,'Denied',body,undefined,{account,lead:ICONS.no});
  }
  async function showConfirmation(req:IncomingMessage,res:ServerResponse,url:URL) {
    const ids=url.searchParams.getAll('id'),id=ids[0];
    if(ids.length!==1||url.searchParams.size!==1||!isConfirmationId(id)) {invalidConfirmationPage(res,404);return;}
    authCookies(req);
    const identitySession=await currentIdentity(req);
    if(!identitySession) {
      // The same page is shown for any well-formed ID, so it reveals nothing before sign-in.
      page(res,'Sign in to continue',`<p class="lead">A change is waiting for your approval. Only the account that owns this Gate can approve it.</p><a class="button" href="/confirm/sign-in?id=${id}">Continue with GitHub</a><p class="muted">You stay signed in on this browser for 24 hours.</p>`);
      return;
    }
    const view=await storage.confirmationFor(id,identitySession.userId);
    if(!view) {invalidConfirmationPage(res,404);return;}
    if(view.state==='pending')confirmationPage(res,id,view.confirmation,identitySession.csrf);
    else if(view.state==='approved')approvedPage(res,view.confirmation);
    else if(view.state==='denied')deniedPage(res,view.confirmation);
    else invalidConfirmationPage(res,200);
  }
  async function confirmationSignIn(req:IncomingMessage,res:ServerResponse,url:URL) {
    const ids=url.searchParams.getAll('id'),id=ids[0];
    if(ids.length!==1||url.searchParams.size!==1||!isConfirmationId(id))throw new HttpFailure(400);
    authCookies(req);
    if(await currentIdentity(req)) {res.writeHead(303,{location:`/confirm?id=${id}`,'cache-control':'no-store'});res.end();return;}
    await startIdentityLogin(res,undefined,id);
  }
  async function decideConfirmation(req:IncomingMessage,res:ServerResponse) {
    const origin=oneHeader(req,'origin'),cookies=authCookies(req);
    const identitySession=cookies.identity?await storage.identity(cookies.identity):undefined;
    const values=await form(req);
    if(values.getAll('id').length!==1||values.getAll('csrf').length!==1||values.getAll('decision').length!==1||[...values.keys()].some(key=>!['id','csrf','decision'].includes(key)))throw new HttpFailure(400);
    const id=values.get('id')!,decision=values.get('decision');
    if(!isConfirmationId(id)||(decision!=='approve'&&decision!=='deny'))throw new HttpFailure(400);
    if(!identitySession||origin!==config.issuer||!equal(identitySession.csrf,values.get('csrf')!))throw new HttpFailure(403);
    if(await storage.decideConfirmation(id,identitySession.userId,decision)==='invalid') {invalidConfirmationPage(res,409);return;}
    res.writeHead(303,{location:`/confirm?id=${id}`,'cache-control':'no-store'});res.end();
  }
  async function confirmationApi(req:IncomingMessage,res:ServerResponse,path:string) {
    const resource=registeredResource(req,config);
    if(!resource) {jsonFailure(res,401);return;}
    const request=await jsonBody(req,CONFIRMATION_BODY_LIMIT);
    try {
      if(path==='/confirmations') {
        const input=parseConfirmationRequest(request);
        if(input.subject!==accountId) {jsonFailure(res,403);return;}
        const id=random();
        const result=await storage.createConfirmation(id,{resourceClientId:resource.client_id,audience:resource.audience,subject:input.subject,connectionId:input.connection_id,reference:input.reference,changeHash:input.change_hash,summary:input.summary});
        if(result==='inactive') {jsonFailure(res,403);return;}
        if(result==='duplicate') {json(res,409,{error:'duplicate_reference'});return;}
        json(res,201,{id,url:`${config.issuer}/confirm?id=${id}`});return;
      }
      if(path==='/confirmations/consume') {
        const input=parseConsumeRequest(request);
        const result=await storage.consumeConfirmation(input.id,resource.client_id,input.reference,input.change_hash);
        if(result.status!=='consumed') {json(res,200,{status:result.status});return;}
        json(res,200,{status:'consumed',subject:result.subject,connection_id:result.connectionId,decided_at:Math.floor(result.decidedAt.toMillis()/1000)});return;
      }
      const input=parseCancelRequest(request);
      await storage.cancelConfirmation(input.id,resource.client_id,input.reference);
      res.writeHead(204,{'cache-control':'no-store'});res.end();
    } catch(error) {
      if(error instanceof InvalidConfirmationError) {jsonFailure(res,400);return;}
      throw error;
    }
  }

  async function handler(req:IncomingMessage,res:ServerResponse) {
    let path='';
    try {
      res.setHeader('strict-transport-security','max-age=31536000');
      const url=new URL(req.url!,config.issuer);path=url.pathname;
      if(path==='/healthz'){res.writeHead(200);res.end('ok');return;}
      if(path==='/readyz'){
        try { await storage.ready(); res.writeHead(200,{'cache-control':'no-store'}); res.end('ok'); }
        catch { res.writeHead(503,{'cache-control':'no-store'}); res.end('unavailable'); }
        return;
      }
      if(req.method==='OPTIONS'&&(path==='/browser/session'||path==='/browser/logout')){preflight(req,res,config,path);return;}
      if(path==='/browser/login'&&req.method==='GET'){await startBrowserLogin(req,res,url);return;}
      if(path==='/browser/approve'&&req.method==='GET'){await browserApprovalPage(req,res,url);return;}
      if(path==='/browser/approve'&&req.method==='POST'){await submitBrowserApproval(req,res);return;}
      if(path==='/browser/session/introspect'&&req.method==='POST'){
        let authorization:string|undefined;
        try {authorization=oneHeader(req,'authorization');} catch {jsonFailure(res,401);return;}
        if(authorization===undefined) {jsonFailure(res,401);return;}
        await browserIntrospection(req,res);return;
      }
      if(path==='/browser/session'&&req.method==='GET'){await browserSession(req,res);return;}
      if(path==='/browser/logout'&&req.method==='POST'){await browserLogout(req,res);return;}
      if(path.startsWith('/browser/')){res.writeHead(404,{'cache-control':'no-store'});res.end('Not found');return;}
      if(req.method==='POST'&&(path==='/confirmations'||path==='/confirmations/consume'||path==='/confirmations/cancel')){await confirmationApi(req,res,path);return;}
      if(path==='/confirm'&&req.method==='GET'){await showConfirmation(req,res,url);return;}
      if(path==='/confirm'&&req.method==='POST'){await decideConfirmation(req,res);return;}
      if(path==='/confirm/sign-in'&&req.method==='GET'){await confirmationSignIn(req,res,url);return;}
      if(path==='/github/callback'&&req.method==='GET') {
        const states=url.searchParams.getAll('state'),codes=url.searchParams.getAll('code');
        if(states.length!==1||codes.length!==1)throw new HttpFailure(400);
        const cookies=authCookies(req),binding=cookies.binding;
        if(!binding)throw new HttpFailure(400);
        const state=states[0]!,code=codes[0]!;
        const browserAttempt=await storage.takeBrowserLogin(state,binding);
        let interaction:string|undefined,confirmation:string|undefined;
        if(!browserAttempt) {
          const saved=await storage.takeLogin(hash(state),hash(binding));
          if(!saved)throw new HttpFailure(400);
          interaction=saved.interaction;confirmation=saved.confirmation;
        }
        const user=await identity.exchange(code);
        if(user!==config.githubUserId){res.writeHead(403,{'cache-control':'no-store'});res.end('Account not allowed');return;}
        const identitySecret=random(),identityCsrf=random();
        await storage.saveIdentity(identitySecret,{userId:accountId,csrf:identityCsrf});
        if(browserAttempt) {
          const transaction=random(),approvalCsrf=random();
          await storage.saveBrowserApproval(transaction,{appId:browserAttempt.appId,appName:browserAttempt.appName,redirectUri:browserAttempt.redirectUri,bindingHash:hash(binding),userId:accountId,csrf:approvalCsrf,deviceLabel:browserAttempt.deviceLabel});
          setCookies(res,[identityCookie(identitySecret)]);
          res.writeHead(303,{location:`/browser/approve?transaction=${encodeURIComponent(transaction)}`,'cache-control':'no-store'});res.end();return;
        }
        setCookies(res,[identityCookie(identitySecret),clearLoginCookie()]);
        const destination=interaction?`/interaction/${encodeURIComponent(interaction)}`:confirmation&&isConfirmationId(confirmation)?`/confirm?id=${confirmation}`:'/connections';
        res.writeHead(303,{location:destination,'cache-control':'no-store'});res.end();return;
      }
      if(path==='/logout'&&req.method==='POST'){await signOut(req,res);return;}
      if(path==='/signed-out'&&req.method==='GET'){page(res,'Signed out','<p class="lead">You are signed out of Gate on this browser, and this browser\'s device session has ended.</p><p class="muted">Your other devices and AI connections stay active. Revoke them in Connections after signing in again.</p><a class="button" href="/login">Sign in again</a>',undefined,{lead:ICONS.ok});return;}
      if(path==='/login'&&req.method==='GET'){
        authCookies(req);
        if(await currentIdentity(req)){res.writeHead(303,{location:'/connections','cache-control':'no-store'});res.end();return;}
        await startIdentityLogin(res);return;
      }
      if(path==='/connections'&&req.method==='GET') {
        authCookies(req);
        const s=await currentIdentity(req);if(!s){res.writeHead(303,{location:'/login','cache-control':'no-store'});res.end();return;}
        const rows=await storage.listConnections(accountId);
        const current=await currentBrowser(req);
        const revoke=(id:string)=>`<form method="post" action="/connections/revoke"><input type="hidden" name="csrf" value="${escape(s.csrf)}"><input type="hidden" name="id" value="${escape(id)}"><button class="danger">Revoke</button></form>`;
        const approved=(createdAt:string)=>`Approved ${escape(createdAt.slice(0,10))}`;
        const clients=rows.filter(r=>r.kind!=='browser').map(r=>`<div class="card row"><div class="grow"><span class="name">${escape(r.clientName??'No name supplied')}<span class="tag">Unverified name</span></span><span class="mono">client ${escape(shortId(r.clientId))}</span><span class="muted">${approved(r.createdAt)}</span></div>${revoke(r.id)}</div>`);
        const browsers=rows.filter(r=>r.kind==='browser').map(r=>`<div class="card row"><div class="grow"><span class="name">${escape(r.deviceLabel??'This browser')}</span><span class="muted">${current?.connectionId===r.id?'This browser · ':''}${approved(r.createdAt)}</span></div>${revoke(r.id)}</div>`);
        const section=(id:string,label:string,cards:string[])=>cards.length?`<section aria-labelledby="${id}"><h2 id="${id}" class="label">${label}</h2>${cards.join('')}</section>`:'';
        const signOutForm=`<form method="post" action="/logout" class="actions"><input type="hidden" name="csrf" value="${escape(s.csrf)}"><button class="secondary">Sign out of Gate on this browser</button></form>`;
        const body='<p class="lead">AIs and browsers that can use your services. Revoking stops access at their next request.</p>'+(rows.length?section('ai-clients','AI clients',clients)+section('browsers','Browsers',browsers):'<p class="muted">No connections.</p>')+signOutForm;
        page(res,'Connections',body,undefined,{account});return;
      }
      if(path==='/connections/revoke'&&req.method==='POST') {
        const origin=oneHeader(req,'origin'),cookies=authCookies(req),s=cookies.identity?await storage.identity(cookies.identity):undefined,bodyValues=await form(req);
        if(bodyValues.getAll('id').length!==1||bodyValues.getAll('csrf').length!==1||[...bodyValues.keys()].some(key=>!['id','csrf'].includes(key)))throw new HttpFailure(400);
        if(!s||!equal(s.csrf,bodyValues.get('csrf')??'')||origin!==config.issuer){res.writeHead(403);res.end();return;}
        const id=bodyValues.get('id')!,browser=cookies.session?await storage.browser(cookies.session):undefined;
        await storage.revoke(id,accountId);
        const headers:string[]=[];
        if(browser?.connectionId===id)headers.push(clearSessionCookie(config));
        if(headers.length)setCookies(res,headers);
        res.writeHead(303,{location:'/connections','cache-control':'no-store'});res.end();return;
      }
      if(/^\/interaction\/[^/]+$/u.test(path)) {
        const details=await provider.interactionDetails(req,res);
        if(details.prompt.name==='login'){
          authCookies(req);
          const loggedIn=await currentIdentity(req);
          if(loggedIn?.userId===accountId){await provider.interactionFinished(req,res,{login:{accountId}},{mergeWithLastSubmission:false});return;}
          await startIdentityLogin(res,details.uid);return;
        }
        authCookies(req);
        const s=await currentIdentity(req);if(!s||s.userId!==details.session?.accountId){res.writeHead(403);res.end('Sign in again');return;}
        if(req.method==='GET') {
          const clientId=details.params.client_id;
          if(typeof clientId!=='string')throw new HttpFailure(403);
          const client=await provider.Client.find(clientId);
          const redirectUri=details.params.redirect_uri;
          const redirectOrigin=registeredRedirectOrigin(client,redirectUri);
          if(!client||client.tokenEndpointAuthMethod!=='none'||!client.grantTypeAllowed('authorization_code')||!redirectOrigin||typeof redirectUri!=='string')throw new HttpFailure(403);
          const name=client.clientName??'No name supplied';
          page(res,'Approve connection',`<p>Unverified client name: ${escape(name)}</p><p>Redirect URI: <code>${escape(redirectUri)}</code></p><p>Approving gives this client access to the registered Gate resources.</p><form method="post" class="actions"><input type="hidden" name="csrf" value="${escape(s.csrf)}"><button class="primary" name="decision" value="approve">Approve</button><button class="secondary" name="decision" value="deny">Deny</button></form>`,redirectOrigin,{account});return;
        }
        if(req.method==='POST') {
          const values=await form(req);
          if(values.getAll('decision').length!==1||values.getAll('csrf').length!==1||[...values.keys()].some(key=>!['decision','csrf'].includes(key))||oneHeader(req,'origin')!==config.issuer||!equal(s.csrf,values.get('csrf')??'')){res.writeHead(403);res.end();return;}
          if(values.get('decision')!=='approve'&&values.get('decision')!=='deny')throw new HttpFailure(400);
          if(values.get('decision')==='deny'){await provider.interactionFinished(req,res,{error:'access_denied'},{mergeWithLastSubmission:false});return;}
          const clientId=details.params.client_id;
          if(typeof clientId!=='string')throw new HttpFailure(403);
          const client=await provider.Client.find(clientId);
          if(!client||client.tokenEndpointAuthMethod!=='none'||!client.grantTypeAllowed('authorization_code')||!registeredRedirectOrigin(client,details.params.redirect_uri))throw new HttpFailure(403);
          const grant=new provider.Grant({accountId,clientId});grant.addOIDCScope('openid');
          for(const r of config.resources)grant.addResourceScope(r.audience,'');
          const grantId=await grant.save();
          await storage.addConnection(grantId,accountId,clientId,client.clientName);
          await provider.interactionFinished(req,res,{consent:{grantId}},{mergeWithLastSubmission:true});return;
        }
      }
      if(path==='/'){res.writeHead(303,{location:'/connections'});res.end();return;}
      await provider.callback()(req,res);
    } catch(error) {
      if(res.headersSent){res.end();return;}
      if(error instanceof HttpFailure) {
        if(path==='/browser/session'||path==='/browser/logout'||path.startsWith('/confirmations'))jsonFailure(res,error.status);
        else {res.writeHead(error.status,{'cache-control':'no-store'});res.end(error.status===401?'Unauthorized':error.status===403?'Forbidden':'Request failed');}
        return;
      }
      if(path.startsWith('/browser/')||path.startsWith('/confirmations')) {jsonFailure(res,503);return;}
      res.writeHead(400,{'cache-control':'no-store'});res.end('Request failed');
    }
  }
  return {provider,server:createServer((req,res)=>{void handler(req,res);})};
}

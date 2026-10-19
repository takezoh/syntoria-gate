import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { Provider, interactionPolicy, type Configuration } from 'oidc-provider';
import type { Storage } from './storage.js';
import type { Config } from './config.js';
import { adapter } from './storage.js';
import { InvalidDcrMetadataError, parseDcrMetadata, REGISTRATION_BODY_LIMIT } from './registration.js';

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

function page(res:ServerResponse,title:string,body:string,formActionOrigin?:string) {
  const formAction=formActionOrigin?`'self' ${formActionOrigin}`:"'self'";
  res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store','content-security-policy':`default-src 'none'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,'x-content-type-options':'nosniff'});
  res.end(`<!doctype html><html lang="en"><meta charset="utf-8"><title>${title}</title><body><h1>${title}</h1>${body}</body></html>`);
}

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

async function jsonBody(req:IncomingMessage) {
  const type=oneHeader(req,'content-type')?.split(';',1)[0]?.trim().toLowerCase();
  if(type!=='application/json')throw new HttpFailure(400);
  let value:unknown;
  try {value=JSON.parse(await body(req));} catch {throw new HttpFailure(400);}
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
    extraTokenClaims:(_ctx,token)=>({connection_id:'grantId' in token?token.grantId:undefined,azp:token.clientId,gate_approved:true}),
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
  async function startIdentityLogin(res:ServerResponse,interaction?:string) {
    const state=random(),binding=random();
    setCookies(res,[loginCookie(binding)]);
    await storage.saveLogin(hash(state),{binding:hash(binding),...(interaction?{interaction}:{})});
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
    const body=`<p>${escape(approval.appName)} requested a shared browser session.</p><p>Approving creates a device connection with full access to registered suite resources. Device: ${escape(approval.deviceLabel)}.</p><form method="post"><input type="hidden" name="transaction" value="${escape(ids[0]!)}"><input type="hidden" name="csrf" value="${escape(approval.csrf)}"><button name="decision" value="approve">Approve this device</button><button name="decision" value="deny">Deny</button></form>`;
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
    res.writeHead(204,{'cache-control':'no-store','set-cookie':clearSessionCookie(config)});res.end();
  }

  async function handler(req:IncomingMessage,res:ServerResponse) {
    let path='';
    try {
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
      if(path==='/github/callback'&&req.method==='GET') {
        const states=url.searchParams.getAll('state'),codes=url.searchParams.getAll('code');
        if(states.length!==1||codes.length!==1)throw new HttpFailure(400);
        const cookies=authCookies(req),binding=cookies.binding;
        if(!binding)throw new HttpFailure(400);
        const state=states[0]!,code=codes[0]!;
        const browserAttempt=await storage.takeBrowserLogin(state,binding);
        let interaction:string|undefined;
        if(!browserAttempt) {
          const saved=await storage.takeLogin(hash(state),hash(binding));
          if(!saved)throw new HttpFailure(400);
          interaction=saved.interaction;
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
        const destination=interaction?`/interaction/${encodeURIComponent(interaction)}`:'/connections';
        res.writeHead(303,{location:destination,'cache-control':'no-store'});res.end();return;
      }
      if(path==='/login'&&req.method==='GET'){
        authCookies(req);
        if(await currentIdentity(req)){res.writeHead(303,{location:'/connections','cache-control':'no-store'});res.end();return;}
        await startIdentityLogin(res);return;
      }
      if(path==='/connections'&&req.method==='GET') {
        authCookies(req);
        const s=await currentIdentity(req);if(!s){res.writeHead(303,{location:'/login','cache-control':'no-store'});res.end();return;}
        const rows=await storage.listConnections(accountId);
        page(res,'Connections',rows.map(r=>`<p>${escape(r.kind==='browser'?(r.deviceLabel??'This browser'):`Unverified OAuth client: ${r.clientName??r.clientId}`)} — ${escape(r.createdAt)}</p><form method="post" action="/connections/revoke"><input type="hidden" name="csrf" value="${escape(s.csrf)}"><input type="hidden" name="id" value="${escape(r.id)}"><button>Revoke connection</button></form>`).join('')||'<p>No connections.</p>');return;
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
          page(res,'Approve connection',`<p>Unverified client name: ${escape(name)}</p><p>Redirect URI: <code>${escape(redirectUri)}</code></p><p>Approving gives this client access to the registered Gate resources.</p><form method="post"><input type="hidden" name="csrf" value="${escape(s.csrf)}"><button name="decision" value="approve">Approve</button><button name="decision" value="deny">Deny</button></form>`,redirectOrigin);return;
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
        if(path==='/browser/session'||path==='/browser/logout')jsonFailure(res,error.status);
        else {res.writeHead(error.status,{'cache-control':'no-store'});res.end(error.status===401?'Unauthorized':error.status===403?'Forbidden':'Request failed');}
        return;
      }
      if(path.startsWith('/browser/')) {jsonFailure(res,503);return;}
      res.writeHead(400,{'cache-control':'no-store'});res.end('Request failed');
    }
  }
  return {provider,server:createServer((req,res)=>{void handler(req,res);})};
}

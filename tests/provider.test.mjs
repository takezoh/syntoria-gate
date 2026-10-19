import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes,createHash} from 'node:crypto';
import {request as httpRequest} from 'node:http';
import {once} from 'node:events';
import {Timestamp} from '@google-cloud/firestore';

import {createService} from '../dist/service.js';
import {createGateVerifier,GateError} from '../packages/sdk/dist/index.js';
import {adapter,Storage,firestore} from '../dist/storage.js';
if(!process.env.FIRESTORE_EMULATOR_HOST) throw new Error('FIRESTORE_EMULATOR_HOST is required: real Firestore Emulator tests must run');
if(!/^(127\.0\.0\.1|localhost|\[::1\]):[0-9]+$/.test(process.env.FIRESTORE_EMULATOR_HOST))throw new Error('Integration emulator must use loopback');
if(process.env.NODE_ENV==='production')throw new Error('Integration tests cannot run in production');
const projectId='demo-gate-test';
const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const jwk=privateKey.export({format:'jwk'});jwk.kid='test-key';jwk.use='sig';jwk.alg='RS256';
const db=firestore(projectId,'(default)');
const namespace='gate_test_'+randomBytes(12).toString('hex');
const storage=new Storage(db,namespace);
const issuer='http://127.0.0.1:55436';
const appRedirect='https://actions.example.test/auth-return.html';
const config={issuer,firestoreProjectId:projectId,firestoreDatabaseId:'(default)',githubClientId:'github-client',githubClientSecret:'github-secret',githubUserId:'12345',cookieKeys:['a'.repeat(64)],jwks:{keys:[jwk]},port:55436,sessionCookieDomain:'example.test',browserSessionTtlSeconds:3600,browserApps:[{app_id:'actions',app_name:'Actions',redirect_uris:[appRedirect]},{app_id:'lore',app_name:'Notes',redirect_uris:['https://notes.example.test/auth-return.html']}],browserOrigins:['https://actions.example.test','https://notes.example.test'],resources:[{audience:'https://weave.example',client_id:'weave',client_secret:'s'.repeat(40),browser_client_id:'weave-browser'}]};
let service;
const cookies=new Map();
async function request(path,options={}){
 const headers={connection:'close',...options.headers};
 if(!Object.keys(headers).some(name=>name.toLowerCase()==='cookie'))headers.cookie=[...cookies].filter(([,v])=>new URL(path,issuer).pathname.startsWith(v.path)).map(([k,v])=>`${k}=${v.value}`).join('; ');
 const response=await fetch(new URL(path,issuer),{...options,redirect:'manual',headers});
 for(const value of response.headers.getSetCookie()){const [entry]=value.split(';');const index=entry.indexOf('=');const name=entry.slice(0,index),cookieValue=entry.slice(index+1);if(/(?:^|;)\s*max-age=0(?:;|$)/i.test(value))cookies.delete(name);else cookies.set(name,{value:cookieValue,path:/(?:^|;)\s*path=([^;]+)/i.exec(value)?.[1]??'/',raw:value});}
 const text=await response.text();return {status:response.status,location:response.headers.get('location'),headers:response.headers,text,json:()=>JSON.parse(text)};
}
async function register(metadata, base=issuer) {
 const response=await fetch(new URL('/reg',base),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(metadata),redirect:'manual'});
 const text=await response.text();
 return {status:response.status,headers:response.headers,text,json:()=>JSON.parse(text)};
}
async function rawRequest(path,headers,body){
 return new Promise((resolve,reject)=>{
  const req=httpRequest({hostname:'127.0.0.1',port:55436,path,method:'POST',headers},response=>{
   const chunks=[];response.on('data',chunk=>chunks.push(chunk));response.on('end',()=>resolve({status:response.statusCode,text:Buffer.concat(chunks).toString('utf8')}));
  });
  req.on('error',reject);req.end(body);
 });
}
async function start(){service=await createService(config,storage,{exchange:async code=>code==='wrong'?'99999':'12345'});await new Promise(resolve=>service.server.listen(55436,'127.0.0.1',resolve));}
async function stop(){await new Promise(resolve=>service.server.close(resolve));}
async function connect(client,options={}){
 const redirectUri=options.redirectUri??client.redirect_uris[0];
 const verifier=randomBytes(32).toString('base64url');
 const params=new URLSearchParams({client_id:client.client_id,redirect_uri:redirectUri,response_type:'code',scope:'openid',resource:'https://weave.example',code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',state:'client-state'});
 let r=await request('/auth?'+params);
 for(let i=0;i<12;i++){
  assert.equal(r.status,303,r.text);
  if(r.location.startsWith(redirectUri)){
   if(options.decision==='deny'){assert.equal(new URL(r.location).searchParams.get('error'),'access_denied');return;}
   const code=new URL(r.location).searchParams.get('code');assert.ok(code,r.location);
   const result=await request('/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:client.client_id,redirect_uri:redirectUri,code,code_verifier:options.wrongVerifier?'b'.repeat(43):verifier})});if(options.wrongVerifier){assert.equal(result.status,400);return;}assert.equal(result.status,200,result.text);return result.json();
  }
  if(r.location.startsWith('https://github.com/')){
   const state=new URL(r.location).searchParams.get('state');r=await request('/github/callback?'+new URLSearchParams({state,code:'good'}));continue;
  }
  const location=r.location;r=await request(location);
  if(r.status===200&&new URL(location,issuer).pathname.startsWith('/interaction/')){
   if(client.client_name)assert.match(r.text,/Unverified client name: &lt;MCP &amp; Client&gt;/);
   else assert.match(r.text,/Unverified client name: No name supplied/);
   assert.ok(r.text.includes(redirectUri),r.text);
   assert.equal(r.headers.get('content-security-policy'),`default-src 'none'; form-action 'self' ${new URL(redirectUri).origin}; frame-ancestors 'none'; base-uri 'none'`);
   const csrf=/name="csrf" value="([^"]+)"/.exec(r.text)?.[1];assert.ok(csrf,r.text);
   r=await request(location,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',origin:issuer},body:new URLSearchParams({csrf,decision:options.decision??'approve'})});
  }
 }
 throw new Error('Authorization did not finish');
}
const introspect=token=>request('/token/introspection',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',authorization:'Basic '+Buffer.from('weave:'+config.resources[0].client_secret).toString('base64')},body:new URLSearchParams({token})});

async function assertSharedRegistrationLimit(limits) {
 const limitedNamespace=`${namespace}_limit_${randomBytes(6).toString('hex')}`;
 const services=await Promise.all([new Storage(db,limitedNamespace,Date.now,limits),new Storage(db,limitedNamespace,Date.now,limits)]
  .map(value=>createService(config,value,{exchange:async()=>{throw new Error('Unused');}})));
 const bases=[];
 try {
  for(const instance of services){instance.server.listen(0,'127.0.0.1');await once(instance.server,'listening');bases.push(`http://127.0.0.1:${instance.server.address().port}`);}
  const results=await Promise.all(bases.map((base,index)=>register({client_name:`quota-${index}`,redirect_uris:[`https://quota-${index}.example.test/callback`]},base)));
  assert.deepEqual(results.map(result=>result.status).sort(),[201,429]);
  const denied=results.find(result=>result.status===429);assert.equal(denied.json().error,'temporarily_unavailable');
 } finally {
  await Promise.all(services.filter(value=>value.server.listening).map(value=>new Promise(resolve=>value.server.close(resolve))));
 }
}

async function assertRegistrationFailsClosed() {
 const reference={doc(){return this;},collection(){return this;}};
 const unavailableDb={collection(){return reference;},async runTransaction(){throw new Error('private Firestore details');}};
 const failing=await createService(config,new Storage(unavailableDb,`${namespace}_unavailable`),{exchange:async()=>{throw new Error('Unused');}});
 try {
  failing.server.listen(0,'127.0.0.1');await once(failing.server,'listening');
  const response=await register({redirect_uris:['https://unavailable.example.test/callback']},`http://127.0.0.1:${failing.server.address().port}`);
  assert.equal(response.status,503,response.text);assert.doesNotMatch(response.text,/private Firestore details/);
 } finally {
  if(failing.server.listening)await new Promise(resolve=>failing.server.close(resolve));
 }
}

async function assertRegistrationWindowNeverMovesBackward() {
 const monotonicNamespace=`${namespace}_clock_${randomBytes(6).toString('hex')}`;
 const limits={total:10,perMinute:1};
 const alignedWindow=Math.ceil(Date.now()/60_000)*60_000+60_000;
 const older=new Storage(db,monotonicNamespace,()=>alignedWindow-59_000,limits);
 const current=new Storage(db,monotonicNamespace,()=>alignedWindow+1_000,limits);
 const later=new Storage(db,monotonicNamespace,()=>alignedWindow+61_000,limits);
 await current.upsert('Client','newer-window',{client_id:'newer-window'});
 await assert.rejects(older.upsert('Client','stale-window',{client_id:'stale-window'}),error=>error.statusCode===429);
 await later.upsert('Client','following-window',{client_id:'following-window'});
}

test('real provider / real Firestore Emulator: separate connections, restart, revoke and refresh',async()=>{
 try {
 await start();
 for(const metadata of [
  {redirect_uris:['https://mcp.example.test/callback'],jwks_uri:'https://127.0.0.1:1/jwks'},
  {redirect_uris:['https://mcp.example.test/callback'],sector_identifier_uri:'https://127.0.0.1:1/sector'},
  {redirect_uris:['https://mcp.example.test/callback'],request_uris:['https://127.0.0.1:1/request']},
  {redirect_uris:['https://mcp.example.test/callback'],token_endpoint_auth_method:'client_secret_basic'},
  {redirect_uris:['https://mcp.example.test/callback'],client_secret:'supplied'},
  {redirect_uris:['https://mcp.example.test/callback'],application_type:'native'},
  {redirect_uris:['https://mcp.example.test/*']},
  {redirect_uris:['http://127.0.0.1:55437/callback','https://mcp.example.test/callback']},
  {redirect_uris:['https://user@mcp.example.test/callback']},
  {redirect_uris:['https://mcp.example.test/callback#fragment']},
  {redirect_uris:['https://mcp.example.test/callback'],grant_types:['client_credentials']},
 ]) assert.ok((await register(metadata)).status>=400,JSON.stringify(metadata));
 const oversized=await request('/reg',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({redirect_uris:['https://mcp.example.test/callback'],padding:'x'.repeat(8192)})});assert.equal(oversized.status,413);
 const webResponse=await register({client_name:'<MCP & Client>',redirect_uris:['https://mcp.example.test/callback'],grant_types:['authorization_code','refresh_token'],client_uri:'http://127.0.0.1:1/client',logo_uri:'http://127.0.0.1:1/logo',software_id:'ignored',software_version:'ignored',scope:'openid'});
 assert.equal(webResponse.status,201,webResponse.text);const webClient=webResponse.json();
 assert.equal(webClient.application_type,'web');assert.equal(webClient.token_endpoint_auth_method,'none');assert.deepEqual(webClient.grant_types,['authorization_code','refresh_token']);assert.deepEqual(webClient.response_types,['code']);assert.equal('client_secret' in webClient,false);assert.equal('registration_access_token' in webClient,false);assert.equal('registration_client_uri' in webClient,false);
 const nativeResponse=await register({redirect_uris:['http://127.0.0.1:55437/callback']});assert.equal(nativeResponse.status,201,nativeResponse.text);const nativeClient=nativeResponse.json();
 assert.equal(nativeClient.application_type,'native');assert.equal(nativeClient.token_endpoint_auth_method,'none');assert.deepEqual(nativeClient.grant_types,['authorization_code']);
 const storedWeb=await storage.find('Client',webClient.client_id);assert.equal(storedWeb.client_uri,undefined);assert.equal(storedWeb.logo_uri,undefined);assert.equal(storedWeb.software_id,undefined);assert.equal(storedWeb.scope,undefined);
 const clientDocument=await storage.artifacts('Client').doc(createHash('sha256').update(webClient.client_id).digest('hex')).get();assert.ok(clientDocument.exists);assert.equal(clientDocument.get('expiresAt'),undefined);
 const initialCount=(await storage.listConnections('github:12345')).length;await connect(webClient,{decision:'deny'});assert.equal((await storage.listConnections('github:12345')).length,initialCount);
 const missingPkce=await request('/auth?'+new URLSearchParams({client_id:webClient.client_id,redirect_uri:webClient.redirect_uris[0],response_type:'code',scope:'openid'}));assert.ok(new URL(missingPkce.location,issuer).searchParams.has('error'));
 await connect(webClient,{wrongVerifier:true});
 const first=await connect(webClient);assert.ok(first.refresh_token);
 const verifier=createGateVerifier({issuer,audience:'https://weave.example',clientId:'weave',clientSecret:config.resources[0].client_secret,browserClientId:'weave-browser',allowLoopbackHttp:true});
 assert.equal((await verifier.verifyToken(first.access_token)).userId,'github:12345');
 const a=(await introspect(first.access_token)).json();assert.equal(a.active,true);assert.equal(a.sub,'github:12345');assert.ok(a.connection_id);assert.equal(a.token_type,'Bearer');
 const second=await connect(webClient);const b=(await introspect(second.access_token)).json();assert.equal(b.active,true);assert.notEqual(a.connection_id,b.connection_id);
 const nativeFlow=await connect(nativeClient,{redirectUri:'http://127.0.0.1:55438/callback'});assert.ok(nativeFlow.access_token);assert.equal((await introspect(nativeFlow.access_token)).json().active,true);
 for(const redirectUri of ['http://127.0.0.2:55438/callback','http://127.0.0.1:55438/other']) {
  const invalid=await request('/auth?'+new URLSearchParams({client_id:nativeClient.client_id,redirect_uri:redirectUri,response_type:'code',scope:'openid',code_challenge:'a'.repeat(43),code_challenge_method:'S256'}));
  assert.equal(invalid.status,400,invalid.location);
 }
 await stop();await start();assert.equal((await introspect(first.access_token)).json().active,true);assert.ok(await storage.find('Client',webClient.client_id));assert.ok(await storage.find('Client',nativeClient.client_id));
 const deletedClient=await connect(nativeClient);
 await storage.artifacts('Client').doc(createHash('sha256').update(nativeClient.client_id).digest('hex')).delete();
 assert.deepEqual((await introspect(deletedClient.access_token)).json().active,false);
 await assertSharedRegistrationLimit({total:1,perMinute:10});
 await assertSharedRegistrationLimit({total:10,perMinute:1});
 await assertRegistrationWindowNeverMovesBackward();
 await assertRegistrationFailsClosed();
 const list=await request('/connections');assert.equal(list.status,200);assert.ok(list.text.includes(a.connection_id));
 assert.equal(list.headers.get('content-security-policy'),"default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
 const csrf=/name="csrf" value="([^"]+)"/.exec(list.text)[1];
 assert.equal((await request('/connections/revoke',{method:'POST',headers:{origin:issuer,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:'wrong',id:a.connection_id})})).status,403);
 const revoked=await request('/connections/revoke',{method:'POST',headers:{origin:issuer,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf,id:a.connection_id})});assert.equal(revoked.status,303);
 assert.equal((await introspect(first.access_token)).json().active,false);await assert.rejects(verifier.verifyToken(first.access_token),e=>e instanceof GateError&&e.status===401);assert.equal((await introspect(second.access_token)).json().active,true);
 const refresh=await request('/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'refresh_token',refresh_token:first.refresh_token,client_id:webClient.client_id})});assert.equal(refresh.status,400);
 const refreshGood=await request('/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'refresh_token',refresh_token:second.refresh_token,client_id:webClient.client_id})});assert.equal(refreshGood.status,200,refreshGood.text);const refreshed=(await introspect(refreshGood.json().access_token)).json();assert.equal(refreshed.connection_id,b.connection_id);
 assert.equal((await introspect(second.refresh_token)).json().active,false);


 const raceConnection=await connect(webClient);const racePrincipal=(await introspect(raceConnection.access_token)).json();
 const raceList=await request('/connections');const raceCsrf=/name="csrf" value="([^"]+)"/.exec(raceList.text)[1];
 const [raceRefresh,raceRevoke]=await Promise.all([
 request('/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'refresh_token',client_id:webClient.client_id,refresh_token:raceConnection.refresh_token})}),
 request('/connections/revoke',{method:'POST',headers:{origin:issuer,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:raceCsrf,id:racePrincipal.connection_id})})]);
 assert.equal(raceRevoke.status,303);assert.equal((await introspect(raceConnection.access_token)).json().active,false);
 if(raceRefresh.status===200) assert.equal((await introspect(raceRefresh.json().access_token)).json().active,false);
 const raceRetry=await request('/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'refresh_token',client_id:webClient.client_id,refresh_token:raceRefresh.status===200?raceRefresh.json().refresh_token:raceConnection.refresh_token})});assert.equal(raceRetry.status,400);
 const reuseConnection=await connect(webClient);
 const concurrentRefresh=()=>request('/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'refresh_token',client_id:webClient.client_id,refresh_token:reuseConnection.refresh_token})});
 const reused=await Promise.all([concurrentRefresh(),concurrentRefresh()]);assert.ok(reused.filter(r=>r.status===200).length<=1);
 assert.equal((await introspect(second.access_token)).json().active,true);
 const A=adapter(storage);const artifact=new A('AuthorizationCode');const artifactId=randomBytes(16).toString('hex');
 await artifact.upsert(artifactId,{grantId:b.connection_id},60);
 const consumed=await Promise.allSettled([artifact.consume(artifactId),artifact.consume(artifactId)]);
 assert.equal(consumed.filter(r=>r.status==='fulfilled').length,1);
 const consumedAt=(await artifact.find(artifactId)).consumed;await artifact.upsert(artifactId,{grantId:b.connection_id},60);assert.equal((await artifact.find(artifactId)).consumed,consumedAt);await assert.rejects(artifact.consume(artifactId));
 await storage.revoke(b.connection_id,'github:99999');assert.equal((await introspect(second.access_token)).json().active,true);
 const raceId=randomBytes(16).toString('hex');const tokens=new A('AccessToken');
 await Promise.allSettled([tokens.upsert(raceId,{grantId:b.connection_id},60),storage.revoke(b.connection_id)]);
 assert.equal(await tokens.find(raceId),undefined);
 await assert.rejects(tokens.upsert(raceId,{grantId:b.connection_id},60));
 await storage.saveLogin('single-state',{binding:'test'});const states=await Promise.all([storage.takeLogin('single-state','test'),storage.takeLogin('single-state','test')]);assert.equal(states.filter(Boolean).length,1);
 const noPrompt=await request('/auth?'+new URLSearchParams({client_id:webClient.client_id,redirect_uri:webClient.redirect_uris[0],response_type:'code',scope:'openid',prompt:'none',code_challenge:'a'.repeat(43),code_challenge_method:'S256'}));
 assert.ok(new URL(noPrompt.location,issuer).searchParams.has('error'));
 const independentMcp=await connect(webClient);const independentMcpPrincipal=(await introspect(independentMcp.access_token)).json();assert.equal(independentMcpPrincipal.active,true);
 await tokens.upsert('expired',{grantId:independentMcpPrincipal.connection_id},-1);assert.equal(await tokens.find('expired'),undefined);
 cookies.clear();const login=await request('/login');const state=new URL(login.location).searchParams.get('state');
 const denied=await request('/github/callback?'+new URLSearchParams({state,code:'wrong'}));assert.equal(denied.status,403);
 assert.equal((await request('/github/callback?'+new URLSearchParams({state,code:'good'}))).status,400);

 const invalidBrowserReturn=await request('/browser/login?'+new URLSearchParams({app_id:'actions',redirect_uri:'https://outside.test/return'}));assert.equal(invalidBrowserReturn.status,400);assert.equal(invalidBrowserReturn.location,null);
 const browserStart=await request('/browser/login?'+new URLSearchParams({app_id:'actions',redirect_uri:appRedirect}),{headers:{'user-agent':'Test device'}});
 assert.equal(browserStart.status,303);assert.ok(browserStart.location.startsWith('https://github.com/'));
 const browserState=new URL(browserStart.location).searchParams.get('state');
 const browserCallback=await request('/github/callback?'+new URLSearchParams({state:browserState,code:'good'}));assert.equal(browserCallback.status,303);
 assert.ok(browserCallback.location.startsWith('/browser/approve?transaction='));assert.equal(cookies.has('__Secure-gate_session'),false);
 const identityCookie=cookies.get('__Host-gate_identity').value;
 const identityOnly=await request('/browser/session',{headers:{origin:'https://actions.example.test',cookie:`__Host-gate_identity=${identityCookie}`}});
 assert.equal(identityOnly.status,401);assert.equal(identityOnly.headers.get('access-control-allow-origin'),'https://actions.example.test');
 const duplicateLogin=await request(browserCallback.location,{headers:{cookie:`__Host-gate_identity=${identityCookie}; __Host-gate_login=${cookies.get('__Host-gate_login').value}; __Host-gate_login=${cookies.get('__Host-gate_login').value}`}});assert.equal(duplicateLogin.status,400);
 const approvalPage=await request(browserCallback.location);assert.equal(approvalPage.status,200);
 assert.match(approvalPage.text,/full access to registered suite resources/);assert.match(approvalPage.text,/Test device/);
 assert.equal(approvalPage.headers.get('content-security-policy'),"default-src 'none'; form-action 'self' https://actions.example.test; frame-ancestors 'none'; base-uri 'none'");
 const transaction=/name="transaction" value="([^"]+)"/.exec(approvalPage.text)?.[1];const approvalCsrf=/name="csrf" value="([^"]+)"/.exec(approvalPage.text)?.[1];assert.ok(transaction&&approvalCsrf);
 const approvalPost=(origin,csrf)=>request('/browser/approve',{method:'POST',headers:{origin,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({transaction,csrf,decision:'approve'})});
 assert.equal((await approvalPost('https://evil.example.test',approvalCsrf)).status,403);
 assert.equal((await approvalPost(issuer,'wrong')).status,403);
 const [approvalRaceA,approvalRaceB]=await Promise.all([approvalPost(issuer,approvalCsrf),approvalPost(issuer,approvalCsrf)]);
 assert.deepEqual([approvalRaceA.status,approvalRaceB.status].sort(),[303,403]);
 const approved=approvalRaceA.status===303?approvalRaceA:approvalRaceB;assert.equal(approved.location,appRedirect);
 const cookieLine=approved.headers.getSetCookie().find(value=>value.startsWith('__Secure-gate_session='));assert.ok(cookieLine);
 for(const attribute of ['Secure','HttpOnly','SameSite=Lax','Path=/','Domain=example.test','Max-Age=3600'])assert.ok(cookieLine.includes(attribute),cookieLine);
 const browserSecret=cookies.get('__Secure-gate_session').value;
 const sessionDocId=createHash('sha256').update(browserSecret).digest('hex');const sessionDoc=await db.collection(`${namespace}_browser_sessions`).doc(sessionDocId).get();
 assert.ok(sessionDoc.exists);assert.ok(!JSON.stringify(sessionDoc.data()).includes(browserSecret));assert.equal(sessionDoc.id,sessionDocId);
 const browserConnection=await storage.connection(sessionDoc.get('connectionId')).get();assert.equal(browserConnection.get('kind'),'browser');assert.equal(browserConnection.get('approved'),true);assert.equal(browserConnection.get('clientId'),'browser');
 const otherApp=await request('/browser/login?'+new URLSearchParams({app_id:'lore',redirect_uri:'https://notes.example.test/auth-return.html'}));assert.equal(otherApp.status,303);assert.equal(otherApp.location,'https://notes.example.test/auth-return.html');
 const sessionBootstrap=await request('/browser/session',{headers:{origin:'https://actions.example.test'}});assert.equal(sessionBootstrap.status,200);
 assert.deepEqual(Object.keys(sessionBootstrap.json()).sort(),['csrf_token']);assert.equal(sessionBootstrap.headers.get('access-control-allow-credentials'),'true');
 assert.equal((await request('/browser/session',{headers:{origin:'https://actions.example.test',cookie:`__Secure-gate_session=${browserSecret}; __Secure-gate_session=${browserSecret}`}})).status,400);
 assert.equal((await request('/browser/session',{headers:{origin:'https://evil.example.test'}})).status,403);
 assert.equal((await request('/browser/session',{headers:{origin:'https://evil.example.test'}})).headers.get('access-control-allow-origin'),null);
 assert.equal((await request('/browser/session',{headers:{origin:'https://actions.example.test',authorization:'Bearer ignored'}})).status,401);
 const preflight=await request('/browser/logout',{method:'OPTIONS',headers:{origin:'https://actions.example.test','access-control-request-method':'POST','access-control-request-headers':'content-type,x-csrf-token'}});
 assert.equal(preflight.status,204);assert.equal(preflight.headers.get('access-control-allow-origin'),'https://actions.example.test');assert.equal(preflight.headers.get('access-control-allow-credentials'),'true');
 const sessionSdkConfig={issuer,audience:config.resources[0].audience,clientId:config.resources[0].client_id,clientSecret:config.resources[0].client_secret,browserClientId:config.resources[0].browser_client_id,allowLoopbackHttp:true};
 const localFetch=async(url,init)=>{const result=await request(new URL(url).pathname,init);return new Response(result.text,{status:result.status,headers:{'content-type':result.headers.get('content-type')??'application/json'}});};
 const browserVerifier=createGateVerifier(sessionSdkConfig,{fetch:localFetch});
 const browserPrincipal=await browserVerifier.verifySession(browserSecret);assert.equal(browserPrincipal.userId,'github:12345');assert.equal(browserPrincipal.clientId,'weave-browser');assert.equal(browserPrincipal.connectionId,sessionDoc.get('connectionId'));assert.ok(Object.isFrozen(browserPrincipal));
 const wrongAudience=createGateVerifier({...sessionSdkConfig,audience:'https://other.example.test/mcp'},{fetch:localFetch});await assert.rejects(wrongAudience.verifySession(browserSecret),e=>e instanceof GateError&&e.status===503);
 const wrongResource=createGateVerifier({...sessionSdkConfig,clientSecret:'x'.repeat(40)},{fetch:localFetch});await assert.rejects(wrongResource.verifySession(browserSecret),e=>e instanceof GateError&&e.status===503);
 const invalidIntrospection=await request('/browser/session/introspect',{method:'POST',headers:{authorization:'Basic '+Buffer.from(`weave:${config.resources[0].client_secret}`).toString('base64'),'content-type':'application/json'},body:JSON.stringify({session:randomBytes(32).toString('base64url'),resource:config.resources[0].audience})});assert.deepEqual(invalidIntrospection.json(),{active:false});
 const wrongIntrospectionAudience=await request('/browser/session/introspect',{method:'POST',headers:{authorization:'Basic '+Buffer.from(`weave:${config.resources[0].client_secret}`).toString('base64'),'content-type':'application/json'},body:JSON.stringify({session:browserSecret,resource:'https://other.example.test/mcp'})});assert.equal(wrongIntrospectionAudience.status,403);
 const resourceAuthorization='Basic '+Buffer.from(`weave:${config.resources[0].client_secret}`).toString('base64');
 const duplicateAuthorization=await rawRequest('/browser/session/introspect',['authorization',resourceAuthorization,'authorization',resourceAuthorization,'content-type','application/json'],JSON.stringify({session:browserSecret,resource:config.resources[0].audience}));assert.ok(duplicateAuthorization.status===400||duplicateAuthorization.status===401);
 const expiredBrowserSecret=randomBytes(32).toString('base64url');await db.collection(`${namespace}_browser_sessions`).doc(createHash('sha256').update(expiredBrowserSecret).digest('hex')).set({userId:'github:12345',connectionId:sessionDoc.get('connectionId'),csrf:randomBytes(32).toString('base64url'),createdAt:Timestamp.now(),expiresAt:Timestamp.fromMillis(Date.now()-1000)});
 assert.equal(await storage.browser(expiredBrowserSecret),undefined);assert.deepEqual((await request('/browser/session/introspect',{method:'POST',headers:{authorization:'Basic '+Buffer.from(`weave:${config.resources[0].client_secret}`).toString('base64'),'content-type':'application/json'},body:JSON.stringify({session:expiredBrowserSecret,resource:config.resources[0].audience})})).json(),{active:false});
 const orphanSecret=randomBytes(32).toString('base64url');await db.collection(`${namespace}_browser_sessions`).doc(createHash('sha256').update(orphanSecret).digest('hex')).set({userId:'github:12345',connectionId:'missing-browser-connection',csrf:randomBytes(32).toString('base64url'),createdAt:Timestamp.now(),expiresAt:Timestamp.fromMillis(Date.now()+60_000)});
 assert.equal(await storage.browser(orphanSecret),undefined);
 const futureStorage=new Storage(db,namespace,()=>Date.now()+3_601_000);assert.equal(await futureStorage.logoutBrowser(browserSecret,sessionDoc.get('connectionId')),false);
 const logout=await request('/browser/logout',{method:'POST',headers:{origin:'https://actions.example.test','content-type':'application/json','x-csrf-token':browserPrincipal.csrfToken},body:'{}'});assert.equal(logout.status,204);
 assert.equal((await browserVerifier.verifySession(browserSecret).catch(error=>error.status)),401);assert.equal(await storage.browser(browserSecret),undefined);
 assert.ok(logout.headers.getSetCookie().some(value=>value.startsWith('__Secure-gate_session=')&&value.includes('Domain=example.test')&&/max-age=0/i.test(value)));
 const afterLogout=await request('/browser/login?'+new URLSearchParams({app_id:'lore',redirect_uri:'https://notes.example.test/auth-return.html'}));assert.equal(afterLogout.status,303);assert.ok(afterLogout.location.startsWith('/browser/approve?transaction='));
 const denyPage=await request(afterLogout.location);const denyTransaction=/name="transaction" value="([^"]+)"/.exec(denyPage.text)[1];const denyCsrf=/name="csrf" value="([^"]+)"/.exec(denyPage.text)[1];
 const deny=await request('/browser/approve',{method:'POST',headers:{origin:issuer,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({transaction:denyTransaction,csrf:denyCsrf,decision:'deny'})});assert.equal(deny.status,303);assert.equal(deny.location,'https://notes.example.test/auth-return.html');assert.equal(cookies.has('__Secure-gate_session'),false);
 const secondStart=await request('/browser/login?'+new URLSearchParams({app_id:'actions',redirect_uri:appRedirect}),{headers:{'user-agent':'Test device 2'}});const secondPage=await request(secondStart.location);const secondTransaction=/name="transaction" value="([^"]+)"/.exec(secondPage.text)[1];const secondCsrf=/name="csrf" value="([^"]+)"/.exec(secondPage.text)[1];
 const secondApproval=await request('/browser/approve',{method:'POST',headers:{origin:issuer,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({transaction:secondTransaction,csrf:secondCsrf,decision:'approve'})});assert.equal(secondApproval.status,303);
 const secondSecret=cookies.get('__Secure-gate_session').value;const connectionsPage=await request('/connections');assert.equal(connectionsPage.status,200);assert.equal(connectionsPage.text.includes('Test device 2'),true);
 const managementCsrf=/name="csrf" value="([^"]+)"/.exec(connectionsPage.text)[1];const secondSession=await storage.browser(secondSecret);assert.ok(secondSession);assert.notEqual(secondSession.connectionId,b.connection_id);
 assert.equal((await storage.connection(independentMcpPrincipal.connection_id).get()).get('revoked'),false);
 const revokeBrowser=await request('/connections/revoke',{method:'POST',headers:{origin:issuer,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:managementCsrf,id:secondSession.connectionId})});assert.equal(revokeBrowser.status,303);
 assert.equal((await request('/browser/session/introspect',{method:'POST',headers:{authorization:'Basic '+Buffer.from(`weave:${config.resources[0].client_secret}`).toString('base64'),'content-type':'application/json'},body:JSON.stringify({session:secondSecret,resource:config.resources[0].audience})})).json().active,false);
 assert.equal((await storage.connection(secondSession.connectionId).get()).get('revoked'),true);
 assert.equal((await storage.connection(independentMcpPrincipal.connection_id).get()).get('revoked'),false);
 assert.equal((await introspect(independentMcp.access_token)).json().active,true);
 } finally {if(service?.server.listening)await stop();await db.terminate();}
});

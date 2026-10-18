import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {once} from 'node:events';
import {createService} from '../dist/service.js';
import {Storage} from '../dist/storage.js';
const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const config={issuer:'http://127.0.0.1:3000',firestoreProjectId:'demo-gate-test',firestoreDatabaseId:'(default)',githubClientId:'test',githubClientSecret:'test',githubUserId:'123',cookieKeys:['a'.repeat(32)],jwks:{keys:[{...privateKey.export({format:'jwk'}),kid:'test',alg:'RS256',use:'sig'}]},port:3000,clients:[{client_id:'web',client_name:'Web',redirect_uris:['http://127.0.0.1:3001/callback']}],resources:[{audience:'https://resource.example/mcp',client_id:'resource',client_secret:'b'.repeat(32)}]};
test('readiness verifies storage and returns no storage details; liveness does not access it',async()=>{
 let reads=0,fail=false;
 const storage=new Storage({doc(path){assert.equal(path,'gate_health/readiness');return {async get(){reads++;if(fail)throw new Error('private infrastructure details');return {exists:false};}};}});
 const {server}=await createService(config,storage,{exchange:async()=>{throw new Error('Unused');}});
 server.listen(0,'127.0.0.1');await once(server,'listening');
 const url=`http://127.0.0.1:${server.address().port}`;
 try {
  assert.equal((await fetch(`${url}/healthz`)).status,200);assert.equal(reads,0);
  const ready=await fetch(`${url}/readyz`);assert.equal(ready.status,200);assert.equal(await ready.text(),'ok');assert.equal(reads,1);
  fail=true;const unavailable=await fetch(`${url}/readyz`);assert.equal(unavailable.status,503);assert.equal(await unavailable.text(),'unavailable');
  assert.equal((await fetch(`${url}/healthz`)).status,200);assert.equal(reads,2);
 }finally{server.close();await once(server,'close');}
});
test('readiness stops waiting for an unresponsive database',async()=>{
 const storage=new Storage({doc(){return {get:()=>new Promise(()=>{})};}});
 const start=Date.now();await assert.rejects(storage.ready(),/readiness timeout/);assert.ok(Date.now()-start<3000);
});

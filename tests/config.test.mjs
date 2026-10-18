import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readConfig} from '../dist/config.js';
const env={NODE_ENV:'production',GATE_FIRESTORE_PROJECT_ID:'demo-gate-test',GATE_FIRESTORE_DATABASE_ID:'(default)',GATE_ISSUER:'https://gate.example.test',GATE_SESSION_COOKIE_DOMAIN:'example.test',GATE_BROWSER_SESSION_TTL_SECONDS:'2592000',GATE_BROWSER_APPS:JSON.stringify([{app_id:'action-tools',app_name:'Actions',redirect_uris:['https://actions.example.test/auth-return.html']}]),GATE_GITHUB_CLIENT_ID:'client',GATE_GITHUB_CLIENT_SECRET:'secret',GATE_GITHUB_USER_ID:'123',GATE_COOKIE_KEYS:JSON.stringify(['a'.repeat(32)]),GATE_JWKS:JSON.stringify({keys:[{kty:'RSA',d:'private'}]}),GATE_CLIENTS:JSON.stringify([{client_id:'desktop',client_name:'Desktop',redirect_uris:['http://127.0.0.1:8000/callback']}]),GATE_RESOURCES:JSON.stringify([{client_id:'weave-api',client_secret:'x'.repeat(32),audience:'https://api.example.test/mcp',browser_client_id:'weave-browser'}])};
test('personal configuration validates issuer cookie scope, browser redirects, TTL and resource grants',()=>{
 const config=readConfig(env);
 assert.equal(config.githubUserId,'123');
 assert.equal(config.sessionCookieDomain,'example.test');
 assert.equal(config.browserSessionTtlSeconds,2592000);
 assert.deepEqual(config.browserOrigins,['https://actions.example.test']);
 for(const change of [
 {GATE_GITHUB_USER_ID:'username'}, {FIRESTORE_EMULATOR_HOST:'127.0.0.1:8080'}, {GATE_FIRESTORE_PROJECT_ID:''}, {GATE_FIRESTORE_DATABASE_ID:'bad/path'}, {GATE_ISSUER:'http://127.0.0.1:3000'}, {GATE_COOKIE_KEYS:'["short"]'},
 {GATE_SESSION_COOKIE_DOMAIN:'.example.test'}, {GATE_SESSION_COOKIE_DOMAIN:'localhost'}, {GATE_SESSION_COOKIE_DOMAIN:'127.0.0.1'}, {GATE_ISSUER:'https://example.test'}, {GATE_ISSUER:'https://gate.other.test'},
 {GATE_BROWSER_SESSION_TTL_SECONDS:'3599'}, {GATE_BROWSER_SESSION_TTL_SECONDS:'2592001'}, {GATE_BROWSER_SESSION_TTL_SECONDS:'30d'},
 {GATE_BROWSER_APPS:JSON.stringify([{app_id:'action-tools',app_name:'Actions',redirect_uris:['http://actions.example.test/callback']}])},
 {GATE_BROWSER_APPS:JSON.stringify([{app_id:'action-tools',app_name:'Actions',redirect_uris:['https:actions.example.test/callback']}])},
 {GATE_BROWSER_APPS:JSON.stringify([{app_id:'action-tools',app_name:'Actions',redirect_uris:['https://actions.example.test\\auth-return.html']}])},
 {GATE_BROWSER_APPS:JSON.stringify([{app_id:'action-tools',app_name:'Actions',redirect_uris:['https://actions.example.test/callback#fragment']}])},
 {GATE_BROWSER_APPS:JSON.stringify([{app_id:'action-tools',app_name:'Actions',redirect_uris:['https://outside.test/callback']}])},
 {GATE_CLIENTS:JSON.stringify([{client_id:'desktop',client_name:'Desktop',redirect_uris:['https://app.example/*']}])},
 {GATE_RESOURCES:JSON.stringify([{client_id:'weave',client_secret:'x'.repeat(32),audience:'https://user:secret@weave.example'}])},
 {GATE_RESOURCES:JSON.stringify([{client_id:'desktop',client_secret:'x'.repeat(32),audience:'https://weave.example'}])},
 {GATE_RESOURCES:JSON.stringify([{client_id:'weave',client_secret:'short',audience:'https://weave.example'}])},
 {GATE_RESOURCES:JSON.stringify([{client_id:'weave-api',client_secret:'x'.repeat(32),audience:'https://api.example.test/mcp'}])},
 {GATE_RESOURCES:JSON.stringify([{client_id:'weave-api',client_secret:'x'.repeat(32),audience:'https://outside.test/mcp',browser_client_id:'weave-browser'}])},
 ]) assert.throws(()=>readConfig({...env,...change}));
});

test('browser CORS origins are derived from registered redirects and deduplicated',()=>{
 const config=readConfig({...env,GATE_BROWSER_APPS:JSON.stringify([
  {app_id:'action-tools',app_name:'Actions',redirect_uris:['https://actions.example.test/return','https://actions.example.test/auth-return.html']},
  {app_id:'notes',app_name:'Notes',redirect_uris:['https://notes.example.test/return']},
 ])});
 assert.deepEqual(config.browserOrigins,['https://actions.example.test','https://notes.example.test']);
});

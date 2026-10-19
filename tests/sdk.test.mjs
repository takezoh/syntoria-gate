import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createGateVerifier, GateError, protectedResourceMetadata } from '../packages/sdk/dist/index.js';

const issuer = 'https://gate.example/realms/syntoria';
const endpoint = `${issuer}/protocol/openid-connect/token/introspect`;
const config = { issuer, audience: 'https://weave.example', clientId: 'resource', clientSecret: 'secret', browserClientId: 'weave-browser' };
const clock = 1_700_000_000_000;
const sessionEndpoint = `${issuer}/browser/session/introspect`;
const sessionSecret = randomBytes(32).toString('base64url');
const active = (extra = {}) => ({ active: true, token_type: 'Bearer', gate_approved: true, iss: issuer, sub: 'person-a', connection_id: 'connection-a', client_id: 'dcr-public-client', azp: 'dcr-public-client', aud: config.audience, exp: clock / 1000 + 60, ...extra });
const json = (data, options = {}) => new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json' }, ...options });
function fixture(result = active(), options = {}) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith('/.well-known/openid-configuration')) return json({ issuer, introspection_endpoint: endpoint });
    return typeof result === 'function' ? result(url, init) : json(result);
  };
  return { calls, verifier: createGateVerifier({ ...config, ...options }, { fetch, now: () => clock }) };
}
const status = (expected) => error => error instanceof GateError && error.status === expected;

const browserActive = (extra = {}) => ({active:true,iss:issuer,sub:'person-a',connection_id:'browser-connection-a',client_id:config.browserClientId,aud:config.audience,exp:clock/1000+60,gate_approved:true,session_type:'browser',csrf_token:randomBytes(32).toString('base64url'),...extra});
function sessionFixture(result = browserActive(), options = {}) {
  const calls=[];
  const fetch=async (url,init)=>{
    calls.push({url,init});
    if(typeof result==='function')return result(url,init);
    return json(result);
  };
  return {calls,verifier:createGateVerifier({...config,...options},{fetch,now:()=>clock})};
}

test('browser session introspection is fresh, resource-bound and returns a frozen typed principal',async()=>{
  let inactive=false;
  const data=browserActive();
  const {calls,verifier}=sessionFixture(()=>json(inactive?{active:false}:data));
  const principal=await verifier.verifySession(sessionSecret);
  assert.deepEqual(principal,{issuer,userId:'person-a',connectionId:'browser-connection-a',clientId:config.browserClientId,expiresAt:data.exp,csrfToken:data.csrf_token,sessionType:'browser'});
  assert.ok(Object.isFrozen(principal));
  assert.equal(calls[0].url,sessionEndpoint);
  assert.equal(calls[0].init.method,'POST');
  assert.equal(calls[0].init.redirect,'error');
  assert.equal(calls[0].init.headers.accept,'application/json');
  assert.equal(calls[0].init.headers['content-type'],'application/json');
  assert.equal(JSON.parse(calls[0].init.body).session,sessionSecret);
  assert.equal(JSON.parse(calls[0].init.body).resource,config.audience);
  assert.equal(Buffer.from(calls[0].init.headers.authorization.slice(6),'base64').toString(),'resource:secret');
  inactive=true;
  await assert.rejects(verifier.verifySession(sessionSecret),status(401));
  assert.equal(calls.length,2);
});

for(const [name,change] of Object.entries({
  'wrong issuer':{iss:'https://other.example'},
  'wrong audience':{aud:'https://other.example'},
  'array audience':{aud:[config.audience]},
  'wrong browser client':{client_id:'dcr-public-client'},
  'missing subject':{sub:undefined},
  'missing connection':{connection_id:undefined},
  'missing CSRF token':{csrf_token:undefined},
  'not a browser session':{session_type:'oauth'},
  'missing approval':{gate_approved:undefined},
  'expired session':{exp:clock/1000},
  'fractional expiry':{exp:clock/1000+60.5},
  'string expiry':{exp:String(clock/1000+60)},
})) {
  test(`rejects browser session introspection with ${name}`,async()=>{
    await assert.rejects(sessionFixture(browserActive(change)).verifier.verifySession(sessionSecret),status(401));
  });
}

test('malformed browser session secrets fail before network access',async()=>{
  const {calls,verifier}=sessionFixture();
  for(const value of ['', 'token', 'a'.repeat(43), 'a'.repeat(44), `${sessionSecret}=`]) await assert.rejects(verifier.verifySession(value),status(401));
  assert.equal(calls.length,0);
});

for(const [name,response] of Object.entries({
  'resource authentication failure':()=>json({}, {status:401}),
  'resource authorization failure':()=>json({}, {status:403}),
  outage:()=>json({}, {status:503}),
  redirect:()=>new Response('',{status:302,headers:{location:'https://other.example'}}),
  'malformed JSON':()=>new Response('{',{headers:{'content-type':'application/json'}}),
  'non-JSON response':()=>new Response('<html>unavailable</html>'),
})) {
  test(`maps ${name} to authorization unavailable for browser sessions`,async()=>{
    await assert.rejects(sessionFixture(response).verifier.verifySession(sessionSecret),status(503));
  });
}

test('fresh native introspection on every request, including immediate revoke', async () => {
  let revoked = false;
  const { verifier, calls } = fixture(() => json(revoked ? { active: false } : active()));
  const principal = await verifier.authenticate('Bearer some.token');
  assert.deepEqual(principal, { issuer, userId: 'person-a', connectionId: 'connection-a', clientId: 'dcr-public-client' });
  assert.ok(Object.isFrozen(principal));
  await verifier.verifyToken('some.token');
  revoked = true;
  await assert.rejects(verifier.verifyToken('some.token'), status(401));
  assert.equal(calls.filter(call => call.url === endpoint).length, 3);
  assert.equal(calls.filter(call => call.url.endsWith('openid-configuration')).length, 1);
  assert.equal(new URLSearchParams(calls[1].init.body).get('token'), 'some.token');
  assert.ok(calls.every(call => call.init.redirect === 'error'));
});

test('separate users and resources do not share cached acceptance', async () => {
  const { verifier } = fixture((_url, init) => json(active({ sub: new URLSearchParams(init.body).get('token') })));
  const [a, b] = await Promise.all([verifier.verifyToken('person-a'), verifier.verifyToken('person-b')]);
  assert.notEqual(a.userId, b.userId);
  const other = fixture(active(), { audience: 'https://lore.example' });
  await assert.rejects(other.verifier.verifyToken('token'), status(401));
});

test('introspection Basic credentials use OAuth form encoding', async () => {
  const { verifier, calls } = fixture(active(), { clientId: 'a :ü', clientSecret: "b+:/!'()" });
  await verifier.verifyToken('valid-token');
  assert.equal(Buffer.from(calls[1].init.headers.authorization.slice(6), 'base64').toString(), 'a+%3A%C3%BC:b%2B%3A%2F%21%27%28%29');
});

for (const [name, change] of Object.entries({
  inactive: { active: false }, 'missing approval': { gate_approved: undefined }, 'string approval': { gate_approved: 'true' }, 'foreign issuer': { iss: 'https://evil.example' }, 'missing subject': { sub: undefined },
  'missing connection': { connection_id: undefined }, 'expired token': { exp: clock / 1000 }, 'string expiry': { exp: '9999999999' },
  'missing client id': { client_id: undefined }, 'inconsistent client': { azp: 'other-app' }, 'empty authorized party': { azp: '' },
  'missing audience': { aud: undefined }, 'foreign audience': { aud: ['other'] }, 'malformed audience': { aud: [config.audience, 1] },
})) {
  test(`rejects ${name}`, async () => {
    await assert.rejects(fixture(active(change)).verifier.verifyToken('token'), status(401));
  });
}

test('accepts dynamic client IDs with consistent client_id and azp across audiences', async () => {
  const { verifier } = fixture(active({ client_id: 'new-dcr-client', azp: 'new-dcr-client', aud: ['other', config.audience] }));
  assert.equal((await verifier.verifyToken('token')).clientId, 'new-dcr-client');
});

test('accepts standard client_id when optional azp is absent', async () => {
  const { verifier } = fixture(active({ client_id: 'new-dcr-client', azp: undefined }));
  assert.equal((await verifier.verifyToken('token')).clientId, 'new-dcr-client');
});

test('malformed credentials fail before any network call', async () => {
  const { verifier, calls } = fixture();
  for (const token of ['', 'a b', 'a\nb', 'a\n', 'a=b', 'a'.repeat(16385)]) {
    await assert.rejects(verifier.verifyToken(token), status(401));
  }
  for (const header of [undefined, '', 'Basic foo', 'Bearer a b', 'Bearer  token', 'Bearer token\n', 'Bearer token, Bearer other']) {
    await assert.rejects(verifier.authenticate(header), status(401));
  }
  assert.equal(calls.length, 0);
});

for (const [name, response] of Object.entries({
  outage: () => json({}, { status: 503 }), 'bad credentials': () => json({}, { status: 401 }),
  'bad json': () => new Response('{', { headers: { 'content-type': 'application/json' } }),
  'bad media type': () => new Response('<html>error</html>'),
  'bad shape': () => json([]), 'missing active': () => json({}), 'wrong active type': () => json({ active: 'true' }),
  'oversized declared body': () => new Response('{}', { headers: { 'content-type': 'application/json', 'content-length': '65537' } }),
  'oversized streamed body': () => json({ text: 'x'.repeat(65537) }),
  redirect: () => new Response('', { status: 302, headers: { location: 'https://evil.example' } }),
})) {
  test(`fails closed with retryable status for ${name}`, async () => {
    await assert.rejects(fixture(response).verifier.verifyToken('token'), status(503));
  });
}

test('provider/network errors never disclose raw token, credentials or response body', async () => {
  const { verifier } = fixture(() => { throw new Error('secret raw-token private body'); });
  await assert.rejects(verifier.verifyToken('raw-token'), error => {
    assert.equal(error.status, 503);
    assert.equal(error.cause, undefined);
    assert.doesNotMatch(String(error), /secret|raw-token|private body/);
    return true;
  });
});

for (const [name, metadata] of Object.entries({
  'issuer mismatch': { issuer: 'https://other.example', introspection_endpoint: endpoint },
  'cross-origin endpoint': { issuer, introspection_endpoint: 'https://evil.example/introspect' },
  'credentials in endpoint': { issuer, introspection_endpoint: 'https://user:pass@gate.example/introspect' },
  'HTTP endpoint': { issuer, introspection_endpoint: 'http://gate.example/introspect' },
  'missing endpoint': { issuer },
})) {
  test(`rejects unsafe discovery ${name}`, async () => {
    let calls = 0;
    const verifier = createGateVerifier(config, { fetch: async () => { calls++; return json(metadata); } });
    await assert.rejects(verifier.verifyToken('token'), status(503));
    assert.equal(calls, 1);
  });
}

test('failed discovery is retryable and never caches invalid metadata', async () => {
  let first = true;
  const verifier = createGateVerifier(config, { now: () => clock, fetch: async url => {
    if (!url.endsWith('openid-configuration')) return json(active());
    if (first) { first = false; return json({ issuer: 'wrong' }); }
    return json({ issuer, introspection_endpoint: endpoint });
  } });
  await assert.rejects(verifier.verifyToken('token'), status(503));
  assert.equal((await verifier.verifyToken('token')).userId, 'person-a');
});

test('one deadline bounds discovery and introspection even for noncompliant fetch', async () => {
  const verifier = createGateVerifier({ ...config, timeoutMs: 15 }, { fetch: async () => new Promise(() => {}) });
  await assert.rejects(verifier.verifyToken('token'), status(503));
});

test('HTTPS configuration and explicit isolated loopback exception', () => {
  assert.throws(() => createGateVerifier({ ...config, browserClientId: undefined }));
  for (const issuer of ['http://gate.example', 'https://user:pass@gate.example', 'https://gate.example?x=1', 'https://gate.example/#x']) {
    assert.throws(() => createGateVerifier({ ...config, issuer }));
  }
  assert.throws(() => createGateVerifier({ ...config, issuer: 'http://10.0.0.1', allowLoopbackHttp: true }));
  assert.doesNotThrow(() => createGateVerifier({ ...config, issuer: 'http://127.0.0.1:8080/realm', allowLoopbackHttp: true }));
  const previous = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = 'production';
    assert.throws(() => createGateVerifier({ ...config, allowLoopbackHttp: true }));
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previous;
  }
});

test('resource metadata advertises bearer transport and issuer without feature scopes', () => {
  assert.deepEqual(protectedResourceMetadata(config.audience, issuer), {
    resource: config.audience, authorization_servers: [issuer], bearer_methods_supported: ['header'],
  });
  assert.throws(() => protectedResourceMetadata('http://resource.example', issuer));
});


test('a slow introspection cannot extend the combined discovery deadline', async () => {
  const verifier = createGateVerifier({ ...config, timeoutMs: 35 }, { fetch: async url => {
    if (url.endsWith('openid-configuration')) {
      await new Promise(resolve => setTimeout(resolve, 20));
      return json({ issuer, introspection_endpoint: endpoint });
    }
    await new Promise(resolve => setTimeout(resolve, 25));
    return json(active());
  }, now: () => clock });
  await assert.rejects(verifier.verifyToken('token'), status(503));
});

test('slow response bodies are bounded by the request deadline', async () => {
  let cancelled = false;
  const { verifier } = fixture(() => new Response(new ReadableStream({
    pull() { return new Promise(() => {}); },
    cancel() { cancelled = true; },
  }), { headers: { 'content-type': 'application/json' } }), { timeoutMs: 15 });
  await assert.rejects(verifier.verifyToken('token'), status(503));
  assert.equal(cancelled, true);
});

test('refresh tokens and browser session identifiers are not access credentials', async () => {
  for (const change of [{token_type:undefined},{token_type:'refresh_token'},{connection_id:undefined,sid:'browser-session'}]) {
    await assert.rejects(fixture(active(change)).verifier.verifyToken('token'), status(401));
  }
});

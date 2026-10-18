import type { JWK } from 'oidc-provider';
import { isIP } from 'node:net';
export interface Config {
  issuer: string; firestoreProjectId: string; firestoreDatabaseId: string; githubClientId: string; githubClientSecret: string; githubUserId: string;
  cookieKeys: string[]; jwks: {keys:JWK[]}; port: number;
  clients: {client_id:string; client_name:string; redirect_uris:string[]}[];
  resources: {audience:string; client_id:string; client_secret:string; browser_client_id:string}[];
  sessionCookieDomain: string;
  browserSessionTtlSeconds: number;
  browserApps: {app_id:string; app_name:string; redirect_uris:string[]}[];
  browserOrigins: readonly string[];
}

function dnsParent(value: string): string {
  if (!value || value.length>253 || value !== value.trim() || /[^\x00-\x7f]/u.test(value) || value.endsWith('.') || value.startsWith('.') || value.includes('*')) throw new Error('Invalid GATE_SESSION_COOKIE_DOMAIN');
  const domain = value.toLowerCase();
  const labels = domain.split('.');
  if (labels.length < 2 || isIP(domain) !== 0 || domain === 'localhost' || labels.some(label => label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))) throw new Error('Invalid GATE_SESSION_COOKIE_DOMAIN');
  return domain;
}

function httpsUrl(value: string, label: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(`Invalid ${label}`); }
  if (!value.startsWith('https://') || url.href !== value || url.protocol !== 'https:' || url.username || url.password || url.hash || value.includes('#') || /[^\x00-\x7f]/u.test(value)) throw new Error(`Invalid ${label}`);
  return url;
}

function underParent(hostname: string, parent: string): boolean {
  const host = hostname.toLowerCase();
  return host === parent || host.endsWith(`.${parent}`);
}

export function readConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const required = (name:string) => { const value=env[name]; if(!value) throw new Error(`Missing ${name}`); return value; };
  const issuer=required('GATE_ISSUER');
  const url=new URL(issuer);
  if(url.username||url.password||url.search||url.hash||url.pathname!=='/'||url.href.replace(/\/$/,'')!==issuer ||
    (url.protocol!=='https:'&&!(env.NODE_ENV!=='production'&&url.protocol==='http:'&&['127.0.0.1','localhost'].includes(url.hostname)))) throw new Error('Invalid GATE_ISSUER');
  const sessionCookieDomain = dnsParent(required('GATE_SESSION_COOKIE_DOMAIN'));
  if (url.protocol !== 'https:' || url.hostname === sessionCookieDomain || !underParent(url.hostname, sessionCookieDomain)) throw new Error('Gate issuer must be a HTTPS subdomain of GATE_SESSION_COOKIE_DOMAIN');
  const clients=JSON.parse(required('GATE_CLIENTS')) as Config['clients'];
  const resources=JSON.parse(required('GATE_RESOURCES')) as Config['resources'];
  const browserApps=JSON.parse(required('GATE_BROWSER_APPS')) as Config['browserApps'];
  if(!Array.isArray(clients)||!clients.length||!Array.isArray(resources)||!resources.length||!Array.isArray(browserApps)||!browserApps.length) throw new Error('Configure clients, resources, and browser apps');
  const ids=new Set<string>();
  for(const client of clients) {
    if(!client.client_id||ids.has(client.client_id)||!client.client_name||!Array.isArray(client.redirect_uris)||!client.redirect_uris.length) throw new Error('Invalid client');
    ids.add(client.client_id);
    for(const uri of client.redirect_uris) { const u=new URL(uri); if(uri.includes('*')||u.hash||u.username||u.password||(u.protocol!=='https:'&&!(u.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(u.hostname)))) throw new Error('Exact HTTPS or loopback redirect required'); }
  }
  const audiences=new Set<string>();
  const browserClientIds=new Set<string>();
  for(const r of resources) {
    let audience: URL;
    try { audience=new URL(r.audience); } catch { throw new Error('Invalid resource'); }
    if(audiences.has(r.audience)||audience.username||audience.password||audience.search||audience.hash||!r.client_id||ids.has(r.client_id)||typeof r.client_secret!=='string'||r.client_secret.length<32||audience.protocol!=='https:'||!underParent(audience.hostname,sessionCookieDomain)||!r.browser_client_id||typeof r.browser_client_id!=='string'||browserClientIds.has(r.browser_client_id)) throw new Error('Invalid resource');
    ids.add(r.client_id);audiences.add(r.audience);browserClientIds.add(r.browser_client_id);
  }
  const appIds=new Set<string>();
  const origins=new Set<string>();
  for(const app of browserApps) {
    if(!app||typeof app.app_id!=='string'||!app.app_id||appIds.has(app.app_id)||typeof app.app_name!=='string'||!app.app_name.trim()||!Array.isArray(app.redirect_uris)||!app.redirect_uris.length) throw new Error('Invalid browser app');
    appIds.add(app.app_id);
    for(const redirect of app.redirect_uris) {
      if(typeof redirect!=='string'||redirect.includes('*')) throw new Error('Invalid browser redirect');
      const target=httpsUrl(redirect,'browser redirect');
      if(!underParent(target.hostname,sessionCookieDomain)) throw new Error('Browser redirect must be an exact HTTPS URI under GATE_SESSION_COOKIE_DOMAIN');
      origins.add(target.origin);
    }
  }
  const browserTtlRaw=env.GATE_BROWSER_SESSION_TTL_SECONDS??'2592000';
  if(!/^(?:0|[1-9][0-9]*)$/u.test(browserTtlRaw)) throw new Error('Invalid GATE_BROWSER_SESSION_TTL_SECONDS');
  const browserSessionTtlSeconds=Number(browserTtlRaw);
  if(!Number.isSafeInteger(browserSessionTtlSeconds)||browserSessionTtlSeconds<3600||browserSessionTtlSeconds>2592000) throw new Error('Invalid GATE_BROWSER_SESSION_TTL_SECONDS');
  const cookieKeys=JSON.parse(required('GATE_COOKIE_KEYS')) as string[];
  if(!Array.isArray(cookieKeys)||!cookieKeys.length||cookieKeys.some(k=>typeof k!=='string'||k.length<32))throw new Error('Invalid cookie keys');
  const jwks=JSON.parse(required('GATE_JWKS')) as Config['jwks'];
  if(!jwks.keys?.length||jwks.keys.some(k=>!k.d)) throw new Error('Private signing JWKS required');
  const githubUserId=required('GATE_GITHUB_USER_ID'); if(!/^[1-9][0-9]*$/.test(githubUserId))throw new Error('GitHub immutable numeric user ID required');
  const port=Number(env.PORT??3000);if(!Number.isInteger(port)||port<1||port>65535)throw new Error('Invalid port');
  if(env.NODE_ENV==='production' && env.FIRESTORE_EMULATOR_HOST) throw new Error('Emulator forbidden in production');
  const firestoreProjectId=required('GATE_FIRESTORE_PROJECT_ID');
  const firestoreDatabaseId=required('GATE_FIRESTORE_DATABASE_ID');
  if(!/^[a-z][a-z0-9-]{4,61}[a-z0-9]$/.test(firestoreProjectId)||!(firestoreDatabaseId==='(default)'||/^[a-z][a-z0-9-]{2,61}[a-z0-9]$/.test(firestoreDatabaseId)))throw new Error('Invalid Firestore project or database');
  return {issuer,firestoreProjectId,firestoreDatabaseId,githubClientId:required('GATE_GITHUB_CLIENT_ID'),githubClientSecret:required('GATE_GITHUB_CLIENT_SECRET'),githubUserId,cookieKeys,jwks,clients,resources,sessionCookieDomain,browserSessionTtlSeconds,browserApps,browserOrigins:Object.freeze([...origins]),port};
}

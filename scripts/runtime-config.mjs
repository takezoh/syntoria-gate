import { readFile } from 'node:fs/promises';

function fail() { throw new Error('Invalid Gate runtime configuration'); }
function dnsParent(value) {
  if (typeof value !== 'string' || !value || value.length > 253 || value !== value.trim() || /[^\x00-\x7f]/u.test(value) || value.startsWith('.') || value.endsWith('.') || value.includes('*')) fail();
  const domain = value.toLowerCase();
  const labels = domain.split('.');
  if (labels.length < 2 || domain === 'localhost' || labels.some(label => label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))) fail();
  return domain;
}
function parseUrl(value, protocol, canonical = true) {
  if (typeof value !== 'string' || /[^\x00-\x7f]/u.test(value)) fail();
  let url;
  try { url = new URL(value); } catch { fail(); }
  if (url.protocol !== protocol || (canonical && url.href !== value) || url.username || url.password || url.hash || value.includes('#')) fail();
  return url;
}
function underParent(host, parent) { return host.toLowerCase() === parent || host.toLowerCase().endsWith(`.${parent}`); }
function exactString(value) { return typeof value === 'string' && value.trim() === value && value.length > 0; }
const RUNTIME_CONFIG_KEYS = new Set(['project', 'projectNumber', 'issuer', 'sessionCookieDomain', 'githubUserId', 'browserApps', 'browserSessionTtlSeconds']);

export function parseRuntimeConfig(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail();
  if (Object.keys(input).some(key => !RUNTIME_CONFIG_KEYS.has(key))) fail();
  const cookieDomain = dnsParent(input.sessionCookieDomain);
  const issuer = parseUrl(input.issuer, 'https:', false);
  if (issuer.search || issuer.pathname !== '/' || issuer.href.slice(0, -1) !== input.issuer || issuer.hostname === cookieDomain || !underParent(issuer.hostname, cookieDomain)) fail();
  if (typeof input.githubUserId !== 'string' || !/^[1-9][0-9]*$/u.test(input.githubUserId)) fail();
  // The GCP project stays out of tracked files; the template carries placeholders.
  if (typeof input.project !== 'string' || !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/u.test(input.project)) fail();
  if (typeof input.projectNumber !== 'string' || !/^[1-9][0-9]{5,19}$/u.test(input.projectNumber)) fail();

  if (!Array.isArray(input.browserApps) || input.browserApps.length === 0) fail();
  const appIds = new Set();
  const origins = new Set();
  for (const app of input.browserApps) {
    if (!app || !exactString(app.app_id) || appIds.has(app.app_id) || !exactString(app.app_name) || !Array.isArray(app.redirect_uris) || app.redirect_uris.length === 0) fail();
    appIds.add(app.app_id);
    for (const redirect of app.redirect_uris) {
      if (!exactString(redirect) || redirect.includes('*')) fail();
      const target = parseUrl(redirect, 'https:');
      if (!underParent(target.hostname, cookieDomain)) fail();
      origins.add(target.origin);
    }
  }
  const ttl = input.browserSessionTtlSeconds ?? 2_592_000;
  if (!Number.isSafeInteger(ttl) || ttl < 3600 || ttl > 2_592_000) fail();
  return {
    project: input.project,
    projectNumber: input.projectNumber,
    issuer: input.issuer,
    sessionCookieDomain: cookieDomain,
    githubUserId: input.githubUserId,
    browserApps: input.browserApps,
    browserSessionTtlSeconds: ttl,
    browserOrigins: Object.freeze([...origins]),
  };
}

export async function readRuntimeConfig(path) {
  let parsed;
  try { parsed = JSON.parse(await readFile(path, 'utf8')); } catch { fail(); }
  return parseRuntimeConfig(parsed);
}

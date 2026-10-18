import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseRuntimeConfig } from '../scripts/runtime-config.mjs';
import { renderService } from '../scripts/render-service.mjs';

const example = JSON.parse(await readFile(new URL('../infra/runtime-config.example.json', import.meta.url), 'utf8'));
const manifest = JSON.parse(await readFile(new URL('../infra/cloud-run/service.template.json', import.meta.url), 'utf8'));
const image = `registry.example.test/project/gate/service@sha256:${'a'.repeat(64)}`;

test('runtime configuration validates exact HTTPS issuer and browser redirects under the cookie parent', () => {
  const parsed = parseRuntimeConfig(example);
  assert.equal(parsed.issuer, 'https://gate.example.test');
  assert.equal(parsed.sessionCookieDomain, 'example.test');
  assert.equal(parsed.browserSessionTtlSeconds, 2592000);
  assert.deepEqual(parsed.browserOrigins, ['https://actions.example.test']);
  for (const change of [
    { sessionCookieDomain: '.example.test' },
    { sessionCookieDomain: 'localhost' },
    { issuer: 'https://example.test' },
    { issuer: 'https://gate.other.test' },
    { issuer: 'http://gate.example.test' },
    { browserSessionTtlSeconds: 3599 },
    { browserSessionTtlSeconds: 2592001 },
    { browserApps: [{ ...example.browserApps[0], redirect_uris: ['http://actions.example.test/return'] }] },
    { browserApps: [{ ...example.browserApps[0], redirect_uris: ['https:actions.example.test/return'] }] },
    { browserApps: [{ ...example.browserApps[0], redirect_uris: ['https://actions.example.test\\return'] }] },
    { browserApps: [{ ...example.browserApps[0], redirect_uris: ['https://other.test/return'] }] },
    { browserApps: [example.browserApps[0], example.browserApps[0]] },
  ]) assert.throws(() => parseRuntimeConfig({ ...example, ...change }));
});

test('renderer injects runtime URLs and registries without changing secret references', () => {
  const rendered = renderService(manifest, image, parseRuntimeConfig(example));
  const env = Object.fromEntries(rendered.spec.template.spec.containers[0].env.map(entry => [entry.name, entry]));
  assert.equal(rendered.spec.template.spec.containers[0].image, image);
  assert.equal(env.GATE_ISSUER.value, example.issuer);
  assert.equal(env.GATE_SESSION_COOKIE_DOMAIN.value, example.sessionCookieDomain);
  assert.equal(env.GATE_GITHUB_USER_ID.value, example.githubUserId);
  assert.deepEqual(JSON.parse(env.GATE_CLIENTS.value), example.clients);
  assert.deepEqual(JSON.parse(env.GATE_BROWSER_APPS.value), example.browserApps);
  assert.equal(env.GATE_RESOURCES.valueFrom.secretKeyRef.name, 'gate-resources');
  assert.equal(JSON.stringify(manifest).includes('GATE_ISSUER'), false);
  assert.throws(() => renderService(manifest, `registry.example.test/project/gate/service:latest`, parseRuntimeConfig(example)));
});

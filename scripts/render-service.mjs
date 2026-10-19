import { readFile, writeFile } from 'node:fs/promises';
import { resolve, relative, dirname, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readRuntimeConfig } from './runtime-config.mjs';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function validImageReference(image) {
  return typeof image === 'string' && /^[A-Za-z0-9.-]+(?::[0-9]+)?\/[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$/u.test(image);
}

export function renderService(manifest, image, runtimeConfig) {
  if (!validImageReference(image)) throw new Error('An immutable container image digest is required');
  const rendered = structuredClone(manifest);
  const container = rendered.spec?.template?.spec?.containers?.[0];
  if (!container || !Array.isArray(container.env)) throw new Error('Invalid Gate Cloud Run service template');
  container.image = image;
  const env = new Map(container.env.map(entry => [entry.name, entry]));
  const set = (name, value) => {
    const entry = env.get(name);
    if (entry) { delete entry.valueFrom; entry.value = value; }
    else { const added = { name, value }; container.env.push(added); env.set(name, added); }
  };
  set('GATE_ISSUER', runtimeConfig.issuer);
  set('GATE_SESSION_COOKIE_DOMAIN', runtimeConfig.sessionCookieDomain);
  set('GATE_GITHUB_USER_ID', runtimeConfig.githubUserId);
  set('GATE_BROWSER_APPS', JSON.stringify(runtimeConfig.browserApps));
  set('GATE_BROWSER_SESSION_TTL_SECONDS', String(runtimeConfig.browserSessionTtlSeconds));
  return rendered;
}

async function main(args) {
  const [image, runtimePath, outputPath] = args;
  if (!image || !runtimePath || !outputPath) throw new Error('Usage: node scripts/render-service.mjs <immutable-image-reference> <ignored-runtime-config.json> <output.json>');
  const resolvedOutput = resolve(outputPath);
  const fromRoot = relative(repositoryRoot, resolvedOutput);
  const insideRepository = fromRoot === '' || (fromRoot !== '..' && !fromRoot.startsWith(`..${sep}`));
  if (insideRepository && !fromRoot.startsWith(`.local${sep}`)) {
    throw new Error('Generated manifests inside the repository must be written under .local/');
  }
  const runtimeConfig = await readRuntimeConfig(runtimePath);
  const manifest = JSON.parse(await readFile(new URL('../infra/cloud-run/service.template.json', import.meta.url), 'utf8'));
  const rendered = renderService(manifest, image, runtimeConfig);
  await writeFile(resolvedOutput, `${JSON.stringify(rendered, null, 2)}\n`, { mode: 0o600 });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main(process.argv.slice(2));
}

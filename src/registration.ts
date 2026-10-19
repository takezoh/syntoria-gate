export const REGISTRATION_BODY_LIMIT = 8_192;
export const REGISTRATION_REDIRECT_LIMIT = 10;
const MAX_REDIRECT_LENGTH = 2_048;
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const FORBIDDEN_METADATA = new Set([
  'client_id',
  'client_secret',
  'client_secret_expires_at',
  'client_id_issued_at',
  'registration_access_token',
  'registration_client_uri',
]);
const REMOTE_METADATA = new Set(['jwks_uri', 'sector_identifier_uri', 'request_uris']);

export interface DcrClientMetadata {
  application_type: 'web' | 'native';
  client_name?: string;
  grant_types: ('authorization_code' | 'refresh_token')[];
  redirect_uris: string[];
  response_types: ['code'];
  token_endpoint_auth_method: 'none';
}

export class InvalidDcrMetadataError extends Error {
  constructor() {
    super('Invalid client metadata');
    this.name = 'InvalidDcrMetadataError';
  }
}

function invalid(): never {
  throw new InvalidDcrMetadataError();
}

function metadataArray(value: unknown, allowed: readonly string[]): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.some(item => typeof item !== 'string')) invalid();
  const values = value as string[];
  if (new Set(values).size !== values.length || values.some(item => !allowed.includes(item))) invalid();
  return values;
}

function redirectType(uri: string): 'web' | 'native' | undefined {
  if (!uri || uri.length > MAX_REDIRECT_LENGTH || uri.includes('*') || /[^\x21-\x7e]/u.test(uri)) return undefined;
  let url: URL;
  try { url = new URL(uri); } catch { return undefined; }
  if (url.href !== uri || url.username || url.password || url.hash || uri.includes('#')) return undefined;
  if (url.protocol === 'https:') return 'web';
  if (url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname)) return 'native';
  return undefined;
}

export function parseDcrMetadata(body: Uint8Array): DcrClientMetadata {
  if (body.byteLength === 0 || body.byteLength > REGISTRATION_BODY_LIMIT) invalid();
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)); } catch { invalid(); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || Object.getPrototypeOf(parsed) !== Object.prototype) invalid();
  const input = parsed as Record<string, unknown>;
  const keys = Object.keys(input);
  if (keys.some(key => FORBIDDEN_METADATA.has(key) || REMOTE_METADATA.has(key))) invalid();

  if (!Array.isArray(input.redirect_uris) || input.redirect_uris.length === 0 || input.redirect_uris.length > REGISTRATION_REDIRECT_LIMIT || input.redirect_uris.some(uri => typeof uri !== 'string')) invalid();
  const redirectUris = input.redirect_uris as string[];
  if (new Set(redirectUris).size !== redirectUris.length) invalid();
  const inferredTypes = redirectUris.map(redirectType);
  if (inferredTypes.some(type => type === undefined) || new Set(inferredTypes).size !== 1) invalid();
  const inferredType = inferredTypes[0]!;
  const applicationType = input.application_type === undefined ? inferredType : input.application_type;
  if (applicationType !== inferredType || (applicationType !== 'web' && applicationType !== 'native')) invalid();

  let clientName: string | undefined;
  if (input.client_name !== undefined) {
    if (typeof input.client_name !== 'string' || input.client_name.trim() !== input.client_name || input.client_name.length === 0 || input.client_name.length > 100 || /[\u0000-\u001f\u007f]/u.test(input.client_name)) invalid();
    clientName = input.client_name;
  }

  if (input.token_endpoint_auth_method !== undefined && input.token_endpoint_auth_method !== 'none') invalid();
  const grantTypes = input.grant_types === undefined
    ? ['authorization_code'] as ('authorization_code' | 'refresh_token')[]
    : metadataArray(input.grant_types, ['authorization_code', 'refresh_token']) as ('authorization_code' | 'refresh_token')[];
  if (!grantTypes.includes('authorization_code')) invalid();
  if (input.response_types !== undefined) {
    const responseTypes = metadataArray(input.response_types, ['code']);
    if (responseTypes.length !== 1) invalid();
  }

  return {
    application_type: applicationType,
    ...(clientName === undefined ? {} : { client_name: clientName }),
    grant_types: grantTypes,
    redirect_uris: redirectUris,
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  };
}

import process from 'node:process';
import { Buffer } from 'node:buffer';

/** Online authorization: accepted credentials are never cached across requests. */
export interface GatePrincipal {
  readonly issuer: string;
  readonly userId: string;
  readonly connectionId: string;
  readonly clientId: string;
  /** The client's unverified registration name for display, or null; it never identifies or authorizes. */
  readonly clientName?: string | null;
}

export interface GateSessionPrincipal extends GatePrincipal {
  readonly expiresAt: number;
  readonly csrfToken: string;
  readonly sessionType: 'browser';
}

export interface GateConfig {
  issuer: string;
  audience: string;
  clientId: string;
  clientSecret: string;
  browserClientId: string;
  timeoutMs?: number;
  /** For isolated local tests only; forbidden when NODE_ENV is production. */
  allowLoopbackHttp?: boolean;
}

export interface GateDependencies {
  fetch?: typeof globalThis.fetch;
  now?: () => number;
}

export class GateError extends Error {
  readonly status: 401 | 503;
  readonly code: 'invalid_token' | 'authorization_unavailable';
  constructor(status: 401 | 503) {
    super(status === 401 ? 'Invalid access token' : 'Connection authorization unavailable');
    this.name = 'GateError';
    this.status = status;
    this.code = status === 401 ? 'invalid_token' : 'authorization_unavailable';
  }
}

const MAX_RESPONSE_BYTES = 65_536;
const MAX_TOKEN_LENGTH = 16_384;
const SESSION_SECRET = /^[A-Za-z0-9_-]{43}$/u;
const bearerToken = /^[A-Za-z0-9\-._~+/]+=*(?![\s\S])/;
const nonempty = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= 4096 && !/[\u0000-\u001f\u007f]/u.test(value);
const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
/** The registration rule for `client_name`; anything else is treated as absent. */
const displayName = (value: unknown): string | null =>
  typeof value === 'string' && value.length > 0 && value.length <= 100 && value.trim() === value && !/[\u0000-\u001f\u007f]/u.test(value) ? value : null;

function safeUrl(value: string, allowHttp: boolean): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new TypeError('Invalid Gate endpoint URL'); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password || url.hash || url.search ||
      (url.protocol !== 'https:' && !(allowHttp && loopback && url.protocol === 'http:'))) {
    throw new TypeError('Gate endpoints require HTTPS without credentials, query or fragment');
  }
  return url;
}

function formEncode(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`).replace(/%20/g, '+');
}

async function readJson(response: Response, signal: AbortSignal): Promise<Record<string, unknown>> {
  const type = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (type !== 'application/json') throw new GateError(503);
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > MAX_RESPONSE_BYTES)) {
    await response.body?.cancel();
    throw new GateError(503);
  }
  if (!response.body) throw new GateError(503);
  const reader = response.body.getReader();
  const abortReader = () => { void reader.cancel().catch(() => undefined); };
  signal.addEventListener('abort', abortReader, { once: true });
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      signal.throwIfAborted();
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) throw new GateError(503);
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!object(parsed)) throw new GateError(503);
    return parsed;
  } finally {
    signal.removeEventListener('abort', abortReader);
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

/** The clock dependency returns Unix epoch milliseconds, like Date.now. */
export function createGateVerifier(config: GateConfig, dependencies: GateDependencies = {}) {
  if (config.allowLoopbackHttp && process.env.NODE_ENV === 'production') {
    throw new TypeError('Loopback HTTP is forbidden in production');
  }
  const allowHttp = config.allowLoopbackHttp === true;
  const issuer = config.issuer;
  const issuerUrl = safeUrl(issuer, allowHttp);
  if (![config.audience, config.clientId, config.clientSecret, config.browserClientId].every(nonempty)) throw new TypeError('Invalid Gate verifier configuration');
  const timeoutMs = config.timeoutMs ?? 3000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) throw new TypeError('Invalid Gate timeout');
  const audience = config.audience;
  const authorization = `Basic ${Buffer.from(`${formEncode(config.clientId)}:${formEncode(config.clientSecret)}`, 'utf8').toString('base64')}`;
  const fetcher = dependencies.fetch ?? globalThis.fetch;
  const now = dependencies.now ?? Date.now;
  let introspectionEndpoint: string | undefined;

  async function request(url: string, options: RequestInit, signal: AbortSignal) {
    const response = await fetcher(url, { ...options, signal, redirect: 'error' });
    if (!response.ok || response.redirected || (response.url && response.url !== url)) {
      await response.body?.cancel();
      throw new GateError(503);
    }
    return readJson(response, signal);
  }

  async function discover(signal: AbortSignal) {
    if (introspectionEndpoint) return introspectionEndpoint;
    const metadata = await request(`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`,
      { headers: { accept: 'application/json' } }, signal);
    if (metadata.issuer !== issuer || !nonempty(metadata.introspection_endpoint)) throw new GateError(503);
    let endpoint: URL;
    try { endpoint = safeUrl(metadata.introspection_endpoint, allowHttp); }
    catch { throw new GateError(503); }
    if (endpoint.origin !== issuerUrl.origin) throw new GateError(503);
    introspectionEndpoint = endpoint.href;
    return introspectionEndpoint;
  }

  async function verifyToken(token: string): Promise<GatePrincipal> {
    if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LENGTH || !bearerToken.test(token)) {
      throw new GateError(401);
    }
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => { controller.abort(); reject(new GateError(503)); }, timeoutMs);
    });
    async function authorize() {
      const endpoint = await discover(controller.signal);
      const data = await request(endpoint, {
        method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded', authorization },
        body: new URLSearchParams({ token, token_type_hint: 'access_token' }).toString(),
      }, controller.signal);
      if (typeof data.active !== 'boolean') throw new GateError(503);
      if (!data.active) throw new GateError(401);
      const clientId = data.client_id;
      const authorizedParty = data.azp;
      if (data.token_type !== 'Bearer' || data.gate_approved !== true || data.iss !== issuer || !nonempty(data.sub) || !nonempty(data.connection_id) ||
          !Number.isSafeInteger(data.exp) || (data.exp as number) <= now() / 1000 ||
          !nonempty(clientId) || (authorizedParty !== undefined && (!nonempty(authorizedParty) || clientId !== authorizedParty))) throw new GateError(401);
      const audiences = typeof data.aud === 'string' ? [data.aud] : data.aud;
      if (!Array.isArray(audiences) || audiences.length === 0 || !audiences.every(nonempty) || !audiences.includes(audience)) {
        throw new GateError(401);
      }
      // An absent or malformed display name never affects authorization.
      const clientName = displayName(data.client_name);
      return Object.freeze({ issuer, userId: data.sub, connectionId: data.connection_id, clientId, clientName });
    }
    try { return await Promise.race([authorize(), timeout]); }
    catch (error) { throw error instanceof GateError ? error : new GateError(503); }
    finally { clearTimeout(timer); controller.abort(); }
  }

  async function authenticate(header: string | undefined | null): Promise<GatePrincipal> {
    if (typeof header !== 'string') throw new GateError(401);
    const match = /^Bearer ([A-Za-z0-9\-._~+/]+=*)(?![\s\S])/i.exec(header);
    if (!match) throw new GateError(401);
    return verifyToken(match[1]!);
  }

  async function verifySession(session: string): Promise<GateSessionPrincipal> {
    if (typeof session !== 'string' || !SESSION_SECRET.test(session) || Buffer.from(session, 'base64url').length !== 32 || Buffer.from(session, 'base64url').toString('base64url') !== session) throw new GateError(401);
    const url = `${issuer.replace(/\/$/u, '')}/browser/session/introspect`;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => { controller.abort(); reject(new GateError(503)); }, timeoutMs);
    });
    async function authorize() {
      const data = await request(url, {
        method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json', authorization },
        body: JSON.stringify({ session, resource: audience }),
      }, controller.signal);
      if (typeof data.active !== 'boolean') throw new GateError(503);
      if (!data.active) throw new GateError(401);
      if (data.iss !== issuer || data.aud !== audience || !nonempty(data.sub) || !nonempty(data.connection_id) ||
          !nonempty(data.client_id) || data.client_id !== config.browserClientId || data.gate_approved !== true ||
          data.session_type !== 'browser' || !nonempty(data.csrf_token) || !Number.isSafeInteger(data.exp) || (data.exp as number) <= now() / 1000) {
        throw new GateError(401);
      }
      return Object.freeze({ issuer, userId: data.sub, connectionId: data.connection_id, clientId: data.client_id, expiresAt: data.exp as number, csrfToken: data.csrf_token, sessionType: 'browser' as const });
    }
    try { return await Promise.race([authorize(), timeout]); }
    catch (error) { throw error instanceof GateError ? error : new GateError(503); }
    finally { clearTimeout(timer); controller.abort(); }
  }

  return Object.freeze({ verifyToken, authenticate, verifySession });
}

export interface GateConfirmationConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  timeoutMs?: number;
  /** For isolated local tests only; forbidden when NODE_ENV is production. */
  allowLoopbackHttp?: boolean;
}

export interface GateConfirmationSummary {
  readonly title: string;
  readonly lines: readonly string[];
}

export interface GateConfirmationRequest {
  readonly subject: string;
  readonly connectionId: string;
  readonly reference: string;
  readonly changeHash: string;
  readonly summary: GateConfirmationSummary;
}

export interface GateConfirmation {
  readonly id: string;
  readonly url: string;
}

export type GateConsumeResult =
  | { readonly status: 'consumed'; readonly subject: string; readonly connectionId: string; readonly decidedAt: number }
  | { readonly status: 'pending' | 'denied' | 'used' | 'expired' };

const CONFIRMATION_ID = /^[A-Za-z0-9_-]{43}$/u;
const WAITING_STATUSES = new Set(['pending', 'denied', 'used', 'expired']);

/**
 * Creates, consumes and cancels change confirmations with the resource's own credentials.
 * A requesting connection that is no longer active surfaces as 401; every other failure as 503.
 */
export function createGateConfirmations(config: GateConfirmationConfig, dependencies: GateDependencies = {}) {
  if (config.allowLoopbackHttp && process.env.NODE_ENV === 'production') {
    throw new TypeError('Loopback HTTP is forbidden in production');
  }
  safeUrl(config.issuer, config.allowLoopbackHttp === true);
  if (![config.clientId, config.clientSecret].every(nonempty)) throw new TypeError('Invalid Gate confirmation configuration');
  const timeoutMs = config.timeoutMs ?? 3000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) throw new TypeError('Invalid Gate timeout');
  const issuer = config.issuer.replace(/\/$/u, '');
  const authorization = `Basic ${Buffer.from(`${formEncode(config.clientId)}:${formEncode(config.clientSecret)}`, 'utf8').toString('base64')}`;
  const fetcher = dependencies.fetch ?? globalThis.fetch;

  async function call(path: string, body: Record<string, unknown>, expected: 200 | 201 | 204): Promise<Record<string, unknown>> {
    const url = `${issuer}${path}`;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => { controller.abort(); reject(new GateError(503)); }, timeoutMs);
    });
    async function send() {
      const response = await fetcher(url, {
        method: 'POST', redirect: 'error', signal: controller.signal,
        headers: { accept: 'application/json', 'content-type': 'application/json', authorization },
        body: JSON.stringify(body),
      });
      const unexpected = response.redirected || (response.url && response.url !== url) || response.status !== expected;
      if (unexpected || expected === 204) {
        await response.body?.cancel();
        if (unexpected) throw new GateError(response.status === 403 ? 401 : 503);
        return {};
      }
      return readJson(response, controller.signal);
    }
    try { return await Promise.race([send(), timeout]); }
    catch (error) { throw error instanceof GateError ? error : new GateError(503); }
    finally { clearTimeout(timer); controller.abort(); }
  }

  async function create(request: GateConfirmationRequest): Promise<GateConfirmation> {
    const data = await call('/confirmations', {
      subject: request.subject,
      connection_id: request.connectionId,
      reference: request.reference,
      change_hash: request.changeHash,
      summary: { title: request.summary.title, lines: [...request.summary.lines] },
    }, 201);
    const id = data.id;
    if (typeof id !== 'string' || !CONFIRMATION_ID.test(id) || data.url !== `${issuer}/confirm?id=${id}`) throw new GateError(503);
    return Object.freeze({ id, url: data.url });
  }

  async function consume(id: string, reference: string, changeHash: string): Promise<GateConsumeResult> {
    const data = await call('/confirmations/consume', { id, reference, change_hash: changeHash }, 200);
    if (data.status === 'consumed') {
      if (!nonempty(data.subject) || !nonempty(data.connection_id) || !Number.isSafeInteger(data.decided_at)) throw new GateError(503);
      return Object.freeze({ status: 'consumed' as const, subject: data.subject, connectionId: data.connection_id, decidedAt: data.decided_at as number });
    }
    if (typeof data.status !== 'string' || !WAITING_STATUSES.has(data.status)) throw new GateError(503);
    return Object.freeze({ status: data.status as 'pending' | 'denied' | 'used' | 'expired' });
  }

  async function cancel(id: string, reference: string): Promise<void> {
    await call('/confirmations/cancel', { id, reference }, 204);
  }

  return Object.freeze({ create, consume, cancel });
}

export function protectedResourceMetadata(resource: string, issuer: string) {
  safeUrl(resource, false);
  safeUrl(issuer, false);
  return Object.freeze({ resource, authorization_servers: Object.freeze([issuer]), bearer_methods_supported: Object.freeze(['header']) });
}

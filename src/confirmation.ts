export const CONFIRMATION_BODY_LIMIT = 16_384;
export const SUMMARY_TITLE_LIMIT = 120;
export const SUMMARY_LINE_LIMIT = 64;
export const SUMMARY_CHARACTER_LIMIT = 4_000;

export interface ConfirmationSummary {
  title: string;
  lines: string[];
}

export interface ConfirmationRequest {
  subject: string;
  connection_id: string;
  reference: string;
  change_hash: string;
  summary: ConfirmationSummary;
}

export interface ConsumeRequest {
  id: string;
  reference: string;
  change_hash: string;
}

export interface CancelRequest {
  id: string;
  reference: string;
}

export class InvalidConfirmationError extends Error {
  constructor() {
    super('Invalid confirmation request');
    this.name = 'InvalidConfirmationError';
  }
}

function invalid(): never {
  throw new InvalidConfirmationError();
}

const CONTROL = /[\u0000-\u001f\u007f]/u;
const CONFIRMATION_ID = /^[A-Za-z0-9_-]{43}$/u;
const REFERENCE = /^[\x21-\x7e]{1,128}$/u;
const CHANGE_HASH = /^sha256:[0-9a-f]{64}$/u;

function exactKeys(value: Record<string, unknown>, keys: readonly string[]) {
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some(key => !keys.includes(key))) invalid();
}

function text(value: unknown, max: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max || CONTROL.test(value) || value.trim() !== value) invalid();
  return value;
}

function summary(value: unknown): ConfirmationSummary {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) invalid();
  const input = value as Record<string, unknown>;
  exactKeys(input, ['title', 'lines']);
  const title = text(input.title, SUMMARY_TITLE_LIMIT);
  if (!Array.isArray(input.lines) || input.lines.length === 0 || input.lines.length > SUMMARY_LINE_LIMIT) invalid();
  const lines = input.lines.map(line => text(line, SUMMARY_CHARACTER_LIMIT));
  // A summary that does not fit is rejected, never truncated: the person must see every line.
  if (lines.reduce((total, line) => total + line.length, title.length) > SUMMARY_CHARACTER_LIMIT) invalid();
  return { title, lines };
}

export function isConfirmationId(value: unknown): value is string {
  return typeof value === 'string' && CONFIRMATION_ID.test(value);
}

export function parseConfirmationRequest(input: Record<string, unknown>): ConfirmationRequest {
  exactKeys(input, ['subject', 'connection_id', 'reference', 'change_hash', 'summary']);
  if (typeof input.reference !== 'string' || !REFERENCE.test(input.reference)) invalid();
  if (typeof input.change_hash !== 'string' || !CHANGE_HASH.test(input.change_hash)) invalid();
  return {
    subject: text(input.subject, 256),
    connection_id: text(input.connection_id, 512),
    reference: input.reference,
    change_hash: input.change_hash,
    summary: summary(input.summary),
  };
}

export function parseConsumeRequest(input: Record<string, unknown>): ConsumeRequest {
  exactKeys(input, ['id', 'reference', 'change_hash']);
  if (!isConfirmationId(input.id) || typeof input.reference !== 'string' || !REFERENCE.test(input.reference) ||
      typeof input.change_hash !== 'string' || !CHANGE_HASH.test(input.change_hash)) invalid();
  return { id: input.id, reference: input.reference, change_hash: input.change_hash };
}

export function parseCancelRequest(input: Record<string, unknown>): CancelRequest {
  exactKeys(input, ['id', 'reference']);
  if (!isConfirmationId(input.id) || typeof input.reference !== 'string' || !REFERENCE.test(input.reference)) invalid();
  return { id: input.id, reference: input.reference };
}

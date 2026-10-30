export const CONNECTION_CHECK_BODY_LIMIT = 2_048;

/** A resource asks whether one exact OAuth connection of the account still authorizes it. */
export interface ConnectionCheckRequest {
  subject: string;
  connection_id: string;
  client_id: string;
}

export class InvalidConnectionCheckError extends Error {
  constructor() {
    super('Invalid connection check request');
    this.name = 'InvalidConnectionCheckError';
  }
}

function field(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512 || value.trim() !== value || /[\u0000-\u001f\u007f]/u.test(value)) throw new InvalidConnectionCheckError();
  return value;
}

export function parseConnectionCheckRequest(value: unknown): ConnectionCheckRequest {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new InvalidConnectionCheckError();
  const input = value as Record<string, unknown>;
  const keys = Object.keys(input).sort();
  if (keys.join(',') !== 'client_id,connection_id,subject') throw new InvalidConnectionCheckError();
  return { subject: field(input.subject), connection_id: field(input.connection_id), client_id: field(input.client_id) };
}

import { z } from 'zod';
import { JsonValueSchema, type JsonObject } from '@almadar/core';

const ClaimsSchema = z.record(JsonValueSchema);

/** A verified token payload as typed JSON; `undefined` slots are dropped. */
export function claimsOf(payload: object): JsonObject {
  return ClaimsSchema.parse(JSON.parse(JSON.stringify(payload)));
}

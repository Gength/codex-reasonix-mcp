import { z } from 'zod';

import { EFFECTIVE_REASONING_EFFORTS } from './types.js';

export const REASONIX_STATUS_METHOD = '_reasonix.io/session/status';
export const REASONIX_STATUS_UPDATE_METHOD = '_reasonix.io/session/status_update';
export const REASONIX_STEER_METHOD = '_reasonix.io/session/steer';
export const REASONIX_STATUS_SCHEMA_VERSION = 1;

const usageSchema = z
  .object({
    promptTokens: z.number().int().nonnegative(),
    completionTokens: z.number().int().nonnegative(),
    // Reasonix >= 1.38 reports the aggregate token count in ACP status.
    // UsageTotals intentionally keeps its existing canonical fields only.
    totalTokens: z.number().int().nonnegative().optional(),
    reasoningTokens: z.number().int().nonnegative(),
    cacheHitTokens: z.number().int().nonnegative(),
    cacheMissTokens: z.number().int().nonnegative(),
    cacheHitRatio: z.number().min(0).max(1).nullable(),
    estimatedCost: z.number().nonnegative().nullable(),
    currency: z.string().nullable(),
    usageSource: z.string().min(1),
    // Reasonix >= 1.19.4 marks each turn/cumulative usage total as estimated.
    // This compatibility-only metadata is projected out before persistence.
    estimated: z.boolean().optional(),
  })
  // Reasonix may add provider/cache telemetry without changing the bridge's
  // canonical UsageTotals fields. Preserve known fields and ignore additions.
  .passthrough();

export const reasonixStatusSchema = z
  .object({
    schemaVersion: z.literal(REASONIX_STATUS_SCHEMA_VERSION),
    sequence: z.number().int().nonnegative(),
    sessionId: z.string().min(1),
    state: z.enum(['running', 'idle']),
    model: z.string().min(1),
    effort: z.enum(EFFECTIVE_REASONING_EFFORTS),
    mode: z.enum(['normal', 'plan', 'goal']),
    workMode: z.enum(['economy', 'balanced', 'delivery']),
    plannerMode: z.enum(['off', 'on']),
    goal: z
      .object({
        status: z.enum(['none', 'running', 'complete', 'blocked', 'failed', 'cancelled']),
        objective: z.string().optional(),
      })
      // Reasonix 1.38 adds goal progress telemetry without bumping the vendor
      // status schema version. Preserve known safety fields and ignore extras.
      .passthrough(),
    phase: z.string().min(1),
    turnOutcome: z
      .object({
        kind: z.enum(['none', 'completed', 'paused', 'cancelled', 'error']),
        reason: z.string().optional(),
      })
      .strict(),
    finalReadiness: z
      .object({
        readyForReview: z.boolean(),
        summary: z.string(),
        risks: z.array(z.string()),
      })
      .strict(),
    sandbox: z
      .object({
        mode: z.enum(['off', 'enforce']),
        engine: z.enum(['none', 'bubblewrap', 'seatbelt']),
        available: z.boolean(),
        workspaceRoot: z.string().min(1),
        writeRoots: z.array(z.string()),
        networkEnabled: z.boolean(),
      })
      .strict(),
    usage: z.object({ turn: usageSchema, cumulative: usageSchema }).strict(),
  })
  .strict();

export type ReasonixStatus = z.infer<typeof reasonixStatusSchema>;

export const reasonixStatusUpdateSchema = z
  .object({
    schemaVersion: z.literal(REASONIX_STATUS_SCHEMA_VERSION),
    sequence: z.number().int().nonnegative(),
    sessionId: z.string().min(1),
    event: z.enum(['phase', 'usage', 'pause', 'completion', 'error']),
    status: reasonixStatusSchema,
  })
  .strict();

export type ReasonixStatusUpdate = z.infer<typeof reasonixStatusUpdateSchema>;

export function assertReasonixStatusCapability(meta: unknown): void {
  if (!meta || typeof meta !== 'object')
    throw new Error('Reasonix status capability metadata missing');
  const capabilities = meta as Record<string, unknown>;
  for (const name of [REASONIX_STATUS_METHOD, REASONIX_STATUS_UPDATE_METHOD]) {
    const value = capabilities[name];
    if (
      !value ||
      typeof value !== 'object' ||
      (value as Record<string, unknown>).schemaVersion !== REASONIX_STATUS_SCHEMA_VERSION
    ) {
      throw new Error(`Required Reasonix ACP extension unavailable: ${name} schemaVersion 1`);
    }
  }
}

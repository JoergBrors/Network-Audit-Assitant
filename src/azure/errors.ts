import { isRestError } from "@azure/core-rest-pipeline";
import type { WarningReason } from "../models/discovery.js";
import { ReadOnlyViolationError } from "./http/readOnlyGuardPolicy.js";

export interface ClassifiedError {
  reason: WarningReason;
  statusCode?: number;
  code?: string;
  message: string;
  /** The request scope (subscription set) is the problem; splitting it may isolate the failing part. */
  scopeRelated: boolean;
  payloadTooLarge: boolean;
}

const AUTH_CODES =
  /authorization|forbidden|insufficient|invalidauthenticationtoken|subscriptionnotfound|disabled/i;

export function classifyAzureError(error: unknown): ClassifiedError {
  if (error instanceof ReadOnlyViolationError) {
    // Programming error, never retried or hidden.
    throw error;
  }
  const message = error instanceof Error ? error.message : String(error);
  if (isRestError(error)) {
    const statusCode = error.statusCode;
    const code = error.code;
    const payloadTooLarge =
      statusCode === 413 || /payload.*too large|response.*too large|toolarge/i.test(`${code} ${message}`);
    if (statusCode === 401 || statusCode === 403 || AUTH_CODES.test(code ?? "")) {
      return {
        reason: "InsufficientPermissions",
        ...(statusCode ? { statusCode } : {}),
        ...(code ? { code } : {}),
        message,
        scopeRelated: true,
        payloadTooLarge,
      };
    }
    if (statusCode === 404) {
      return {
        reason: "NotFound",
        statusCode,
        ...(code ? { code } : {}),
        message,
        scopeRelated: false,
        payloadTooLarge,
      };
    }
    if (statusCode === 429) {
      return {
        reason: "Throttled",
        statusCode,
        ...(code ? { code } : {}),
        message,
        scopeRelated: false,
        payloadTooLarge,
      };
    }
    const scopeRelated = statusCode === 400 && /subscription/i.test(`${code} ${message}`);
    return {
      reason: "Error",
      ...(statusCode ? { statusCode } : {}),
      ...(code ? { code } : {}),
      message,
      scopeRelated,
      payloadTooLarge,
    };
  }
  return { reason: "Error", message, scopeRelated: false, payloadTooLarge: false };
}

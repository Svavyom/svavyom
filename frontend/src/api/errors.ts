// Typed error and operation-state presentation (M0-E02-S06 r5 section 6), bound to the M0-E01-S01 contracts.
// Unit tests fail if a contract category or operation status lacks a mapping here.
import errorsContract from "../../../contracts/interfaces/errors.json";
import inventory from "../../../contracts/interfaces/inventory.json";
import resources from "../../../contracts/interfaces/resources.json";

export type ErrorCategory = keyof typeof errorsContract.categories;

export interface ErrorPresentation {
  title: string;
  recovery: string;
}

/** User-facing text per category. Server messages are never shown; only this text and a correlation id. */
export const ERROR_PRESENTATION: Record<ErrorCategory, ErrorPresentation> = {
  validation: { title: "Some details need attention", recovery: "Correct the highlighted fields and submit again." },
  unauthenticated: { title: "Sign in required", recovery: "Your session is missing or has expired. Sign in again to continue." },
  forbidden: { title: "You are not allowed to do this", recovery: "This action is not permitted for your account. Go back to the previous view." },
  not_found: { title: "Not found", recovery: "It may have been deleted or you may not have access. Return to the list." },
  conflict: { title: "Changed by someone else", recovery: "The resource changed since you loaded it. Reload it and review before trying again." },
  rate_limited: { title: "Too many requests", recovery: "Wait a moment, then try again." },
  prohibited: { title: "This request is not allowed", recovery: "The product never performs this kind of action. Choose a different action." },
  unavailable: { title: "Service temporarily unavailable", recovery: "A dependency is not responding. Try again shortly." },
  timeout: { title: "The outcome is unknown", recovery: "The request did not finish in time. Check the status before doing anything again." },
  host_error: { title: "The host reported a failure", recovery: "Review the operation details. The request was not completed." },
  internal: { title: "Something went wrong", recovery: "Try again later. If it persists, report the correlation id below." },
};

export const KNOWN_CATEGORIES = Object.keys(errorsContract.categories) as ErrorCategory[];
/** Categories the browser-api boundary can return (inventory.json); journeys list only these. */
export const BOUNDARY_CATEGORIES = inventory.boundaries["browser-api"].error_categories as ErrorCategory[];

export function isRetryable(category: ErrorCategory): boolean {
  return Boolean(errorsContract.categories[category].retryable);
}

/** Unknown or out-of-boundary categories render as `internal` (r5 section 6, defensive mapping). */
export function normaliseCategory(value: unknown): ErrorCategory {
  return typeof value === "string" && (BOUNDARY_CATEGORIES as string[]).includes(value) ? (value as ErrorCategory) : "internal";
}

export type OperationStatus = keyof typeof resources.operation_status;

export const OPERATION_STATUS_LABEL: Record<OperationStatus, string> = {
  pending: "Pending",
  running: "Running",
  retryable_failure: "Failed, will be retried",
  succeeded: "Succeeded",
  failed: "Failed",
  cancelled: "Cancelled",
};

export const OPERATION_STATUSES = Object.keys(resources.operation_status) as OperationStatus[];

export function operationFlags(status: OperationStatus): { terminal: boolean; retryable: boolean } {
  const s = resources.operation_status[status];
  return { terminal: s.terminal, retryable: s.retryable };
}

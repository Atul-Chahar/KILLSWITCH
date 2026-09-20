// Utilities for redacting sensitive AWS access keys and identifiers for display in the UI.
// Preserves underlying values for protocol tokens, signatures, and API calls.

const AWS_ACCESS_KEY_PATTERN = /^A[A-Z0-9]{19}$/;
const AWS_ACCOUNT_ID_PATTERN = /^\d{12}$/;
const DEFAULT_MASK = "••••••••";

/**
 * Masks an AWS access key ID (e.g. AKIAIOSFODNN7EXAMPLE -> AKIA••••••••EXAMPLE).
 * Keeps the 4-character prefix and meaningful suffix while redacting the middle secret segment.
 */
export function maskAccessKey(accessKeyId: string, mask: string = DEFAULT_MASK): string {
  if (accessKeyId.length < 12) {
    return accessKeyId;
  }
  const suffixLength = accessKeyId.endsWith("EXAMPLE") ? 7 : 4;
  const prefix = accessKeyId.slice(0, 4);
  const suffix = accessKeyId.slice(-suffixLength);
  return `${prefix}${mask}${suffix}`;
}

/**
 * Masks an incident identifier carrying an embedded access key (e.g. inc-AKIA... -> inc-AKIA••••••••EXAMPLE).
 */
export function maskIncidentId(incidentId: string, mask: string = DEFAULT_MASK): string {
  if (incidentId.startsWith("inc-")) {
    const rawKey = incidentId.slice(4);
    return `inc-${maskAccessKey(rawKey, mask)}`;
  }
  return incidentId;
}

/**
 * Masks a 12-digit AWS account ID (e.g. 123456789012 -> ****9012), matching shared/guards.py.
 */
export function maskAccountId(accountId: string): string {
  if (accountId.length < 4) {
    return "****";
  }
  return `****${accountId.slice(-4)}`;
}

/**
 * Context-aware helper to redact sensitive credentials or identifiers while preserving non-sensitive targets.
 */
export function maskCredential(value: string, mask: string = DEFAULT_MASK): string {
  if (AWS_ACCESS_KEY_PATTERN.test(value)) {
    return maskAccessKey(value, mask);
  }
  if (value.startsWith("inc-") && AWS_ACCESS_KEY_PATTERN.test(value.slice(4))) {
    return maskIncidentId(value, mask);
  }
  if (AWS_ACCOUNT_ID_PATTERN.test(value)) {
    return maskAccountId(value);
  }
  return value;
}

/**
 * Formats an action signature (action_type:target:region) for safe UI display by masking credential targets.
 */
export function maskActionSignature(signature: string, mask: string = DEFAULT_MASK): string {
  const parts = signature.split(":");
  if (parts.length >= 2) {
    const actionType = parts[0];
    const target = parts[1];
    if (actionType !== undefined && target !== undefined) {
      const rest = parts.slice(2);
      const maskedTarget = maskCredential(target, mask);
      return [actionType, maskedTarget, ...rest].join(":");
    }
  }
  return signature;
}

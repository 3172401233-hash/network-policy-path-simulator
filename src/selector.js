import { SimulationError, ERROR_CODES } from "./errors.js";

/**
 * A label selector as used inside NetworkPolicy objects.
 *
 * @typedef {Object} LabelSelector
 * @property {Object<string, string>} [matchLabels]
 * @property {Array<{key: string, operator: string, values?: string[]}>} [matchExpressions]
 */

/**
 * Evaluate a Kubernetes label selector against a label map.
 *
 * Semantics:
 * - null/undefined selector (field omitted) means "select everything".
 * - an explicitly empty object {} means "select everything" as well.
 * - all matchLabels entries and all matchExpressions must hold (logical AND).
 *
 * @param {LabelSelector | null | undefined} selector
 * @param {Object<string, string>} labels
 * @returns {boolean}
 */
export function matchesLabels(selector, labels) {
  if (selector === null || selector === undefined) {
    return true;
  }
  if (typeof selector !== "object") {
    throw new SimulationError(
      ERROR_CODES.INVALID_SELECTOR,
      `Label selector must be an object, got ${typeof selector}`,
    );
  }

  const targetLabels = labels ?? {};

  for (const [key, value] of Object.entries(selector.matchLabels ?? {})) {
    if (!Object.hasOwn(targetLabels, key) || targetLabels[key] !== value) {
      return false;
    }
  }

  for (const expression of selector.matchExpressions ?? []) {
    if (!evaluateExpression(expression, targetLabels)) {
      return false;
    }
  }
  return true;
}

function evaluateExpression(expression, labels) {
  const { key, operator, values } = expression;
  if (typeof key !== "string" || key.length === 0) {
    throw new SimulationError(
      ERROR_CODES.INVALID_SELECTOR,
      "matchExpressions entry requires a non-empty key",
      { expression },
    );
  }
  const exists = Object.hasOwn(labels, key);
  const value = labels[key];

  switch (operator) {
    case "In":
      return exists && Array.isArray(values) && values.includes(value);
    case "NotIn":
      return !exists || !values.includes(value);
    case "Exists":
      return exists;
    case "DoesNotExist":
      return !exists;
    default:
      throw new SimulationError(
        ERROR_CODES.INVALID_SELECTOR,
        `Unsupported label selector operator: ${String(operator)}`,
        { expression },
      );
  }
}

/**
 * Error codes used to distinguish a topology/configuration problem from a
 * policy-driven (legitimate) traffic denial.
 *
 * A simulation that throws or reports one of these codes did not fail because
 * a NetworkPolicy denied the packet. It failed because the input model itself
 * could not be resolved.
 */

export class SimulationError extends Error {
  /**
   * @param {string} code One of the ERROR_CODES values.
   * @param {string} message Human readable explanation.
   * @param {{sourcePod?: string, service?: string, hop?: number, [key: string]: unknown}} [details]
   */
  constructor(code, message, details = {}) {
    super(message);
    this.name = "SimulationError";
    this.code = code;
    this.details = details;
  }
}

export const ERROR_CODES = Object.freeze({
  MISSING_REQUEST: "MISSING_REQUEST",
  UNKNOWN_SOURCE_POD: "UNKNOWN_SOURCE_POD",
  UNKNOWN_NAMESPACE: "UNKNOWN_NAMESPACE",
  UNKNOWN_SERVICE: "UNKNOWN_SERVICE",
  SERVICE_PORT_NOT_FOUND: "SERVICE_PORT_NOT_FOUND",
  NO_READY_ENDPOINTS: "NO_READY_ENDPOINTS",
  UNKNOWN_TARGET_PORT: "UNKNOWN_TARGET_PORT",
  INVALID_CIDR: "INVALID_CIDR",
  INVALID_IP: "INVALID_IP",
  INVALID_SELECTOR: "INVALID_SELECTOR",
});

/**
 * Warning codes describe non-fatal configuration smells. The simulation still
 * completes, but the warning is surfaced so the user can tell a real "denied"
 * result apart from a model that is probably misconfigured.
 */
export const WARNING_CODES = Object.freeze({
  NAMED_PORT_UNRESOLVED: "NAMED_PORT_UNRESOLVED",
  NO_ENDPOINT_IN_IP_FAMILY: "NO_ENDPOINT_IN_IP_FAMILY",
});

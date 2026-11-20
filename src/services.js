import { SimulationError, ERROR_CODES, WARNING_CODES } from "./errors.js";
import { parseIp } from "./cidr.js";
import { matchesLabels } from "./selector.js";
import { podKey } from "./topology.js";

/**
 * @typedef {import("./topology.js").Topology} Topology
 * @typedef {import("./topology.js").ServiceSpec} ServiceSpec
 * @typedef {import("./topology.js").Pod} Pod
 *
 * @typedef {Object} ResolvedEndpoint
 * @property {string} ip
 * @property {4 | 6} family
 * @property {number} [targetPort]
 * @property {string} targetPortSource "number" | "named"
 * @property {string} [portName]
 * @property {Pod} [pod] Owning pod when the address belongs to a known pod.
 * @property {{code: string, message: string}} [error] Per-endpoint resolution error.
 *
 * @typedef {Object} ServiceResolution
 * @property {ServiceSpec} service
 * @property {{name?: string, port?: number, targetPort?: number|string, protocol: string}} servicePort
 * @property {number} servicePortNumber
 * @property {string} protocol
 * @property {ResolvedEndpoint[]} endpoints
 * @property {Array<{code: string, message: string}>} warnings
 */

/**
 * Resolve a service + destination port into concrete endpoint IPs and the
 * translated target port.
 *
 * Endpoints either come from an explicit `endpoints` field (mirroring the
 * Kubernetes Endpoints API) or are derived from the service selector and the
 * pods known to the topology.
 *
 * @param {Topology} topology
 * @param {ServiceSpec} service
 * @param {number|string} destinationPort Port number or service port name.
 * @returns {ServiceResolution}
 */
export function resolveService(topology, service, destinationPort, protocol = "TCP") {
  const warnings = [];
  const servicePort = pickServicePort(service, destinationPort, protocol);

  const rawEndpoints = service.endpoints
    ? explicitEndpoints(service, servicePort)
    : deriveEndpoints(topology, service, servicePort);

  if (rawEndpoints.length === 0) {
    throw new SimulationError(
      ERROR_CODES.NO_READY_ENDPOINTS,
      `Service ${podKey(service.namespace, service.name)} has no ready endpoints for port ${String(
        destinationPort,
      )}`,
      { service: podKey(service.namespace, service.name) },
    );
  }

  const endpoints = [];
  for (const endpoint of rawEndpoints) {
    let family;
    try {
      family = parseIp(endpoint.ip).family;
    } catch {
      throw new SimulationError(
        ERROR_CODES.INVALID_IP,
        `Endpoint of service ${podKey(service.namespace, service.name)} has an invalid IP: ${endpoint.ip}`,
      );
    }
    const pod = topology.getPodByIp(endpoint.ip);
    const resolved = resolveTargetPort(servicePort, pod, endpoint, warnings);
    endpoints.push({
      ip: endpoint.ip,
      family,
      targetPort: resolved.port,
      targetPortSource: typeof servicePort.targetPort === "string" ? "named" : "number",
      portName: typeof servicePort.targetPort === "string" ? servicePort.targetPort : undefined,
      pod,
      error: resolved.error,
    });
  }

  return {
    service,
    servicePort,
    servicePortNumber: servicePort.port,
    protocol: servicePort.protocol,
    endpoints,
    warnings,
  };
}

function pickServicePort(service, destinationPort, protocol = "TCP") {
  const ports = service.ports;
  if (!ports || ports.length === 0) {
    throw new SimulationError(
      ERROR_CODES.SERVICE_PORT_NOT_FOUND,
      `Service ${podKey(service.namespace, service.name)} declares no ports`,
      { service: podKey(service.namespace, service.name) },
    );
  }

  let match;
  if (typeof destinationPort === "string") {
    match = ports.find((port) => port.name === destinationPort && port.protocol === protocol);
  } else if (typeof destinationPort === "number") {
    match = ports.find((port) => port.port === destinationPort && port.protocol === protocol);
  }

  if (!match) {
    throw new SimulationError(
      ERROR_CODES.SERVICE_PORT_NOT_FOUND,
      `Service ${podKey(service.namespace, service.name)} has no ${protocol} port matching ${String(
        destinationPort,
      )}`,
      { service: podKey(service.namespace, service.name), requestedPort: destinationPort },
    );
  }
  return match;
}

function explicitEndpoints(service, servicePort) {
  const result = [];
  for (const subset of service.endpoints ?? []) {
    const addresses = subset.addresses ?? [];
    if (addresses.length === 0) {
      continue;
    }

    let subsetPort = null;
    if (subset.ports && subset.ports.length > 0) {
      subsetPort =
        subset.ports.find((port) => port.name === servicePort.name) ??
        subset.ports.find((port) => port.protocol === servicePort.protocol) ??
        subset.ports[0];
    }

    for (const address of addresses) {
      result.push({
        ip: address.ip,
        port: subsetPort?.port ?? servicePort.targetPort,
      });
    }
  }
  return result;
}

function deriveEndpoints(topology, service) {
  if (!service.selector || Object.keys(service.selector).length === 0) {
    return [];
  }
  const result = [];
  for (const pod of topology.pods.values()) {
    if (pod.namespace !== service.namespace) {
      continue;
    }
    if (!matchesLabels({ matchLabels: service.selector }, pod.labels)) {
      continue;
    }
    if (pod.ip) {
      result.push({ ip: pod.ip, port: undefined });
    }
    if (pod.ipv6) {
      result.push({ ip: pod.ipv6, port: undefined });
    }
  }
  return result;
}

function resolveTargetPort(servicePort, pod, endpoint, warnings) {
  const rawTarget = endpoint.port ?? servicePort.targetPort ?? servicePort.port;

  if (typeof rawTarget === "number") {
    return { port: rawTarget };
  }

  const portName = String(rawTarget);
  const containerPort = pod?.ports.find(
    (port) => port.name === portName && port.protocol === servicePort.protocol,
  );
  if (!containerPort) {
    const message = pod
      ? `Named port "${portName}" is not declared by pod ${podKey(pod.namespace, pod.name)}`
      : `Named port "${portName}" cannot be resolved because endpoint ${endpoint.ip} maps to no known pod`;
    warnings.push({
      code: WARNING_CODES.NAMED_PORT_UNRESOLVED,
      message,
    });
    return {
      port: undefined,
      error: {
        code: ERROR_CODES.UNKNOWN_TARGET_PORT,
        message: `Cannot resolve named target port "${portName}" for endpoint ${endpoint.ip}`,
      },
    };
  }
  return { port: containerPort.containerPort };
}

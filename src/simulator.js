import {
  SimulationError,
  ERROR_CODES,
  WARNING_CODES,
} from "./errors.js";
import { parseIp } from "./cidr.js";
import { createTopology, podKey } from "./topology.js";
import { resolveService } from "./services.js";
import { evaluateDirection } from "./policies.js";

/**
 * @typedef {import("./topology.js").Scenario} Scenario
 * @typedef {import("./topology.js").Pod} Pod
 * @typedef {import("./services.js").ResolvedEndpoint} ResolvedEndpoint
 *
 * @typedef {Object} PathRequest
 * @property {string} sourceNamespace
 * @property {string} sourcePod
 * @property {number|string} destinationPort Service port number or service port name.
 * @property {string} [protocol] Defaults to TCP.
 * @property {4|6} [ipFamily] Preferred IP family for dual-stack services.
 * @property {{namespace: string, name: string, clusterIP?: string}} [destinationService]
 * @property {{namespace: string, name: string}} [destinationPod]
 * @property {string} [destinationIp]
 *
 * @typedef {Object} Hop
 * @property {number} hop
 * @property {string} stage "egress" | "ingress"
 * @property {string} evaluatedPod
 * @property {string} peerIp
 * @property {string} peerPod
 * @property {number} port
 * @property {string} protocol
 * @property {"allow"|"deny"} decision
 * @property {boolean} policyApplies
 * @property {object[]} matchedRules
 * @property {string[]} blockingPolicies
 * @property {string} [note]
 *
 * @typedef {Object} Branch
 * @property {number} index
 * @property {"allow"|"deny"|"error"} result
 * @property {{ip: string, family: 4|6, pod?: string, targetPort?: number, portName?: string}} endpoint
 * @property {Hop[]} hops
 * @property {{code: string, message: string}} [error]
 *
 * @typedef {Object} SimulationResult
 * @property {"allow"|"deny"|"partial"|"error"} status
 * @property {string} source
 * @property {string} protocol
 * @property {object} [route]
 * @property {Branch[]} branches
 * @property {object[]} endpoints
 * @property {Array<{code: string, message: string}>} warnings
 * @property {{code: string, message: string}} [error]
 */

/**
 * Run an offline hop-by-hop simulation.
 *
 * @param {Scenario} scenario
 * @param {PathRequest} request
 * @returns {SimulationResult}
 */
export function simulatePath(scenario, request) {
  if (!request || typeof request !== "object") {
    throw new SimulationError(ERROR_CODES.MISSING_REQUEST, "A path request object is required");
  }

  const topology = createTopology(scenario);
  const protocol = (request.protocol ?? "TCP").toUpperCase();
  const warnings = [];

  const sourcePod = lookupSourcePod(topology, request);
  const sourceId = podKey(sourcePod.namespace, sourcePod.name);

  const base = {
    source: sourceId,
    protocol,
    warnings,
  };

  if (request.destinationService) {
    return simulateServicePath(topology, request, sourcePod, protocol, warnings, base);
  }
  if (request.destinationIp) {
    return simulateIpPath(topology, request, sourcePod, protocol, base);
  }
  if (request.destinationPod) {
    return simulateNamedPodPath(topology, request, sourcePod, protocol, base);
  }
  throw new SimulationError(
    ERROR_CODES.MISSING_REQUEST,
    "The request needs destinationService, destinationPod or destinationIp",
  );
}

function lookupSourcePod(topology, request) {
  if (!request.sourceNamespace || !request.sourcePod) {
    throw new SimulationError(
      ERROR_CODES.UNKNOWN_SOURCE_POD,
      "sourceNamespace and sourcePod are both required",
    );
  }
  const pod = topology.getPod(request.sourceNamespace, request.sourcePod);
  if (!pod) {
    throw new SimulationError(
      ERROR_CODES.UNKNOWN_SOURCE_POD,
      `Source pod ${podKey(request.sourceNamespace, request.sourcePod)} is not defined`,
    );
  }
  return pod;
}

function simulateServicePath(topology, request, sourcePod, protocol, warnings, base) {
  const ref = request.destinationService;
  const service = ref.clusterIP
    ? findServiceByClusterIP(topology, ref.clusterIP)
    : topology.getService(ref.namespace, ref.name);

  if (!service) {
    throw new SimulationError(
      ERROR_CODES.UNKNOWN_SERVICE,
      `Service ${ref.clusterIP ?? podKey(ref.namespace, ref.name)} is not defined`,
      { service: ref.clusterIP ?? podKey(ref.namespace, ref.name) },
    );
  }

  const resolution = resolveService(topology, service, request.destinationPort, protocol);
  warnings.push(...resolution.warnings);

  const requestedFamily = request.ipFamily ?? parseIp(resolution.endpoints[0].ip).family;
  let endpoints = resolution.endpoints.filter((endpoint) => endpoint.family === requestedFamily);
  if (endpoints.length === 0) {
    const fallback = resolution.endpoints[0];
    warnings.push({
      code: WARNING_CODES.NO_ENDPOINT_IN_IP_FAMILY,
      message: `No IPv${requestedFamily} endpoints exist for ${podKey(
        service.namespace,
        service.name,
      )}; falling back to IPv${fallback.family}`,
    });
    endpoints = [fallback];
  }

  const branches = endpoints.map((endpoint, index) =>
    evaluateBranch(topology, sourcePod, endpoint, protocol, index),
  );

  return {
    ...base,
    status: aggregateStatus(branches),
    route: {
      kind: "service",
      service: podKey(service.namespace, service.name),
      clusterIP: service.clusterIP,
      clusterIPv6: service.clusterIPv6,
      servicePort: resolution.servicePortNumber,
      targetPort: resolution.servicePort.targetPort ?? resolution.servicePortNumber,
      protocol,
      dnat: `${service.clusterIP ?? service.clusterIPv6}:${resolution.servicePortNumber} -> endpoint:targetPort`,
    },
    branches,
    endpoints: branches.map((branch) => branch.endpoint),
  };
}

function simulateIpPath(topology, request, sourcePod, protocol, base) {
  const ip = request.destinationIp;
  let family;
  try {
    family = parseIp(ip).family;
  } catch (error) {
    throw new SimulationError(
      ERROR_CODES.INVALID_IP,
      `destinationIp is not a valid IPv4/IPv6 literal: ${ip}`,
    );
  }
  const pod = topology.getPodByIp(ip);
  const endpoint = {
    ip,
    family,
    pod: pod ? podKey(pod.namespace, pod.name) : undefined,
    targetPort: request.destinationPort,
  };
  const branch = evaluateBranch(
    topology,
    sourcePod,
    { ip, family, targetPort: request.destinationPort, pod },
    protocol,
    0,
  );
  return {
    ...base,
    status: aggregateStatus([branch]),
    route: { kind: "ip", destinationIp: ip, protocol },
    branches: [branch],
    endpoints: [endpoint],
  };
}

function simulateNamedPodPath(topology, request, sourcePod, protocol, base) {
  const ref = request.destinationPod;
  const pod = topology.getPod(ref.namespace, ref.name);
  if (!pod) {
    throw new SimulationError(
      ERROR_CODES.UNKNOWN_SOURCE_POD,
      `Destination pod ${podKey(ref.namespace, ref.name)} is not defined`,
    );
  }
  const family = request.ipFamily ?? 4;
  const ip = family === 6 ? pod.ipv6 : pod.ip;
  if (!ip) {
    throw new SimulationError(
      ERROR_CODES.INVALID_IP,
      `Pod ${podKey(pod.namespace, pod.name)} has no IPv${family} address`,
    );
  }
  const branch = evaluateBranch(
    topology,
    sourcePod,
    { ip, family, targetPort: request.destinationPort, pod },
    protocol,
    0,
  );
  return {
    ...base,
    status: aggregateStatus([branch]),
    route: { kind: "pod", destination: podKey(pod.namespace, pod.name), protocol },
    branches: [branch],
    endpoints: [branch.endpoint],
  };
}

function evaluateBranch(topology, sourcePod, endpoint, protocol, index) {
  if (endpoint.error) {
    return {
      index,
      result: "error",
      endpoint: {
        ip: endpoint.ip,
        family: endpoint.family,
        pod: endpoint.pod ? podKey(endpoint.pod.namespace, endpoint.pod.name) : undefined,
        portName: endpoint.portName,
      },
      hops: [],
      error: endpoint.error,
    };
  }

  const hops = [];
  try {
    const egress = evaluateDirection(topology, sourcePod, "Egress", {
      ip: endpoint.ip,
      peerPod: endpoint.pod,
      port: endpoint.targetPort,
      protocol,
    });
    hops.push({
      hop: 1,
      stage: "egress",
      evaluatedPod: podKey(sourcePod.namespace, sourcePod.name),
      peerIp: endpoint.ip,
      peerPod: endpoint.pod ? podKey(endpoint.pod.namespace, endpoint.pod.name) : null,
      port: endpoint.targetPort,
      protocol,
      decision: egress.decision,
      policyApplies: egress.policyApplies,
      matchedRules: egress.matchedRules,
      blockingPolicies: egress.blockingPolicies,
      note: "Evaluated against the post-DNAT endpoint identity, as kube-proxy DNAT happens before policy enforcement in most CNIs.",
    });

    if (egress.decision === "deny" || !endpoint.pod) {
      return {
        index,
        result: egress.decision === "deny" ? "deny" : "allow",
        endpoint: describeEndpoint(endpoint),
        hops,
      };
    }

    const targetPod = endpoint.pod;
    const sourceIp = endpoint.family === 6 ? sourcePod.ipv6 ?? sourcePod.ip : sourcePod.ip ?? sourcePod.ipv6;
    const ingress = evaluateDirection(topology, targetPod, "Ingress", {
      ip: sourceIp,
      peerPod: sourcePod,
      port: endpoint.targetPort,
      protocol,
    });
    hops.push({
      hop: 2,
      stage: "ingress",
      evaluatedPod: podKey(targetPod.namespace, targetPod.name),
      peerIp: sourceIp,
      peerPod: podKey(sourcePod.namespace, sourcePod.name),
      port: endpoint.targetPort,
      protocol,
      decision: ingress.decision,
      policyApplies: ingress.policyApplies,
      matchedRules: ingress.matchedRules,
      blockingPolicies: ingress.blockingPolicies,
      note: "Ingress policy runs on the endpoint after service/port translation.",
    });

    return {
      index,
      result: ingress.decision === "allow" ? "allow" : "deny",
      endpoint: describeEndpoint(endpoint),
      hops,
    };
  } catch (error) {
    return {
      index,
      result: "error",
      endpoint: describeEndpoint(endpoint),
      hops,
      error: toErrorBody(error),
    };
  }
}

function describeEndpoint(endpoint) {
  return {
    ip: endpoint.ip,
    family: endpoint.family,
    pod: endpoint.pod ? podKey(endpoint.pod.namespace, endpoint.pod.name) : undefined,
    targetPort: endpoint.targetPort,
    portName: endpoint.portName,
  };
}

function aggregateStatus(branches) {
  if (branches.some((branch) => branch.result === "error")) {
    return branches.every((branch) => branch.result === "error") ? "error" : "partial";
  }
  if (branches.every((branch) => branch.result === "allow")) {
    return "allow";
  }
  if (branches.every((branch) => branch.result === "deny")) {
    return "deny";
  }
  return "partial";
}

function findServiceByClusterIP(topology, clusterIP) {
  for (const service of topology.services.values()) {
    if (service.clusterIP === clusterIP || service.clusterIPv6 === clusterIP) {
      return service;
    }
  }
  return undefined;
}

function toErrorBody(error) {
  if (error instanceof SimulationError) {
    return { code: error.code, message: error.message };
  }
  return { code: "UNEXPECTED_ERROR", message: error.message };
}

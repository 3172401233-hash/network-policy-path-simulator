import { SimulationError, ERROR_CODES } from "./errors.js";
import { matchesLabels } from "./selector.js";

/**
 * @typedef {Object} Scenario
 * @property {Array<{name: string, labels?: Object<string,string>}>} namespaces
 * @property {Array<Pod>} pods
 * @property {Array<ServiceSpec>} [services]
 * @property {Array<NetworkPolicySpec>} [policies]
 *
 * @typedef {Object} Pod
 * @property {string} namespace
 * @property {string} name
 * @property {Object<string,string>} [labels]
 * @property {string} [ip] IPv4 address.
 * @property {string} [ipv6] IPv6 address.
 * @property {Array<ContainerPort>} [ports]
 *
 * @typedef {Object} ContainerPort
 * @property {string} name
 * @property {number} containerPort
 * @property {string} [protocol]
 *
 * @typedef {Object} ServiceSpec
 * @property {string} namespace
 * @property {string} name
 * @property {Object<string,string>} [selector]
 * @property {string} [clusterIP]
 * @property {string} [clusterIPv6]
 * @property {Array<ServicePort>} [ports]
 * @property {Array<EndpointSubset>} [endpoints]
 *
 * @typedef {Object} ServicePort
 * @property {string} [name]
 * @property {number} [port]
 * @property {number|string} [targetPort] Number or named container port.
 * @property {string} [protocol]
 *
 * @typedef {Object} EndpointSubset
 * @property {Array<{ip: string}>} [addresses]
 * @property {Array<{port?: number|string, name?: string, protocol?: string}>} [ports]
 */

/**
 * Normalize and index a complete simulation scenario.
 *
 * @param {Scenario} scenario
 * @returns {Topology}
 */
export function createTopology(scenario) {
  if (!scenario || typeof scenario !== "object") {
    throw new SimulationError(ERROR_CODES.MISSING_REQUEST, "A scenario object is required");
  }

  const namespaces = new Map();
  for (const namespace of scenario.namespaces ?? []) {
    if (!namespace || typeof namespace.name !== "string" || namespace.name.length === 0) {
      throw new SimulationError(
        ERROR_CODES.UNKNOWN_NAMESPACE,
        "Every namespace requires a non-empty name",
      );
    }
    if (namespaces.has(namespace.name)) {
      throw new SimulationError(
        ERROR_CODES.UNKNOWN_NAMESPACE,
        `Duplicate namespace definition: ${namespace.name}`,
      );
    }
    namespaces.set(namespace.name, { name: namespace.name, labels: namespace.labels ?? {} });
  }

  const pods = new Map();
  const podsByIp = new Map();
  for (const pod of scenario.pods ?? []) {
    requireNamespace(namespaces, pod?.namespace);
    if (!pod.name) {
      throw new SimulationError(ERROR_CODES.UNKNOWN_SOURCE_POD, "Every pod requires a name");
    }
    const key = podKey(pod.namespace, pod.name);
    if (pods.has(key)) {
      throw new SimulationError(
        ERROR_CODES.UNKNOWN_SOURCE_POD,
        `Duplicate pod definition: ${key}`,
      );
    }
    const normalized = {
      namespace: pod.namespace,
      name: pod.name,
      labels: pod.labels ?? {},
      ip: pod.ip,
      ipv6: pod.ipv6,
      ports: (pod.ports ?? []).map((port) => ({
        name: port.name,
        containerPort: port.containerPort,
        protocol: (port.protocol ?? "TCP").toUpperCase(),
      })),
    };
    pods.set(key, normalized);
    if (normalized.ip) {
      podsByIp.set(normalized.ip, normalized);
    }
    if (normalized.ipv6) {
      podsByIp.set(normalized.ipv6, normalized);
    }
  }

  const services = new Map();
  for (const service of scenario.services ?? []) {
    requireNamespace(namespaces, service?.namespace);
    const key = podKey(service.namespace, service.name);
    if (services.has(key)) {
      throw new SimulationError(ERROR_CODES.UNKNOWN_SERVICE, `Duplicate service definition: ${key}`);
    }
    services.set(key, {
      namespace: service.namespace,
      name: service.name,
      selector: service.selector,
      clusterIP: service.clusterIP,
      clusterIPv6: service.clusterIPv6,
      ports: (service.ports ?? []).map((port) => ({
        name: port.name,
        port: port.port,
        targetPort: port.targetPort,
        protocol: (port.protocol ?? "TCP").toUpperCase(),
      })),
      endpoints: service.endpoints ?? null,
    });
  }

  validatePolicies(scenario.policies ?? [], namespaces);

  return {
    namespaces,
    pods,
    services,
    policies: scenario.policies ?? [],
    getNamespace(name) {
      return namespaces.get(name);
    },
    getPod(namespace, name) {
      return pods.get(podKey(namespace, name));
    },
    getService(namespace, name) {
      return services.get(podKey(namespace, name));
    },
    getPodByIp(ip) {
      return podsByIp.get(ip);
    },
  };
}

/**
 * @typedef {Object} Topology
 * @property {Map<string, {name: string, labels: Object<string,string>}>} namespaces
 * @property {Map<string, Pod>} pods
 * @property {Map<string, ServiceSpec>} services
 * @property {NetworkPolicySpec[]} policies
 * @property {(name: string) => {name: string, labels: Object<string,string>} | undefined} getNamespace
 * @property {(namespace: string, name: string) => Pod | undefined} getPod
 * @property {(namespace: string, name: string) => ServiceSpec | undefined} getService
 * @property {(ip: string) => Pod | undefined} getPodByIp
 */

export function podKey(namespace, name) {
  return `${namespace}/${name}`;
}

export function requireNamespace(namespaces, name) {
  if (!namespaces.has(name)) {
    throw new SimulationError(
      ERROR_CODES.UNKNOWN_NAMESPACE,
      `Namespace "${name}" is not defined in the scenario`,
      { namespace: name },
    );
  }
}

function validatePolicies(policies, namespaces) {
  for (const policyDoc of policies) {
    if (!policyDoc || typeof policyDoc !== "object" || !policyDoc.name) {
      throw new SimulationError(
        ERROR_CODES.INVALID_SELECTOR,
        "Every NetworkPolicy requires a name",
      );
    }
    if (!namespaces.has(policyDoc.namespace)) {
      throw new SimulationError(
        ERROR_CODES.UNKNOWN_NAMESPACE,
        `Policy ${policyDoc.namespace}/${policyDoc.name} references an undefined namespace`,
      );
    }
    // Evaluate every selector against empty labels once, purely to surface
    // malformed operators/keys at load time instead of mid-simulation.
    matchesLabels(policyDoc.podSelector ?? {}, {});
    for (const rule of policyDoc.ingress ?? []) {
      for (const peer of rule.from ?? []) {
        validatePeer(peer);
      }
    }
    for (const rule of policyDoc.egress ?? []) {
      for (const peer of rule.to ?? []) {
        validatePeer(peer);
      }
    }
  }
}

function validatePeer(peer) {
  if (peer.podSelector !== undefined) {
    matchesLabels(peer.podSelector, {});
  }
  if (peer.namespaceSelector !== undefined) {
    matchesLabels(peer.namespaceSelector, {});
  }
  if (peer.ipBlock !== undefined && typeof peer.ipBlock.cidr !== "string") {
    throw new SimulationError(
      ERROR_CODES.INVALID_CIDR,
      "ipBlock peer requires a string cidr field",
    );
  }
}

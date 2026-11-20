import { SimulationError, ERROR_CODES } from "./errors.js";
import { matchesIpBlock } from "./cidr.js";
import { matchesLabels } from "./selector.js";
import { podKey } from "./topology.js";

/**
 * @typedef {import("./topology.js").Topology} Topology
 * @typedef {import("./topology.js").Pod} Pod
 *
 * @typedef {Object} NetworkPolicySpec
 * @property {string} namespace Namespace that owns the policy object.
 * @property {string} name
 * @property {Object} [podSelector] Label selector; null/undefined/{} selects all pods.
 * @property {string[]} [policyTypes] Subset of ["Ingress", "Egress"].
 * @property {Array<IngressRule>} [ingress]
 * @property {Array<EgressRule>} [egress]
 *
 * @typedef {Object} IngressRule
 * @property {Array<Peer>} [from] Omitted means any peer; an empty array matches none.
 * @property {Array<PolicyPort>} [ports] Omitted means any port/protocol.
 *
 * @typedef {Object} EgressRule
 * @property {Array<Peer>} [to] Omitted means any peer; an empty array matches none.
 * @property {Array<PolicyPort>} [ports] Omitted means any port/protocol.
 *
 * @typedef {Object} Peer
 * @property {Object} [podSelector]
 * @property {Object} [namespaceSelector]
 * @property {{cidr: string, except?: string[]}} [ipBlock]
 *
 * @typedef {Object} PolicyPort
 * @property {number} [port]
 * @property {string} [portName] Alternative field for named ports in this input model.
 * @property {number} [endPort]
 * @property {string} [protocol]
 */

/**
 * @typedef {Object} Traffic
 * @property {string} ip Peer IP literal (the other side of the connection).
 * @property {Pod} [peerPod] Pod owning that IP, when known.
 * @property {number} port Destination (egress) or destination (ingress) port.
 * @property {string} protocol
 *
 * @typedef {Object} DirectionDecision
 * @property {"allow" | "deny"} decision
 * @property {boolean} policyApplies Whether any policy selects this pod for the direction.
 * @property {Array<{namespace: string, name: string, ruleIndex: number, peerIndex: number, kind: string}>} matchedRules
 * @property {string[]} blockingPolicies Identifiers of policies that selected the pod but had no matching rule.
 */

/**
 * Evaluate one direction (Ingress or Egress) of all policies against one pod.
 *
 * Kubernetes semantics:
 * - policies are additive (union of allow rules);
 * - if no policy enables this direction on the pod, everything is allowed;
 * - once at least one policy enables the direction, the pod is isolated and
 *   traffic is allowed only when some rule matches.
 *
 * @param {Topology} topology
 * @param {Pod} pod The pod whose policy boundary is being evaluated.
 * @param {"Ingress" | "Egress"} direction
 * @param {Traffic} traffic
 * @returns {DirectionDecision}
 */
export function evaluateDirection(topology, pod, direction, traffic) {
  const applicable = topology.policies.filter(
    (policy) =>
      policy.namespace === pod.namespace &&
      matchesLabels(policy.podSelector ?? {}, pod.labels) &&
      directionEnabled(policy, direction),
  );

  if (applicable.length === 0) {
    return { decision: "allow", policyApplies: false, matchedRules: [], blockingPolicies: [] };
  }

  const matchedRules = [];
  const blockingPolicies = [];

  for (const policy of applicable) {
    const rules = direction === "Ingress" ? policy.ingress ?? [] : policy.egress ?? [];
    const ruleMatch = findMatchingRule(rules, direction, topology, pod, traffic);
    if (ruleMatch) {
      matchedRules.push({
        namespace: policy.namespace,
        name: policy.name,
        ...ruleMatch,
      });
    } else {
      blockingPolicies.push(policyId(policy));
    }
  }

  return {
    decision: matchedRules.length > 0 ? "allow" : "deny",
    policyApplies: true,
    matchedRules,
    blockingPolicies,
  };
}

/**
 * Default policyTypes handling mirrors Kubernetes:
 * - Ingress is always enabled when policyTypes is omitted;
 * - Egress is enabled when omitted only if the policy contains egress rules.
 */
function directionEnabled(policy, direction) {
  if (!policy.policyTypes || policy.policyTypes.length === 0) {
    if (direction === "Ingress") {
      return true;
    }
    return Array.isArray(policy.egress) && policy.egress.length > 0;
  }
  return policy.policyTypes.includes(direction);
}

function findMatchingRule(rules, direction, topology, pod, traffic) {
  const peerField = direction === "Ingress" ? "from" : "to";

  for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
    const rule = rules[ruleIndex];
    const peerEntries = rule[peerField];

    let peerMatch;
    if (peerEntries === undefined) {
      peerMatch = { peerIndex: -1, kind: "any" };
    } else if (peerEntries.length === 0) {
      peerMatch = null;
    } else {
      peerMatch = findMatchingPeer(peerEntries, topology, pod, traffic);
    }

    if (!peerMatch) {
      continue;
    }
    if (!portMatches(rule.ports, pod, traffic)) {
      continue;
    }
    return { ruleIndex, peerIndex: peerMatch.peerIndex, kind: peerMatch.kind };
  }
  return null;
}

function findMatchingPeer(peerEntries, topology, pod, traffic) {
  for (let peerIndex = 0; peerIndex < peerEntries.length; peerIndex += 1) {
    const peer = peerEntries[peerIndex];
    if (peer.ipBlock) {
      if (matchesIpBlock(traffic.ip, peer.ipBlock)) {
        return { peerIndex, kind: "ipBlock" };
      }
      continue;
    }

    const peerPod = traffic.peerPod;
    if (!peerPod) {
      continue;
    }

    if (peer.namespaceSelector) {
      const namespace = topology.getNamespace(peerPod.namespace);
      if (!namespace || !matchesLabels(peer.namespaceSelector, namespace.labels)) {
        continue;
      }
    } else if (peer.podSelector) {
      if (peerPod.namespace !== pod.namespace) {
        continue;
      }
    }

    if (peer.podSelector !== undefined) {
      if (!matchesLabels(peer.podSelector, peerPod.labels)) {
        continue;
      }
    }

    return { peerIndex, peer: peerPod, kind: describePeerKind(peer) };
  }
  return null;
}

function describePeerKind(peer) {
  if (peer.podSelector && peer.namespaceSelector) {
    return "namespaceAndPodSelector";
  }
  if (peer.namespaceSelector) {
    return "namespaceSelector";
  }
  return "podSelector";
}

function portMatches(rulePorts, pod, traffic) {
  if (rulePorts === undefined || rulePorts.length === 0) {
    return true;
  }
  const protocol = traffic.protocol;

  for (const rulePort of rulePorts) {
    const ruleProtocol = (rulePort.protocol ?? "TCP").toUpperCase();
    if (ruleProtocol !== protocol) {
      continue;
    }

    let numericPort;
    if (typeof rulePort.port === "number") {
      numericPort = rulePort.port;
    } else if (typeof rulePort.port === "string" || rulePort.portName) {
      const name = rulePort.portName ?? rulePort.port;
      numericPort = resolveNamedPort(pod, name, protocol);
      if (numericPort === null) {
        continue;
      }
    } else {
      continue;
    }

    const endPort = rulePort.endPort ?? numericPort;
    if (endPort < numericPort) {
      throw new SimulationError(
        ERROR_CODES.UNKNOWN_TARGET_PORT,
        `Policy port range endPort ${endPort} is below port ${numericPort}`,
      );
    }
    if (traffic.port >= numericPort && traffic.port <= endPort) {
      return true;
    }
  }
  return false;
}

function resolveNamedPort(pod, portName, protocol) {
  const containerPort = pod.ports.find(
    (port) => port.name === portName && port.protocol === protocol,
  );
  return containerPort ? containerPort.containerPort : null;
}

export function policyId(policy) {
  return podKey(policy.namespace, policy.name);
}

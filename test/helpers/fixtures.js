/**
 * Shared scenario builders. Each test can mutate the returned plain objects,
 * so every call returns a fresh deep copy.
 */

export function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

/**
 * Two namespaces:
 * - "frontend" labeled tier=frontend
 * - "backend"  labeled tier=backend
 *
 * Pods:
 * - frontend/web        10.10.1.10
 * - backend/api-a       10.20.0.11 (named http -> 8080)
 * - backend/api-b       10.20.0.12 (named http -> 8080)
 * - backend/legacy      10.20.0.21 (no named http port)
 *
 * Service backend/api (ClusterIP 172.16.0.100, port 80 -> named targetPort http)
 * selects app=api, so it has two ready endpoints.
 */
export function baseScenario() {
  return clone({
    namespaces: [
      { name: "frontend", labels: { tier: "frontend", env: "prod" } },
      { name: "backend", labels: { tier: "backend", env: "prod" } },
      { name: "legacy", labels: { tier: "legacy", env: "old" } },
    ],
    pods: [
      {
        namespace: "frontend",
        name: "web",
        labels: { app: "web", role: "client" },
        ip: "10.10.1.10",
        ipv6: "fd00:10::a",
      },
      {
        namespace: "backend",
        name: "api-a",
        labels: { app: "api" },
        ip: "10.20.0.11",
        ipv6: "fd00:20::b",
        ports: [{ name: "http", containerPort: 8080, protocol: "TCP" }],
      },
      {
        namespace: "backend",
        name: "api-b",
        labels: { app: "api" },
        ip: "10.20.0.12",
        ipv6: "fd00:20::c",
        ports: [{ name: "http", containerPort: 8080, protocol: "TCP" }],
      },
      {
        namespace: "backend",
        name: "legacy",
        labels: { app: "legacy" },
        ip: "10.20.0.21",
        ports: [{ name: "grpc", containerPort: 9090, protocol: "TCP" }],
      },
      {
        namespace: "legacy",
        name: "old-web",
        labels: { app: "old-web" },
        ip: "10.30.0.10",
        ports: [{ name: "http", containerPort: 8080, protocol: "TCP" }],
      },
    ],
    services: [
      {
        namespace: "backend",
        name: "api",
        selector: { app: "api" },
        clusterIP: "172.16.0.100",
        clusterIPv6: "2001:db8::100",
        ports: [
          { name: "http", port: 80, targetPort: "http", protocol: "TCP" },
          { name: "metrics", port: 9100, targetPort: 9100, protocol: "TCP" },
        ],
      },
    ],
    policies: [],
  });
}

export function serviceRequest(overrides = {}) {
  return {
    sourceNamespace: "frontend",
    sourcePod: "web",
    destinationService: { namespace: "backend", name: "api" },
    destinationPort: 80,
    protocol: "TCP",
    ...overrides,
  };
}

export function policy(overrides) {
  return {
    namespace: "backend",
    name: "test-policy",
    podSelector: {},
    policyTypes: ["Ingress"],
    ingress: [],
    ...overrides,
  };
}

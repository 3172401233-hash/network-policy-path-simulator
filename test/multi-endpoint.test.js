import { test } from "node:test";
import assert from "node:assert/strict";

import { simulatePath } from "../src/index.js";
import { baseScenario, serviceRequest, policy, clone } from "./helpers/fixtures.js";

test("multi-endpoint service produces one branch per endpoint with translated port", () => {
  const result = simulatePath(baseScenario(), serviceRequest());

  assert.equal(result.route.kind, "service");
  assert.equal(result.route.service, "backend/api");
  assert.equal(result.route.servicePort, 80);
  assert.deepEqual(
    result.endpoints.map((endpoint) => endpoint.ip).sort(),
    ["10.20.0.11", "10.20.0.12"],
  );
  for (const endpoint of result.endpoints) {
    assert.equal(endpoint.targetPort, 8080);
    assert.equal(endpoint.portName, "http");
    assert.equal(endpoint.pod.startsWith("backend/"), true);
  }
});

test("one endpoint denied, another allowed yields partial with per-hop blocking policy", () => {
  const scenario = baseScenario();
  scenario.pods[2].labels = { app: "api", canary: "true" };
  scenario.policies = [
    policy({
      name: "only-first-endpoint",
      podSelector: {
        matchExpressions: [{ key: "canary", operator: "DoesNotExist" }],
      },
      ingress: [
        {
          from: [
            {
              namespaceSelector: { matchLabels: { tier: "frontend" } },
              podSelector: { matchLabels: { app: "web" } },
            },
          ],
          ports: [{ port: 8080 }],
        },
      ],
    }),
    policy({
      name: "isolate-canary",
      podSelector: { matchLabels: { canary: "true" } },
      policyTypes: ["Ingress"],
      ingress: [],
    }),
  ];

  const result = simulatePath(scenario, serviceRequest());
  assert.equal(result.status, "partial");

  const healthy = result.branches.find((branch) => branch.endpoint.ip === "10.20.0.11");
  const canary = result.branches.find((branch) => branch.endpoint.ip === "10.20.0.12");
  assert.equal(healthy.result, "allow");
  assert.equal(canary.result, "deny");
  assert.deepEqual(canary.hops[1].blockingPolicies, ["backend/isolate-canary"]);
  assert.equal(canary.hops[1].matchedRules.length, 0);
});

test("named port unresolved on one endpoint is an error branch while the other still succeeds", () => {
  const scenario = baseScenario();
  scenario.services[0].selector = undefined;
  scenario.services[0].endpoints = [
    {
      addresses: [{ ip: "10.20.0.11" }, { ip: "10.20.0.99" }],
      ports: [{ name: "http", protocol: "TCP" }],
    },
  ];

  const result = simulatePath(scenario, serviceRequest());

  assert.equal(result.status, "partial");
  const good = result.branches.find((branch) => branch.endpoint.ip === "10.20.0.11");
  const bad = result.branches.find((branch) => branch.endpoint.ip === "10.20.0.99");
  assert.equal(good.result, "allow");
  assert.equal(good.endpoint.targetPort, 8080);
  assert.equal(bad.result, "error");
  assert.equal(bad.error.code, "UNKNOWN_TARGET_PORT");
  assert.equal(result.warnings[0].code, "NAMED_PORT_UNRESOLVED");
});

test("explicit numeric targetPort on Endpoints bypasses named port lookup", () => {
  const scenario = baseScenario();
  scenario.services[0].endpoints = [
    {
      addresses: [{ ip: "10.20.0.11" }],
      ports: [{ name: "http", port: 8081, protocol: "TCP" }],
    },
  ];

  const result = simulatePath(scenario, serviceRequest());
  assert.equal(result.status, "allow");
  assert.equal(result.branches[0].endpoint.targetPort, 8081);
});

test("port range with endPort matches ports inside and outside the range", () => {
  const scenario = baseScenario();
  scenario.services[0].ports = [{ name: "metrics", port: 9100, targetPort: 9100, protocol: "TCP" }];
  scenario.pods[1].ports.push({ name: "metrics", containerPort: 9100, protocol: "TCP" });
  scenario.pods[2].ports.push({ name: "metrics", containerPort: 9100, protocol: "TCP" });
  scenario.policies = [
    {
      namespace: "frontend",
      name: "range-egress",
      podSelector: { matchLabels: { app: "web" } },
      policyTypes: ["Egress"],
      egress: [
        {
          to: [{ namespaceSelector: { matchLabels: { tier: "backend" } } }],
          ports: [{ port: 9000, endPort: 9099, protocol: "TCP" }],
        },
      ],
    },
  ];

  const denied = simulatePath(scenario, serviceRequest({ destinationPort: 9100 }));
  assert.equal(denied.status, "deny");
  assert.equal(denied.branches[0].hops[0].blockingPolicies[0], "frontend/range-egress");

  const allowedScenario = clone(scenario);
  allowedScenario.policies[0].egress[0].ports[0].endPort = 9200;
  const allowed = simulatePath(allowedScenario, serviceRequest({ destinationPort: 9100 }));
  assert.equal(allowed.status, "allow");
});

test("service without ready endpoints is reported as a configuration error, not a policy deny", () => {
  const scenario = baseScenario();
  scenario.services.push({
    namespace: "backend",
    name: "ghost",
    selector: { app: "does-not-exist" },
    clusterIP: "172.16.0.200",
    ports: [{ port: 80, targetPort: 8080, protocol: "TCP" }],
  });

  assert.throws(
    () =>
      simulatePath(
        scenario,
        serviceRequest({ destinationService: { namespace: "backend", name: "ghost" } }),
      ),
    (error) => error.code === "NO_READY_ENDPOINTS",
  );
});

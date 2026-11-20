import { test } from "node:test";
import assert from "node:assert/strict";

import { simulatePath } from "../src/index.js";
import { baseScenario, serviceRequest, policy, clone } from "./helpers/fixtures.js";

test("no policies at all: every hop is allowed by default", () => {
  const result = simulatePath(baseScenario(), serviceRequest());

  assert.equal(result.status, "allow");
  assert.equal(result.branches.length, 2);
  for (const branch of result.branches) {
    assert.equal(branch.result, "allow");
    assert.equal(branch.hops.length, 2);
    for (const hop of branch.hops) {
      assert.equal(hop.decision, "allow");
      assert.equal(hop.policyApplies, false);
      assert.deepEqual(hop.matchedRules, []);
      assert.deepEqual(hop.blockingPolicies, []);
    }
  }
});

test("same namespace: matching ingress podSelector allows the traffic", () => {
  const scenario = baseScenario();
  scenario.policies = [
    policy({
      namespace: "backend",
      name: "allow-same-selector",
      podSelector: { matchLabels: { app: "api" } },
      ingress: [
        {
          from: [{ podSelector: { matchLabels: { app: "api" } } }],
          ports: [{ port: 8080, protocol: "TCP" }],
        },
      ],
    }),
  ];

  const request = serviceRequest({
    sourceNamespace: "backend",
    sourcePod: "api-a",
  });
  const result = simulatePath(scenario, request);

  assert.equal(result.status, "allow");
  for (const branch of result.branches) {
    const ingress = branch.hops.find((hop) => hop.stage === "ingress");
    assert.equal(ingress.decision, "allow");
    assert.equal(ingress.matchedRules[0].name, "allow-same-selector");
  }
});

test("empty podSelector on the policy selects every pod in its namespace", () => {
  const scenario = baseScenario();
  scenario.policies = [
    policy({
      namespace: "backend",
      name: "allow-all-in-namespace",
      podSelector: {},
      ingress: [{ from: [{ namespaceSelector: { matchLabels: { tier: "frontend" } } }] }],
    }),
  ];

  const result = simulatePath(scenario, serviceRequest());
  assert.equal(result.status, "allow");
  assert.ok(
    result.branches.every((branch) =>
      branch.hops.some(
        (hop) => hop.stage === "ingress" && hop.matchedRules[0]?.name === "allow-all-in-namespace",
      ),
    ),
  );
});

test("policy with omitted policyTypes still enables ingress and defaults egress", () => {
  const scenario = baseScenario();
  scenario.policies = [
    {
      namespace: "backend",
      name: "ingress-only-default-types",
      podSelector: { matchLabels: { app: "api" } },
      ingress: [
        { from: [{ namespaceSelector: { matchLabels: { tier: "frontend" } } }], ports: [{ port: 8080 }] },
      ],
    },
  ];

  const result = simulatePath(scenario, serviceRequest());
  const branch = result.branches[0];
  const egress = branch.hops.find((hop) => hop.stage === "egress");
  const ingress = branch.hops.find((hop) => hop.stage === "ingress");
  assert.equal(egress.policyApplies, false);
  assert.equal(ingress.policyApplies, true);
  assert.equal(ingress.decision, "allow");
});

test("direct pod IP destination with no policies is allowed", () => {
  const result = simulatePath(
    baseScenario(),
    serviceRequest({
      destinationService: undefined,
      destinationIp: "10.20.0.11",
      destinationPort: 8080,
    }),
  );
  assert.equal(result.status, "allow");
  assert.equal(result.route.kind, "ip");
});

test("named service port resolves to the translated container port", () => {
  const scenario = baseScenario();
  scenario.policies = [
    policy({
      name: "only-8080",
      podSelector: { matchLabels: { app: "api" } },
      ingress: [
        {
          from: [{ namespaceSelector: { matchLabels: { tier: "frontend" } } }],
          ports: [{ port: 8080, protocol: "TCP" }],
        },
      ],
    }),
  ];

  const result = simulatePath(
    scenario,
    serviceRequest({ destinationPort: "http" }),
  );
  assert.equal(result.status, "allow");
  assert.equal(result.route.servicePort, 80);
  for (const branch of result.branches) {
    assert.equal(branch.endpoint.targetPort, 8080);
    assert.equal(branch.hops[1].port, 8080);
  }
});

test("scenario object is not mutated across simulations", () => {
  const scenario = baseScenario();
  const snapshot = clone(scenario);
  simulatePath(scenario, serviceRequest());
  assert.deepEqual(scenario, snapshot);
});

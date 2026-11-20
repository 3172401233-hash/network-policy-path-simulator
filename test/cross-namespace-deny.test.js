import { test } from "node:test";
import assert from "node:assert/strict";

import { simulatePath } from "../src/index.js";
import { baseScenario, serviceRequest, policy } from "./helpers/fixtures.js";

test("cross namespace: ingress policy scoped to another namespace denies frontend traffic", () => {
  const scenario = baseScenario();
  scenario.policies = [
    policy({
      namespace: "backend",
      name: "allow-only-legacy-namespace",
      podSelector: { matchLabels: { app: "api" } },
      ingress: [
        {
          from: [{ namespaceSelector: { matchLabels: { tier: "legacy" } } }],
          ports: [{ port: 8080 }],
        },
      ],
    }),
  ];

  const result = simulatePath(scenario, serviceRequest());

  assert.equal(result.status, "deny");
  for (const branch of result.branches) {
    assert.equal(branch.result, "deny");
    const egress = branch.hops.find((hop) => hop.stage === "egress");
    const ingress = branch.hops.find((hop) => hop.stage === "ingress");
    assert.equal(egress.decision, "allow");
    assert.equal(ingress.decision, "deny");
    assert.deepEqual(ingress.blockingPolicies, ["backend/allow-only-legacy-namespace"]);
    assert.deepEqual(ingress.matchedRules, []);
  }
});

test("podSelector-only ingress peer cannot match pods outside the policy namespace", () => {
  const scenario = baseScenario();
  scenario.policies = [
    policy({
      namespace: "backend",
      name: "backend-internal-only",
      podSelector: { matchLabels: { app: "api" } },
      ingress: [
        {
          from: [{ podSelector: { matchLabels: { role: "client" } } }],
          ports: [{ port: 8080 }],
        },
      ],
    }),
  ];

  const result = simulatePath(scenario, serviceRequest());
  assert.equal(result.status, "deny");
  const ingress = result.branches[0].hops.find((hop) => hop.stage === "ingress");
  assert.equal(ingress.blockingPolicies[0], "backend/backend-internal-only");
});

test("empty ingress rule list isolates pods and denies everything", () => {
  const scenario = baseScenario();
  scenario.policies = [
    policy({
      namespace: "backend",
      name: "default-deny-ingress",
      podSelector: { matchLabels: { app: "api" } },
      policyTypes: ["Ingress"],
      ingress: [],
    }),
  ];

  const result = simulatePath(scenario, serviceRequest());
  assert.equal(result.status, "deny");
  const ingress = result.branches[0].hops.find((hop) => hop.stage === "ingress");
  assert.equal(ingress.policyApplies, true);
  assert.equal(ingress.decision, "deny");
});

test("egress allows the call but ingress still denies: path fails at the second hop", () => {
  const scenario = baseScenario();
  scenario.policies = [
    {
      namespace: "frontend",
      name: "web-egress-to-backend",
      podSelector: { matchLabels: { app: "web" } },
      policyTypes: ["Egress"],
      egress: [
        {
          to: [{ namespaceSelector: { matchLabels: { tier: "backend" } }, podSelector: { matchLabels: { app: "api" } } }],
          ports: [{ port: 8080, protocol: "TCP" }],
        },
      ],
    },
    {
      namespace: "backend",
      name: "default-deny-ingress",
      podSelector: { matchLabels: { app: "api" } },
      policyTypes: ["Ingress"],
      ingress: [],
    },
  ];

  const result = simulatePath(scenario, serviceRequest());

  assert.equal(result.status, "deny");
  for (const branch of result.branches) {
    const egress = branch.hops.find((hop) => hop.stage === "egress");
    const ingress = branch.hops.find((hop) => hop.stage === "ingress");
    assert.equal(egress.decision, "allow");
    assert.equal(egress.matchedRules[0].name, "web-egress-to-backend");
    assert.equal(ingress.decision, "deny");
    assert.deepEqual(ingress.blockingPolicies, ["backend/default-deny-ingress"]);
  }
});

test("egress default-deny stops the path before ingress is evaluated", () => {
  const scenario = baseScenario();
  scenario.policies = [
    {
      namespace: "frontend",
      name: "deny-all-egress",
      podSelector: { matchLabels: { app: "web" } },
      policyTypes: ["Egress"],
      egress: [],
    },
    {
      namespace: "backend",
      name: "allow-all-ingress",
      podSelector: { matchLabels: { app: "api" } },
      policyTypes: ["Ingress"],
      ingress: [{ from: [{ namespaceSelector: {} }] }],
    },
  ];

  const result = simulatePath(scenario, serviceRequest());
  assert.equal(result.status, "deny");
  for (const branch of result.branches) {
    assert.equal(branch.hops.length, 1);
    assert.equal(branch.hops[0].stage, "egress");
    assert.equal(branch.hops[0].decision, "deny");
    assert.deepEqual(branch.hops[0].blockingPolicies, ["frontend/deny-all-egress"]);
  }
});

test("union semantics: one of several policies allowing is sufficient per hop", () => {
  const scenario = baseScenario();
  scenario.policies = [
    policy({
      name: "deny-all",
      podSelector: { matchLabels: { app: "api" } },
      policyTypes: ["Ingress"],
      ingress: [],
    }),
    policy({
      name: "allow-frontend",
      podSelector: { matchLabels: { app: "api" } },
      policyTypes: ["Ingress"],
      ingress: [
        {
          from: [{ namespaceSelector: { matchLabels: { tier: "frontend" } } }],
          ports: [{ port: 8080 }],
        },
      ],
    }),
  ];

  const result = simulatePath(scenario, serviceRequest());
  assert.equal(result.status, "allow");
  const ingress = result.branches[0].hops.find((hop) => hop.stage === "ingress");
  assert.equal(ingress.matchedRules.length, 1);
  assert.equal(ingress.matchedRules[0].name, "allow-frontend");
  assert.deepEqual(ingress.blockingPolicies, ["backend/deny-all"]);
});

test("explicitly empty from list matches no peer and therefore denies", () => {
  const scenario = baseScenario();
  scenario.policies = [
    policy({
      name: "empty-from",
      podSelector: { matchLabels: { app: "api" } },
      ingress: [{ from: [], ports: [{ port: 8080 }] }],
    }),
  ];

  const result = simulatePath(scenario, serviceRequest());
  assert.equal(result.status, "deny");
  assert.equal(result.branches[0].hops[1].blockingPolicies[0], "backend/empty-from");
});

test("rule without a from section allows any peer subject to the port check", () => {
  const scenario = baseScenario();
  scenario.policies = [
    policy({
      name: "any-peer-8080",
      podSelector: { matchLabels: { app: "api" } },
      ingress: [{ ports: [{ port: 8080, protocol: "TCP" }] }],
    }),
  ];

  assert.equal(simulatePath(scenario, serviceRequest()).status, "allow");

  assert.throws(
    () => simulatePath(scenario, serviceRequest({ protocol: "UDP" })),
    (error) => error.code === "SERVICE_PORT_NOT_FOUND",
  );
});

test("named port inside a policy resolves against the selected pod", () => {
  const scenario = baseScenario();
  scenario.policies = [
    policy({
      name: "named-policy-port",
      podSelector: { matchLabels: { app: "api" } },
      ingress: [
        {
          from: [{ namespaceSelector: { matchLabels: { tier: "frontend" } } }],
          ports: [{ port: "http", protocol: "TCP" }],
        },
      ],
    }),
  ];

  assert.equal(simulatePath(scenario, serviceRequest()).status, "allow");

  const unknownName = baseScenario();
  unknownName.policies = [
    policy({
      name: "unknown-named-port",
      podSelector: { matchLabels: { app: "api" } },
      ingress: [
        {
          from: [{ namespaceSelector: { matchLabels: { tier: "frontend" } } }],
          ports: [{ port: "does-not-exist", protocol: "TCP" }],
        },
      ],
    }),
  ];
  assert.equal(simulatePath(unknownName, serviceRequest()).status, "deny");
});

import { test } from "node:test";
import assert from "node:assert/strict";

import { simulatePath, SimulationError, ERROR_CODES } from "../src/index.js";
import { baseScenario, serviceRequest } from "./helpers/fixtures.js";

test("unknown source pod is a configuration error", () => {
  assert.throws(
    () => simulatePath(baseScenario(), serviceRequest({ sourcePod: "missing" })),
    (error) => {
      assert.ok(error instanceof SimulationError);
      assert.equal(error.code, ERROR_CODES.UNKNOWN_SOURCE_POD);
      return true;
    },
  );
});

test("unknown namespace is a configuration error", () => {
  const scenario = baseScenario();
  scenario.namespaces.push({ name: "void", labels: {} });
  assert.throws(
    () =>
      simulatePath(scenario, serviceRequest({ sourceNamespace: "void", sourcePod: "web" })),
    (error) => error.code === ERROR_CODES.UNKNOWN_SOURCE_POD,
  );
});

test("unknown service is a configuration error", () => {
  assert.throws(
    () =>
      simulatePath(
        baseScenario(),
        serviceRequest({ destinationService: { namespace: "backend", name: "nope" } }),
      ),
    (error) => error.code === ERROR_CODES.UNKNOWN_SERVICE,
  );
});

test("service lookup by ClusterIP works and a wrong port reports a config error", () => {
  const good = simulatePath(
    baseScenario(),
    serviceRequest({
      destinationService: { namespace: "backend", name: "api", clusterIP: "172.16.0.100" },
    }),
  );
  assert.equal(good.route.service, "backend/api");

  assert.throws(
    () =>
      simulatePath(
        baseScenario(),
        serviceRequest({
          destinationService: { namespace: "backend", name: "api", clusterIP: "172.16.0.100" },
          destinationPort: 65000,
        }),
      ),
    (error) => error.code === ERROR_CODES.SERVICE_PORT_NOT_FOUND,
  );
});

test("malformed CIDR inside an ipBlock surfaces as INVALID_CIDR per branch", () => {
  const scenario = baseScenario();
  scenario.policies = [
    {
      namespace: "frontend",
      name: "broken-cidr",
      podSelector: { matchLabels: { app: "web" } },
      policyTypes: ["Egress"],
      egress: [{ to: [{ ipBlock: { cidr: "10.20.0.0/99" } }] }],
    },
  ];

  const result = simulatePath(scenario, serviceRequest());
  assert.equal(result.status, "error");
  for (const branch of result.branches) {
    assert.equal(branch.result, "error");
    assert.equal(branch.error.code, ERROR_CODES.INVALID_CIDR);
  }
});

test("malformed IP literal in the request is a configuration error", () => {
  assert.throws(
    () =>
      simulatePath(baseScenario(), {
        ...serviceRequest(),
        destinationService: undefined,
        destinationIp: "not-an-ip",
      }),
    (error) => error.code === ERROR_CODES.INVALID_IP,
  );
});

test("unsupported label selector operator is a configuration error", () => {
  const scenario = baseScenario();
  scenario.policies = [
    {
      namespace: "backend",
      name: "bad-operator",
      podSelector: {
        matchExpressions: [{ key: "app", operator: "Around", values: ["api"] }],
      },
      policyTypes: ["Ingress"],
      ingress: [],
    },
  ];
  assert.throws(
    () => simulatePath(scenario, serviceRequest()),
    (error) => error.code === ERROR_CODES.INVALID_SELECTOR,
  );
});

test("policy deny and configuration error are distinguishable by result shape", () => {
  const denyScenario = baseScenario();
  denyScenario.policies = [
    {
      namespace: "backend",
      name: "closed",
      podSelector: { matchLabels: { app: "api" } },
      policyTypes: ["Ingress"],
      ingress: [],
    },
  ];

  const denied = simulatePath(denyScenario, serviceRequest());
  assert.equal(denied.status, "deny");
  assert.equal(denied.error, undefined);
  assert.equal(denied.branches[0].hops[1].blockingPolicies[0], "backend/closed");
});

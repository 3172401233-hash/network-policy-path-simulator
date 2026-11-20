import { test } from "node:test";
import assert from "node:assert/strict";

import { simulatePath, parseIp, parseCidr, ipInCidr, matchesIpBlock } from "../src/index.js";
import { baseScenario, serviceRequest, policy } from "./helpers/fixtures.js";

test("ipBlock egress rule allows the endpoint CIDR and records the matched rule", () => {
  const scenario = baseScenario();
  scenario.policies = [
    {
      namespace: "frontend",
      name: "egress-to-pod-cidr",
      podSelector: { matchLabels: { app: "web" } },
      policyTypes: ["Egress"],
      egress: [
        {
          to: [{ ipBlock: { cidr: "10.20.0.0/16" } }],
          ports: [{ port: 8080 }],
        },
      ],
    },
  ];

  const result = simulatePath(scenario, serviceRequest());
  assert.equal(result.status, "allow");
  const egress = result.branches[0].hops[0];
  assert.equal(egress.stage, "egress");
  assert.equal(egress.matchedRules[0].kind, "ipBlock");
});

test("ipBlock except excludes a specific endpoint while the other stays allowed", () => {
  const scenario = baseScenario();
  scenario.policies = [
    {
      namespace: "frontend",
      name: "egress-with-exception",
      podSelector: { matchLabels: { app: "web" } },
      policyTypes: ["Egress"],
      egress: [
        {
          to: [{ ipBlock: { cidr: "10.20.0.0/16", except: ["10.20.0.11/32"] } }],
          ports: [{ port: 8080 }],
        },
      ],
    },
  ];

  const result = simulatePath(scenario, serviceRequest());
  assert.equal(result.status, "partial");

  const blocked = result.branches.find((branch) => branch.endpoint.ip === "10.20.0.11");
  const allowed = result.branches.find((branch) => branch.endpoint.ip === "10.20.0.12");
  assert.equal(blocked.result, "deny");
  assert.equal(blocked.hops[0].blockingPolicies[0], "frontend/egress-with-exception");
  assert.equal(allowed.result, "allow");
});

test("ingress ipBlock policy decides on the source IP", () => {
  const scenario = baseScenario();
  scenario.policies = [
    policy({
      name: "ingress-ip-block",
      podSelector: { matchLabels: { app: "api" } },
      ingress: [
        {
          from: [{ ipBlock: { cidr: "10.10.0.0/16" } }],
          ports: [{ port: 8080 }],
        },
      ],
    }),
  ];

  const allowed = simulatePath(scenario, serviceRequest());
  assert.equal(allowed.status, "allow");

  const deniedRequest = serviceRequest({
    destinationService: undefined,
    destinationIp: "10.20.0.11",
    destinationPort: 8080,
    sourceNamespace: "legacy",
    sourcePod: "old-web",
  });
  const denied = simulatePath(scenario, deniedRequest);
  assert.equal(denied.status, "deny");
  assert.equal(denied.branches[0].hops[1].blockingPolicies[0], "backend/ingress-ip-block");
});

test("IPv6: dual-stack service uses IPv6 endpoints when ipFamily=6", () => {
  const scenario = baseScenario();
  scenario.policies = [
    {
      namespace: "frontend",
      name: "v6-egress",
      podSelector: { matchLabels: { app: "web" } },
      policyTypes: ["Egress"],
      egress: [{ to: [{ ipBlock: { cidr: "fd00:20::/32" } }], ports: [{ port: 8080 }] }],
    },
    policy({
      name: "v6-ingress",
      podSelector: { matchLabels: { app: "api" } },
      ingress: [
        {
          from: [{ ipBlock: { cidr: "fd00:10::/32" } }],
          ports: [{ port: 8080 }],
        },
      ],
    }),
  ];

  const result = simulatePath(scenario, serviceRequest({ ipFamily: 6 }));
  assert.equal(result.status, "allow");
  for (const branch of result.branches) {
    assert.equal(branch.endpoint.family, 6);
    assert.match(branch.endpoint.ip, /^fd00:20::/);
    assert.equal(branch.hops[1].peerIp, "fd00:10::a");
  }
});

test("CIDR helpers cover IPv4, IPv6 compression and IPv4-mapped literals", () => {
  assert.equal(parseIp("10.0.0.1").family, 4);
  assert.equal(parseIp("fd00::1").family, 6);
  assert.equal(parseIp("::ffff:10.0.0.1").family, 4);

  assert.equal(ipInCidr("10.1.2.3", "10.0.0.0/8"), true);
  assert.equal(ipInCidr("11.1.2.3", "10.0.0.0/8"), false);
  assert.equal(ipInCidr("fd00::1", "fd00::/16"), true);
  assert.equal(ipInCidr("fd01::1", "fd00::/16"), false);
  assert.equal(ipInCidr("::ffff:10.0.0.5", "10.0.0.0/24"), true);

  assert.equal(matchesIpBlock("10.0.0.9", { cidr: "10.0.0.0/24", except: ["10.0.0.8/30"] }), false);
  assert.equal(parseCidr("fd00::/128").prefix, 128);
});

test("different IP families never match", () => {
  assert.equal(ipInCidr("fd00::1", "10.0.0.0/8"), false);
  assert.equal(ipInCidr("10.0.0.1", "fd00::/16"), false);
});

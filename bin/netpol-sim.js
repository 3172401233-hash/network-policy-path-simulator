#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { simulatePath } from "../src/index.js";
import { SimulationError } from "../src/errors.js";

async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h") || args.length === 0) {
    printUsage();
    process.exit(args.length === 0 ? 2 : 0);
  }

  let scenario;
  let request;

  if (args.length === 1) {
    const document = JSON.parse(await readFile(args[0], "utf8"));
    scenario = document.scenario ?? document;
    request = document.request;
  } else {
    scenario = JSON.parse(await readFile(args[0], "utf8"));
    request = JSON.parse(await readFile(args[1], "utf8"));
  }

  if (!request) {
    throw new Error("No request found: use a single file with {scenario, request} or pass two files");
  }

  const result = simulatePath(scenario, request);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

  const exitCode = {
    allow: 0,
    deny: 1,
    partial: 1,
    error: 2,
  }[result.status];
  process.exit(exitCode);
}

function printUsage() {
  process.stdout.write(
    [
      "Usage:",
      "  netpol-sim <scenario-request.json>",
      "  netpol-sim <scenario.json> <request.json>",
      "",
      "Exit codes: 0 allow | 1 deny/partial | 2 configuration error",
      "",
    ].join("\n"),
  );
}

main().catch((error) => {
  const body =
    error instanceof SimulationError
      ? { status: "error", error: { code: error.code, message: error.message }, details: error.details }
      : { status: "error", error: { code: "UNEXPECTED_ERROR", message: error.message } };
  process.stderr.write(`${JSON.stringify(body, null, 2)}\n`);
  process.exit(2);
});

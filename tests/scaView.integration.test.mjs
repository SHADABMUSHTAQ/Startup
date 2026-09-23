import assert from "node:assert/strict";
import { after, before, beforeEach, test } from "node:test";
import { join } from "node:path";

import { JSDOM } from "jsdom";
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { createServer } from "vite";

const dom = new JSDOM("<!doctype html><html><body><div id=\"root\"></div></body></html>", {
  url: "https://warsoc.test/dashboard",
});

globalThis.IS_REACT_ACT_ENVIRONMENT = true;
globalThis.window = dom.window;
globalThis.document = dom.window.document;
Object.defineProperty(globalThis, "navigator", { configurable: true, value: dom.window.navigator });
globalThis.HTMLElement = dom.window.HTMLElement;

let vite;
let ConfigurationAssessment;
let apiClient;
let root;

const flush = async () => {
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
};

const waitForText = async (textValue) => {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    if (document.body.textContent.includes(textValue)) return;
    await flush();
  }
  assert.fail(`Timed out waiting for UI text: ${textValue}`);
};

const renderView = async () => {
  root = createRoot(document.getElementById("root"));
  await act(async () => { root.render(React.createElement(ConfigurationAssessment)); });
  await flush();
};

before(async () => {
  vite = await createServer({
    configFile: join(process.cwd(), "tests", "vite.integration.config.mjs"),
    server: { middlewareMode: true },
    appType: "custom",
    logLevel: "silent",
  });
  ({ default: ConfigurationAssessment } = await vite.ssrLoadModule(
    "/src/assets/Pages/Compliance/ConfigurationAssessment.jsx",
  ));
  ({ default: apiClient } = await vite.ssrLoadModule("/src/api/apiClient.js"));
});

after(async () => {
  if (root) await act(async () => root.unmount());
  await vite.close();
  dom.window.close();
});

beforeEach(async () => {
  if (root) {
    await act(async () => root.unmount());
    root = null;
  }
  document.body.innerHTML = "<div id=\"root\"></div>";
});

test("configuration assessment renders tenant summary and failed endpoint controls", async () => {
  const calls = [];
  apiClient.get = async (url) => {
    calls.push(url);
    if (url === "/compliance/sca/summary") {
      return {
        data: {
          total_endpoints: 2,
          assessed_endpoints: 1,
          average_compliance_score: 80,
          compliant_endpoints: 1,
          at_risk_endpoints: 0,
          stale_endpoints: 0,
          endpoints: [
            { agent_id: "WARSOC_AGENT_01", status: "COMPLIANT", compliance_score: 80 },
            { agent_id: "WARSOC_AGENT_02", status: "NOT_ASSESSED", compliance_score: 0 },
          ],
        },
      };
    }
    assert.equal(url, "/compliance/sca/posture/WARSOC_AGENT_01");
    return {
      data: {
        agent_id: "WARSOC_AGENT_01",
        status: "COMPLIANT",
        freshness: "CURRENT",
        assessment_trust: "AGENT_REPORTED",
        benchmark: "CIS Windows Server 2022",
        scan_id: "scan-42",
        compliance_score: 80,
        last_scanned_at: "2026-09-21T00:00:00Z",
        summary: { passed: 4, failed: 1, not_applicable: 0 },
        findings: [{
          check_id: "10001",
          title: "Minimum password length",
          severity: "HIGH",
          cis_control: "1.1.1",
          rationale: "Weak passwords increase risk.",
          remediation: "Set the minimum password length to 14.",
        }],
      },
    };
  };

  await renderView();
  await waitForText("Minimum password length");

  assert.deepEqual(calls, [
    "/compliance/sca/summary",
    "/compliance/sca/posture/WARSOC_AGENT_01",
  ]);
  assert.match(document.body.textContent, /Agent Reported/i);
  assert.equal(document.body.textContent.includes("Wazuh"), false);
});

test("configuration assessment fails closed when the backend feature is disabled", async () => {
  apiClient.get = async () => {
    const error = new Error("disabled");
    error.response = { status: 503 };
    throw error;
  };

  await renderView();
  await waitForText("Configuration assessment is not enabled.");

  assert.equal(document.querySelector(".sca-posture"), null);
});

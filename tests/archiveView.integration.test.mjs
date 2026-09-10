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
Object.defineProperty(globalThis, "navigator", {
  configurable: true,
  value: dom.window.navigator,
});
globalThis.HTMLElement = dom.window.HTMLElement;
globalThis.Event = dom.window.Event;
globalThis.MouseEvent = dom.window.MouseEvent;
globalThis.FormData = dom.window.FormData;

let vite;
let ArchiveView;
let apiClient;
let useAuthStore;
let root;

const flush = async () => {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
};

const waitForText = async (textValue) => {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    if (document.body.textContent.includes(textValue)) return;
    await flush();
  }
  assert.fail(`Timed out waiting for UI text: ${textValue}`);
};

const renderArchive = async () => {
  const container = document.getElementById("root");
  root = createRoot(container);
  await act(async () => {
    root.render(React.createElement(ArchiveView));
  });
  await flush();
};

const requestRow = (status, index) => ({
  request_id: `ARR-${index}`,
  collections: [index % 2 ? "siem_cold_vault" : "security_alerts"],
  start_at: "2026-08-01T00:00:00Z",
  end_at: "2026-08-02T00:00:00Z",
  estimated_bytes: 458752,
  status,
});

before(async () => {
  vite = await createServer({
    configFile: join(process.cwd(), "tests", "vite.integration.config.mjs"),
    server: { middlewareMode: true },
    appType: "custom",
    logLevel: "silent",
  });
  ({ ArchiveView } = await vite.ssrLoadModule("/src/assets/Components/OperationsViews/OperationsViews.jsx"));
  ({ default: apiClient } = await vite.ssrLoadModule("/src/api/apiClient.js"));
  ({ useAuthStore } = await vite.ssrLoadModule("/src/store/authStore.js"));
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
  useAuthStore.setState({ role: "admin", user: { role: "admin" }, isAuthenticated: true });
});

test("archive view renders every lifecycle state and downloads only READY evidence", async () => {
  const statuses = [
    "PENDING_APPROVAL",
    "APPROVED",
    "PENDING_REHYDRATION",
    "READY",
    "FAILED",
    "REJECTED",
    "CANCELLED",
    "EXPIRED",
    "NEW_WORKER_STATE",
  ];
  apiClient.get = async (url) => url === "/auth/my-packs"
    ? { data: { compliance_packs: ["peca_forensic", "fbr_pos"] } }
    : { data: { items: statuses.map(requestRow) } };
  apiClient.post = async (url) => {
    assert.equal(url, "/archive-retrievals/ARR-3/download-links");
    return {
      data: {
        expires_at: "2026-09-10T18:00:00Z",
        items: [{
          archive_key: "archive-1",
          collection: "siem_cold_vault",
          bytes: 458752,
          url: "https://evidence.example.test/private/archive.json?sig=redacted",
        }],
      },
    };
  };

  await renderArchive();
  await waitForText("New Worker State");

  for (const label of [
    "Waiting for approval",
    "Accepted and queued",
    "Preparing secure archive",
    "Download available",
    "Retrieval failed",
    "Request rejected",
    "Request cancelled",
    "Download period ended",
  ]) assert.match(document.body.textContent, new RegExp(label));

  const downloadButtons = [...document.querySelectorAll("button")]
    .filter((button) => button.textContent.includes("Get download links"));
  assert.equal(downloadButtons.length, 1);
  await act(async () => {
    downloadButtons[0].dispatchEvent(new MouseEvent("click", { bubbles: true }));
  });
  await waitForText("Secure downloads are ready");

  const link = document.querySelector(".archive-downloads a");
  assert.equal(link.protocol, "https:");
  assert.equal(link.rel, "noopener noreferrer");
  assert.match(link.textContent, /Endpoint evidence \(448 KB\)/);
  assert.match(link.textContent, /Expires 2026-09-10 18:00:00Z/);
});

test("archive view blocks invalid and duplicate submissions before the API boundary", async () => {
  apiClient.get = async (url) => url === "/auth/my-packs"
    ? { data: { compliance_packs: [] } }
    : { data: { items: [] } };

  let postCount = 0;
  let resolvePost;
  apiClient.post = () => {
    postCount += 1;
    return new Promise((resolve) => { resolvePost = resolve; });
  };

  await renderArchive();
  await waitForText("No archive requests have been recorded.");
  const form = document.querySelector(".archive-form");
  form.elements.source.value = "logs";
  form.elements.start.value = "2026-08-01T00:00";
  form.elements.end.value = "2026-08-02T00:00";
  form.elements.reason.value = "short";

  await act(async () => {
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
  await waitForText("Enter a reason between 8 and 500 characters.");
  assert.equal(postCount, 0);

  form.elements.reason.value = "Authorized archive review";
  await act(async () => {
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
  assert.equal(postCount, 1);

  resolvePost({ data: {} });
  await waitForText("Archive request submitted.");
});

test("archive view rejects unsafe download URLs without rendering a link", async () => {
  apiClient.get = async (url) => url === "/auth/my-packs"
    ? { data: { compliance_packs: [] } }
    : { data: { items: [requestRow("READY", 1)] } };
  apiClient.post = async () => ({
    data: { items: [{ archive_key: "unsafe", url: "javascript:alert(1)" }] },
  });

  await renderArchive();
  await waitForText("Download available");
  const button = [...document.querySelectorAll("button")]
    .find((candidate) => candidate.textContent.includes("Get download links"));
  await act(async () => {
    button.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  });
  await waitForText("Secure download links are temporarily unavailable.");
  assert.equal(document.querySelector(".archive-downloads a"), null);
});

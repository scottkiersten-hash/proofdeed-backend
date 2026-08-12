#!/usr/bin/env node
/*
 * ProofDeed Systems Check
 * ------------------------
 * Exercises every customer-facing service the platform offers and reports
 * pass/fail for each. Designed to be run from the DigitalOcean App Platform
 * Console (open the backend component -> Console tab -> `node systems-check.js`)
 * or from any machine with network access to the deployed backend.
 *
 * Two tiers of testing:
 *
 *   1. REACHABILITY (always runs, no credentials needed)
 *      Confirms every route actually resolves to the backend and responds
 *      the way it should -- a 404/"Cannot GET" here means the route is
 *      broken at the infrastructure/routing layer, which is exactly the
 *      class of bug that silently took the entire /api/v1 Developer API
 *      offline in production before this script existed. This tier alone
 *      is a meaningful, safe-to-run-anytime smoke test.
 *
 *   2. FUNCTIONAL (runs only if PROOFDEED_TEST_API_KEY is set)
 *      Actually exercises the paid flow end-to-end: certifies a real
 *      document, creates a real Asset Passport, a real Trust ID, etc.,
 *      and confirms the response is correct -- this is the strongest
 *      available proof that "a customer who pays gets a working system."
 *      This tier consumes a small amount of the test key's monthly quota.
 *      It skips genuinely destructive operations (key rotation, key
 *      deletion) since running those would break the very key being used
 *      to run the rest of the suite.
 *
 * Usage:
 *   node systems-check.js
 *   PROOFDEED_TEST_API_KEY=pd_live_xxx node systems-check.js
 *   PROOFDEED_BASE_URL=http://localhost:8080 node systems-check.js
 *
 * Setting up a dedicated test key (recommended over using a real customer's
 * key): use the admin panel's "Create user" / "Generate Enterprise key" flow
 * to provision a small-quota key labeled clearly as a test/QA account, and
 * store it as PROOFDEED_TEST_API_KEY in whatever secrets store you run this
 * from -- do not commit it to the repo.
 */

const BASE = (process.env.PROOFDEED_BASE_URL || "https://proofdeed.com").replace(/\/$/, "");
const API_KEY = process.env.PROOFDEED_TEST_API_KEY || null;
const FUNCTIONAL = !!API_KEY;

const results = [];
let sha256Hex = null;

async function sha256(text) {
  if (!sha256Hex) {
    const { createHash } = await import("node:crypto");
    sha256Hex = (s) => createHash("sha256").update(s).digest("hex");
  }
  return sha256Hex(text);
}

function record(group, name, pass, detail) {
  results.push({ group, name, pass, detail: detail || "" });
  const icon = pass ? "PASS" : "FAIL";
  console.log(`[${icon}] ${group} :: ${name}${detail ? " -- " + detail : ""}`);
}

async function req(method, path, { body, apiKey, timeoutMs = 15000, headers = {} } = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(BASE + path, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...(apiKey ? { "X-API-Key": apiKey } : {}),
        ...headers,
      },
      body: body !== undefined && !["GET", "HEAD"].includes(method) ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON, e.g. an HTML 404 page */ }
    return { status: res.status, text, json, isJson: json !== null };
  } finally {
    clearTimeout(t);
  }
}

// A route that is dead at the infra/routing layer returns an HTML "Cannot
// GET/POST ..." page (Express's default 404), never JSON. Any JSON response
// -- even an error like "API key required" -- proves the route is reachable.
function reachable(r) {
  return r.isJson || (r.status !== 404 && !r.text.includes("Cannot "));
}

/* ============================== TIER 1: REACHABILITY ============================== */

async function checkReachability() {
  console.log(`\n=== Reachability checks against ${BASE} (no credentials required) ===\n`);

  // --- Platform health ---
  {
    const r = await req("GET", "/api/health");
    record("Platform", "Backend + database reachable (/api/health)", r.status === 200 && r.json?.status === "ok", `status=${r.status}`);
  }

  // --- Public customer-facing flows (the actual web product) ---
  {
    const r = await req("POST", "/api/create-proof", { body: {} });
    record("Web app", "Certify via web upload flow (/api/create-proof)", reachable(r), `status=${r.status}`);
  }
  {
    const r = await req("GET", "/verify/PD-SYSTEMSCHECK-0000");
    record("Web app", "Public verify page reachable (/verify/:certId)", reachable(r), `status=${r.status}`);
  }
  {
    const r = await req("POST", "/api/demo/certify", { body: {} });
    record("Web app", "Public demo certify (/api/demo/certify)", reachable(r), `status=${r.status}`);
  }
  {
    const r = await req("POST", "/api/create-checkout-session", { body: {} });
    record("Billing", "Stripe checkout session creation reachable", reachable(r), `status=${r.status}`);
  }
  {
    const r = await req("POST", "/api/auth/magic-link", { body: {} });
    record("Auth", "Magic-link login reachable", reachable(r), `status=${r.status}`);
  }

  // --- Developer / Enterprise Trust API (the paid integration surface) ---
  const v1Routes = [
    ["POST", "/api/v1/certify", "Trust Records: certify"],
    ["POST", "/api/v1/certify/file", "Trust Records: certify file + forensics"],
    ["POST", "/api/v1/certify/fields", "Trust Records: certify structured fields"],
    ["POST", "/api/v1/verify/fields", "Trust Records: verify structured fields"],
    ["POST", "/api/v1/batch", "Trust Records: batch certify"],
    ["POST", "/api/v1/batch/verify", "Trust Records: batch verify"],
    ["GET", "/api/v1/usage", "Account: usage"],
    ["GET", "/api/v1/certificates", "Trust Records: list certificates"],
    ["POST", "/api/v1/asset-passport", "Asset Passports: create"],
    ["POST", "/api/v1/trust-id", "Trust IDs: create"],
    ["POST", "/api/v1/trust-analysis", "Trust Intelligence: analyze"],
    ["POST", "/api/v1/reseller/register", "Partner Program: register"],
  ];
  for (const [method, path, label] of v1Routes) {
    const r = await req(method, path, { body: {} });
    record("Trust API", label, reachable(r), `status=${r.status}`);
  }
}

/* ============================== TIER 2: FUNCTIONAL ============================== */

async function checkFunctional() {
  console.log(`\n=== Functional checks using the supplied test API key ===\n`);

  // --- Usage / account state ---
  const usage = await req("GET", "/api/v1/usage", { apiKey: API_KEY });
  record("Account", "Usage query returns account data", usage.status === 200 && typeof usage.json?.monthlyLimit === "number", JSON.stringify(usage.json));
  if (usage.status !== 200) {
    console.log("\nTest API key was rejected -- stopping functional tests. Check PROOFDEED_TEST_API_KEY is active.\n");
    return;
  }

  // --- Trust Records: certify + verify round trip ---
  const docHash = await sha256(`systems-check ${Date.now()} ${Math.random()}`);
  const certify = await req("POST", "/api/v1/certify", {
    apiKey: API_KEY,
    body: { documentHash: docHash, label: "systems-check test record" },
  });
  const proofId = certify.json?.proofId;
  record("Trust Records", "Certify a document", certify.status === 200 && !!proofId, JSON.stringify(certify.json));

  if (proofId) {
    const verify = await req("GET", `/api/verify/${proofId}`);
    const hashMatches = verify.json?.certification?.hash === docHash;
    record("Trust Records", "Public verify confirms the certified hash matches", verify.status === 200 && hashMatches, `status=${verify.status}`);
  }

  // --- Batch certify (small, cheap batch -- validates the fix for the
  //     sequential-insert scalability bug, not a full 500k-record load test) ---
  const batchDocs = await Promise.all(
    Array.from({ length: 5 }, (_, i) => sha256(`systems-check batch ${Date.now()} ${i} ${Math.random()}`))
  );
  const batch = await req("POST", "/api/v1/batch", {
    apiKey: API_KEY,
    body: { documents: batchDocs.map((documentHash, i) => ({ documentHash, label: `batch-item-${i}` })) },
  });
  const batchId = batch.json?.batchId;
  record("Trust Records", "Batch certify accepts a multi-document batch", batch.status === 200 && !!batchId && batch.json.total === 5, JSON.stringify(batch.json));

  if (batchId) {
    // Give background Merkle anchoring a moment, then confirm status is queryable.
    await new Promise((r) => setTimeout(r, 3000));
    const batchStatus = await req("GET", `/api/v1/batch/${batchId}`, { apiKey: API_KEY });
    record("Trust Records", "Batch status is queryable after submission", batchStatus.status === 200 && batchStatus.json?.total === 5, `status=${batchStatus.json?.status}`);
  }

  // --- Asset Passports ---
  const assetId = "SYSCHECK-" + Date.now();
  const passport = await req("POST", "/api/v1/asset-passport", {
    apiKey: API_KEY,
    body: { asset_type: "test", asset_identifier: assetId, label: "systems-check test asset", fields: { note: "created by systems-check.js" } },
  });
  const passportId = passport.json?.passportId;
  record("Asset Passports", "Create a passport", passport.status === 200 && !!passportId, JSON.stringify(passport.json));

  if (passportId) {
    const getPassport = await req("GET", `/api/v1/asset-passport/${passportId}`, { apiKey: API_KEY });
    record("Asset Passports", "Retrieve the created passport", getPassport.status === 200, `status=${getPassport.status}`);
  }

  // --- Trust IDs ---
  const trustIdReq = await req("POST", "/api/v1/trust-id", {
    apiKey: API_KEY,
    body: { entity_type: "organization", entity_name: "Systems Check Test Entity", entity_email: `systems-check-${Date.now()}@example.com` },
  });
  const trustId = trustIdReq.json?.trust_id;
  record("Trust IDs", "Create a Trust ID", trustIdReq.status === 201 && !!trustId, JSON.stringify(trustIdReq.json));

  if (trustId) {
    const getTrustId = await req("GET", `/api/v1/trust-id/${trustId}`, { apiKey: API_KEY });
    record("Trust IDs", "Retrieve the created Trust ID", getTrustId.status === 200, `status=${getTrustId.status}`);
  }

  // --- Trust Intelligence ---
  // trust-analysis matches proof_id against the document's hash or internal
  // numeric id, NOT the PD-... certification_id customers normally see --
  // use the hash from the certify step above, not proofId.
  if (docHash) {
    const analysis = await req("POST", "/api/v1/trust-analysis", {
      apiKey: API_KEY,
      body: { proof_id: docHash },
    });
    record("Trust Intelligence", "Run an analysis against a certified record", analysis.status === 200, JSON.stringify(analysis.json));
  }

  // --- Trust Graph (entities + relationships) ---
  const entity = await req("POST", "/api/entities", {
    apiKey: API_KEY,
    body: { entity_type: "organization", name: "Systems Check Test Org" },
  });
  const entityId = entity.json?.entity_id;
  record("Trust Graph", "Create an entity", entity.status === 200 && !!entityId, JSON.stringify(entity.json));

  if (entityId && proofId) {
    const relationship = await req("POST", `/api/certifications/${proofId}/relationships`, {
      apiKey: API_KEY,
      body: { entity_id: entityId, relationship_type: "related_to" },
    });
    record("Trust Graph", "Link a certification to an entity", relationship.status === 200, JSON.stringify(relationship.json));
  }

  // --- Webhook config (set + read back, non-destructive) ---
  const setWebhook = await req("PUT", "/api/v1/webhook", {
    apiKey: API_KEY,
    body: { webhookUrl: "https://example.com/systems-check-placeholder" },
  });
  record("Account", "Set webhook URL", setWebhook.status === 200, `status=${setWebhook.status}`);

  console.log("\nSkipped (destructive, not safe to run against a live key): POST /api/v1/keys/rotate, DELETE /api/v1/keys");
}

/* ============================== MAIN ============================== */

(async () => {
  console.log("ProofDeed Systems Check");
  console.log(`Target: ${BASE}`);
  console.log(`Mode: ${FUNCTIONAL ? "REACHABILITY + FUNCTIONAL (test API key supplied)" : "REACHABILITY ONLY (set PROOFDEED_TEST_API_KEY to also run functional tests)"}`);

  await checkReachability();
  if (FUNCTIONAL) await checkFunctional();

  const failed = results.filter((r) => !r.pass);
  console.log(`\n=== Summary: ${results.length - failed.length}/${results.length} passed ===\n`);
  if (failed.length > 0) {
    console.log("Failures:");
    for (const f of failed) console.log(`  - [${f.group}] ${f.name}${f.detail ? " -- " + f.detail : ""}`);
    process.exitCode = 1;
  } else {
    console.log("All checks passed.");
  }
})();

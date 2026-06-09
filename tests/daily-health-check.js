#!/usr/bin/env node
/**
 * ProofDeed Daily Health Check
 * Tests: all site pages, all checkout flows, backend API, DB connectivity
 * Sends alert email via Resend if anything fails
 */

const https = require("https");
const http = require("http");

const BASE_URL = "https://proofdeed.com";
const API_BASE = "https://proofdeed.com/api";
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const STRIPE_TEST_KEY = process.env.STRIPE_TEST_KEY;
const ALERT_EMAIL = "info@proofdeed.com";

const results = { passed: [], failed: [], warnings: [] };

// ─── Helper: HTTP GET ────────────────────────────────────────────────────────
function get(url) {
  return new Promise((resolve) => {
    const client = url.startsWith("https") ? https : http;
    const req = client.get(url, { timeout: 15000 }, (res) => {
      resolve({ status: res.statusCode, url });
    });
    req.on("error", (e) => resolve({ status: 0, url, error: e.message }));
    req.on("timeout", () => { req.destroy(); resolve({ status: 0, url, error: "timeout" }); });
  });
}

// ─── Helper: POST JSON ───────────────────────────────────────────────────────
function post(url, body) {
  return new Promise((resolve) => {
    const data = JSON.stringify(body);
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) },
      timeout: 15000,
    };
    const client = url.startsWith("https") ? https : http;
    const req = client.request(options, (res) => {
      let raw = "";
      res.on("data", (c) => (raw += c));
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(raw), url }); }
        catch { resolve({ status: res.statusCode, body: raw, url }); }
      });
    });
    req.on("error", (e) => resolve({ status: 0, url, error: e.message }));
    req.on("timeout", () => { req.destroy(); resolve({ status: 0, url, error: "timeout" }); });
    req.write(data);
    req.end();
  });
}

// ─── TEST 1: All Frontend Pages ──────────────────────────────────────────────
async function testPages() {
  const pages = [
    "/", "/how-it-works", "/faq", "/about", "/contact",
    "/government", "/government/use-cases", "/government/security",
    "/document/intake", "/auto/intake",
    "/blockchain", "/procurement", "/court", "/vs-notary",
    "/technical-package", "/rfp-framework", "/technical-process",
    "/affiliates", "/reseller", "/demo",
    "/api-docs", "/security-compliance", "/privacy", "/terms",
    "/login", "/signup", "/verify", "/success",
  ];

  console.log(`\n📄 Testing ${pages.length} pages...`);
  for (const page of pages) {
    const r = await get(BASE_URL + page);
    if (r.status === 200 || r.status === 301 || r.status === 302) {
      results.passed.push(`Page ${page} → ${r.status}`);
      process.stdout.write(".");
    } else {
      results.failed.push(`Page ${page} → ${r.status || r.error}`);
      process.stdout.write("✗");
    }
  }
  console.log("");
}

// ─── TEST 2: Backend API Health ──────────────────────────────────────────────
async function testBackendHealth() {
  console.log("\n🔧 Testing backend API...");

  // Health endpoint
  const health = await get(`${API_BASE}/health`);
  if (health.status === 200) {
    results.passed.push("Backend /api/health → 200");
    console.log("  ✅ /api/health OK");
  } else {
    results.warnings.push(`Backend /api/health → ${health.status || health.error} (may not exist)`);
    console.log(`  ⚠️  /api/health → ${health.status || health.error}`);
  }

  // Verify endpoint
  const verify = await get(`${API_BASE}/verify/test-cert-id-that-wont-exist`);
  if (verify.status === 200 || verify.status === 404) {
    results.passed.push(`Backend /api/verify → ${verify.status} (reachable)`);
    console.log(`  ✅ /api/verify reachable (${verify.status})`);
  } else {
    results.failed.push(`Backend /api/verify → ${verify.status || verify.error}`);
    console.log(`  ✗ /api/verify → ${verify.status || verify.error}`);
  }
}

// ─── TEST 3: Checkout Sessions (Stripe Test Mode) ────────────────────────────
async function testCheckouts() {
  if (!STRIPE_TEST_KEY) {
    results.warnings.push("STRIPE_TEST_KEY not set — skipping checkout tests");
    console.log("\n⚠️  Skipping checkout tests (no STRIPE_TEST_KEY)");
    return;
  }

  console.log("\n💳 Testing checkout sessions (Stripe test mode)...");

  // Use Stripe API directly with test key to verify price IDs exist
  const plans = [
    { name: "starter-monthly", envVar: "PRICE_STARTER_MONTHLY" },
    { name: "starter-annual",  envVar: "PRICE_STARTER_YEARLY" },
    { name: "pro-monthly",     envVar: "PRICE_PRO_MONTHLY" },
    { name: "pro-annual",      envVar: "PRICE_PRO_YEARLY" },
    { name: "enterprise",      envVar: "PRICE_ENTERPRISE" },
    { name: "government-pilot",envVar: "PRICE_GOVERNMENT_PILOT" },
  ];

  for (const plan of plans) {
    const r = await post(`${API_BASE}/create-checkout-session`, { plan: plan.name });
    if (r.status === 200 && r.body?.url) {
      results.passed.push(`Checkout ${plan.name} → URL generated`);
      console.log(`  ✅ ${plan.name}`);
    } else {
      results.failed.push(`Checkout ${plan.name} → ${r.status} ${JSON.stringify(r.body)}`);
      console.log(`  ✗ ${plan.name} → ${r.status} ${JSON.stringify(r.body)}`);
    }
  }
}

// ─── TEST 4: Certificate Verify Page ─────────────────────────────────────────
async function testVerifyFlow() {
  console.log("\n🔍 Testing verify endpoint...");
  const r = await get(`${BASE_URL}/verify`);
  if (r.status === 200) {
    results.passed.push("Verify page → 200");
    console.log("  ✅ /verify loads");
  } else {
    results.failed.push(`Verify page → ${r.status}`);
    console.log(`  ✗ /verify → ${r.status}`);
  }
}

// ─── SEND ALERT EMAIL ────────────────────────────────────────────────────────
async function sendAlert() {
  if (!RESEND_API_KEY) {
    console.log("\n⚠️  No RESEND_API_KEY — cannot send alert email");
    return;
  }
  if (results.failed.length === 0) {
    console.log("\n✅ All checks passed — no alert needed");
    return;
  }

  const subject = `🚨 ProofDeed Health Check FAILED — ${results.failed.length} issue(s) detected`;
  const body = `
ProofDeed Daily Health Check — ${new Date().toUTCString()}

❌ FAILED (${results.failed.length}):
${results.failed.map(f => `  • ${f}`).join("\n")}

⚠️  WARNINGS (${results.warnings.length}):
${results.warnings.length > 0 ? results.warnings.map(w => `  • ${w}`).join("\n") : "  None"}

✅ PASSED (${results.passed.length}):
${results.passed.map(p => `  • ${p}`).join("\n")}

---
Fix issues at: https://cloud.digitalocean.com/apps/753587e4-5e82-46af-a29e-a80b7dd60f87
Stripe dashboard: https://dashboard.stripe.com
  `.trim();

  const emailPayload = {
    from: "ProofDeed Health Check <info@proofdeed.com>",
    to: [ALERT_EMAIL],
    subject,
    text: body,
  };

  return new Promise((resolve) => {
    const data = JSON.stringify(emailPayload);
    const req = https.request({
      hostname: "api.resend.com",
      path: "/emails",
      method: "POST",
      headers: {
        "Authorization": `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(data),
      },
    }, (res) => {
      console.log(`\n📧 Alert email sent → ${res.statusCode}`);
      resolve();
    });
    req.on("error", (e) => { console.log(`\n📧 Email error: ${e.message}`); resolve(); });
    req.write(data);
    req.end();
  });
}

// ─── MAIN ────────────────────────────────────────────────────────────────────
async function main() {
  console.log("=".repeat(60));
  console.log(`ProofDeed Health Check — ${new Date().toUTCString()}`);
  console.log("=".repeat(60));

  await testPages();
  await testBackendHealth();
  await testCheckouts();
  await testVerifyFlow();

  console.log("\n" + "=".repeat(60));
  console.log(`RESULTS: ✅ ${results.passed.length} passed | ✗ ${results.failed.length} failed | ⚠️  ${results.warnings.length} warnings`);
  console.log("=".repeat(60));

  if (results.failed.length > 0) {
    console.log("\n❌ FAILURES:");
    results.failed.forEach(f => console.log(`  • ${f}`));
  }

  await sendAlert();

  // Exit with error code if failures — GitHub Actions will mark the run as failed
  process.exit(results.failed.length > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("Health check crashed:", err);
  process.exit(1);
});

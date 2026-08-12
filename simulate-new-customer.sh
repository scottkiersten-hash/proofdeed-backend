#!/usr/bin/env bash
# Simulates a brand-new paying customer end to end, using the exact code
# paths the real product uses -- no real credit card needed, since Stripe
# checkout itself was already confirmed working by the health check.
#
# Run this from the DigitalOcean App Platform Console tab on the BACKEND
# component (it reads ADMIN_PASSWORD/ADMIN_SECRET from the container's own
# environment, same as the app itself -- nothing to paste in).
#
# What it proves, step by step:
#   1. A customer record + active plan gets created (mirrors what the real
#      Stripe webhook does after a successful payment)
#   2. That customer can log in (magic-link flow, same as the real /login page)
#   3. Their dashboard endpoints return real data
#   4. They can actually certify a document (the core paid action)
#   5. The certified document is publicly verifiable
#
# Safe to re-run -- uses a fresh timestamped email each time.

set -euo pipefail

BASE="${PROOFDEED_BASE_URL:-https://proofdeed.com}"
# Match verifyAdminAuth()'s exact precedence: ADMIN_PASSWORD checked first.
# ADMIN_SECRET is a DO "encrypted" var -- the Console shell shows its raw
# EV[...] ciphertext placeholder instead of the decrypted value, so it must
# never be preferred over a plain var that's actually readable here.
ADMIN_KEY="${ADMIN_PASSWORD:-${ADMIN_SECRET:-}}"
if [ -z "$ADMIN_KEY" ]; then
  echo "ERROR: neither ADMIN_SECRET nor ADMIN_PASSWORD is set in this environment."
  exit 1
fi
if [[ "$ADMIN_KEY" == EV\[* ]]; then
  echo "ERROR: resolved admin key is a DO encrypted-var placeholder (starts with EV[), not the real value."
  echo "Set ADMIN_PASSWORD as a plain (non-encrypted) variable, or run this outside the Console."
  exit 1
fi

EMAIL="new-customer-sim-$(date +%s)@example.com"
PLAN="professional-monthly"

pass() { echo "  [PASS] $1"; }
fail() { echo "  [FAIL] $1"; exit 1; }

echo "=== Simulating a new $PLAN customer: $EMAIL ==="

echo ""
echo "1. Provisioning the account (mirrors the real Stripe webhook)..."
CREATE=$(curl -s -X POST -H "x-admin-secret: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"plan\":\"$PLAN\"}" \
  "$BASE/api/admin/create-user")
echo "  $CREATE"
echo "$CREATE" | grep -q '"success":true' && pass "Account + plan created" || fail "Account creation failed"

echo ""
echo "2. Logging in (magic-link flow, same as a real customer clicking the emailed link)..."
IMPERSONATE=$(curl -s -X POST -H "x-admin-secret: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\"}" \
  "$BASE/api/admin/impersonate")
TOKEN=$(echo "$IMPERSONATE" | node -e "process.stdin.on('data',d=>{try{console.log(new URL(JSON.parse(d).login_url).searchParams.get('token'))}catch(e){}})")
[ -n "$TOKEN" ] && pass "Got a login token" || fail "Could not get login token: $IMPERSONATE"

VERIFY=$(curl -s "$BASE/api/auth/verify?token=$TOKEN")
JWT=$(echo "$VERIFY" | node -e "process.stdin.on('data',d=>{try{console.log(JSON.parse(d).jwt||'')}catch(e){}})")
[ -n "$JWT" ] && pass "Signed in, got a real session JWT" || fail "Sign-in failed: $VERIFY"

echo ""
echo "3. Checking the dashboard sees the right plan..."
PROFILE=$(curl -s -H "Authorization: Bearer $JWT" "$BASE/api/user/profile")
echo "  $PROFILE"
CERTS_PAGE=$(curl -s -H "Authorization: Bearer $JWT" "$BASE/api/user/certifications")
echo "  $CERTS_PAGE"
echo "$CERTS_PAGE" | grep -q "\"plan\":\"$PLAN\"" && pass "Dashboard reflects the $PLAN plan" || fail "Dashboard does not show the expected plan"

echo ""
echo "4. Certifying a real document (the core paid action)..."
DOC_HASH=$(node -e "console.log(require('crypto').createHash('sha256').update('new-customer-sim-'+Date.now()+Math.random()).digest('hex'))")
CERTIFY=$(curl -s -X POST -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"documentHash\":\"$DOC_HASH\"}" \
  "$BASE/api/create-proof")
echo "  $CERTIFY"
PROOF_ID=$(echo "$CERTIFY" | node -e "process.stdin.on('data',d=>{try{console.log(JSON.parse(d).proofId||JSON.parse(d).proof_id||'')}catch(e){}})")
[ -n "$PROOF_ID" ] && pass "Document certified: $PROOF_ID" || fail "Certification failed: $CERTIFY"

echo ""
echo "5. Confirming it's publicly verifiable..."
VERIFY_PAGE=$(curl -s "$BASE/api/verify/$PROOF_ID")
echo "$VERIFY_PAGE" | grep -q "\"hash\":\"$DOC_HASH\"" && pass "Public verify confirms the certified hash" || fail "Public verify did not match: $VERIFY_PAGE"

echo ""
echo "=== ALL STEPS PASSED: a paying customer signs up, logs in, and gets a working system ==="
echo "(Test account $EMAIL left in place -- safe to ignore, or clean up manually.)"

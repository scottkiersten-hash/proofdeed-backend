/**
 * ProofDeed AI Content Analysis
 *
 * A probabilistic heuristic for whether an image shows signs of AI
 * generation or digital manipulation. This is NOT a certified forensic
 * result and is NOT the same thing as forensics.js's document-metadata
 * checks (timestamp mismatches, edit history, authoring software) — that
 * system is deterministic and rule-based; this one is a model's
 * best-effort read of the pixels themselves, and must always be shown
 * as a supporting signal, never a guarantee.
 *
 * Two backends, tried in this order:
 *   1. Hive AI (thehive.ai) V3 "AI-Generated & Deepfake Content Detection" model —
 *      a purpose-built, trained classifier. Used only if HIVE_API_KEY (a V3 "Secret
 *      Key" from portal.thehive.ai > Service API Keys) is set. Request/response shape
 *      taken from Hive's own docs (docs.thehive.ai, Oct 2026) and unit-tested against
 *      their example response; not yet exercised with a live key. $6 per 1,000 images.
 *      A Hive failure means the image is reported as not checked; the admin test endpoint says why.
 *   2. Claude vision (Anthropic) — OFF by default because it costs far more per image.
 *      Only used if AI_CHECK_ALLOW_CLAUDE=true is set on purpose.
 *
 * Supported: JPEG, PNG (same image types forensics.js handles)
 */

import Anthropic from "@anthropic-ai/sdk";

const VALID_ASSESSMENTS = ["unlikely", "possible", "likely", "inconclusive"];

function detectImageType(buffer, mimetype) {
  if (mimetype === "image/jpeg" || (buffer[0] === 0xff && buffer[1] === 0xd8)) return "image/jpeg";
  if (mimetype === "image/png" || buffer.slice(0, 4).toString("hex") === "89504e47") return "image/png";
  return null;
}

// Hive scores the two generation classes (ai_generated / not_ai_generated) so they sum to 1,
// and separately scores "deepfake" for manipulated faces. Map the higher of the two relevant
// scores onto our 4-value scale.
function mapHiveScoreToAssessment(score) {
  if (score == null) return "inconclusive";
  if (score >= 0.85) return "likely";
  if (score >= 0.4) return "possible";
  return "unlikely";
}

// Exported only so it can be unit-tested against Hive's documented response.
export function parseHiveV3Response(json) {
  // V3 shape: { output: [ { classes: [ { class: "ai_generated", value: 0.02 }, ... ] } ] }
  const classes = json?.output?.[0]?.classes || [];
  const valueOf = (name) => {
    const c = classes.find((x) => x.class === name);
    return c && typeof c.value === "number" ? c.value : null;
  };
  const aiScore = valueOf("ai_generated");
  const deepfakeScore = valueOf("deepfake");

  // If the response has no ai_generated class, don't record an empty "hive" answer:
  // throw so the caller falls back to Claude.
  if (aiScore == null) {
    throw new Error("Hive response had no ai_generated class: " + JSON.stringify(json).slice(0, 200));
  }

  const worst = Math.max(aiScore, deepfakeScore ?? 0);
  let summary = `Hive's AI-content classifier scored this image ${(aiScore * 100).toFixed(1)}% likely to be AI-generated.`;
  if (deepfakeScore != null && deepfakeScore >= 0.4) {
    summary += ` It also scored ${(deepfakeScore * 100).toFixed(1)}% likely to contain a deepfaked face.`;
  }
  return { assessment: mapHiveScoreToAssessment(worst), summary, method: "hive" };
}

async function analyzeWithHive(buffer, imageType) {
  const hiveKey = process.env.HIVE_API_KEY;
  if (!hiveKey) return null;

  // Multipart upload with a "media" field, per Hive's V3 docs (limit 200MB; our own cap is 5MB).
  const form = new FormData();
  form.append("media", new Blob([buffer], { type: imageType }), imageType === "image/png" ? "image.png" : "image.jpg");

  const res = await fetch("https://api.thehive.ai/api/v3/hive/ai-generated-and-deepfake-content-detection", {
    method: "POST",
    headers: { Authorization: `Bearer ${hiveKey}` },
    body: form,
  });

  if (!res.ok) {
    throw new Error(`Hive API returned ${res.status}: ${(await res.text().catch(() => "")).slice(0, 200)}`);
  }

  return parseHiveV3Response(await res.json());
}

async function analyzeWithClaude(buffer, imageType) {
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  if (!anthropicKey) return null;

  const anthropic = new Anthropic({ apiKey: anthropicKey });
  const base64 = buffer.toString("base64");

  const message = await anthropic.messages.create({
    model: "claude-sonnet-5",
    max_tokens: 300,
    system:
      'You are a careful, calibrated visual reviewer helping assess whether an image shows visual signs of AI generation or digital manipulation. This is a probabilistic read of the pixels only — a separate, deterministic system already checks file metadata for tampering, so do not comment on metadata, timestamps, or file properties, only what you can see in the image itself. Respond with ONLY a JSON object: {"assessment": one of "unlikely"|"possible"|"likely"|"inconclusive", "summary": a one-to-two sentence plain-English explanation}. Use "inconclusive" whenever the image gives no clear visual signal either way — do not guess to sound confident. You will sometimes be wrong in either direction; this is a supporting signal for a human reviewer, never a certified determination. Respond with ONLY the JSON object, no other text.',
    messages: [
      {
        role: "user",
        content: [
          { type: "image", source: { type: "base64", media_type: imageType, data: base64 } },
          { type: "text", text: "Assess this image." },
        ],
      },
    ],
  });

  const raw = message.content?.[0]?.text || "{}";
  let parsed;
  try {
    parsed = JSON.parse(raw.trim().replace(/^```json\s*|\s*```$/g, ""));
    if (!VALID_ASSESSMENTS.includes(parsed.assessment) || typeof parsed.summary !== "string") {
      throw new Error("unexpected shape");
    }
  } catch {
    parsed = { assessment: "inconclusive", summary: "AI content analysis could not produce a valid reading for this image." };
  }

  return { assessment: parsed.assessment, summary: parsed.summary, method: "claude-vision" };
}

/**
 * analyzeImageForAIContent(buffer, mimetype)
 *
 * Returns null if the file isn't a supported image type, or if neither
 * backend is configured — callers should treat null as "not analyzed,"
 * not as a negative result.
 *
 * On success, returns:
 * {
 *   assessment: 'unlikely' | 'possible' | 'likely' | 'inconclusive',
 *   summary: string,
 *   method: 'hive' | 'claude-vision',
 *   analyzed_at: string,
 * }
 */
export async function analyzeImageForAIContent(buffer, mimetype, { debug = false } = {}) {
  const imageType = detectImageType(buffer, mimetype);
  if (!imageType) return null;

  // Hive is the check. Claude vision costs far more per image, so it only runs when
  // AI_CHECK_ALLOW_CLAUDE=true is set on purpose; by default a Hive problem means "not checked".
  const allowClaude = process.env.AI_CHECK_ALLOW_CLAUDE === "true" && !!process.env.ANTHROPIC_API_KEY;
  if (!process.env.HIVE_API_KEY && !allowClaude) return null;

  // 10MB matches the upload limit in server.js. Claude's vision API itself rejects over 5MB.
  if (buffer.length > 10 * 1024 * 1024) {
    return { assessment: "inconclusive", summary: "This image is over 10MB, which is too large for the AI check.", method: null, analyzed_at: new Date().toISOString() };
  }

  // With debug on (admin test endpoint only), say whether Hive was tried and why it failed,
  // so a bad key can't hide behind a fallback.
  let hiveNote = null;
  if (process.env.HIVE_API_KEY) {
    try {
      const hiveResult = await analyzeWithHive(buffer, imageType);
      if (hiveResult) return { ...hiveResult, analyzed_at: new Date().toISOString(), ...(debug ? { hive_attempted: true } : {}) };
    } catch (err) {
      console.error("[AIContentAnalysis] Hive failed:", err.message);
      hiveNote = err.message.slice(0, 300);
    }
  }
  const debugInfo = debug ? { hive_attempted: !!process.env.HIVE_API_KEY, hive_error: hiveNote } : {};

  if (allowClaude && buffer.length <= 5 * 1024 * 1024) {
    try {
      const claudeResult = await analyzeWithClaude(buffer, imageType);
      if (claudeResult) return { ...claudeResult, analyzed_at: new Date().toISOString(), ...debugInfo };
    } catch (err) {
      console.error("[AIContentAnalysis] Claude failed:", err.message);
    }
  }

  // The check was genuinely attempted but did not run. Say so rather than disappearing silently.
  return { assessment: "inconclusive", summary: "AI content analysis failed to run for this image.", method: null, analyzed_at: new Date().toISOString(), ...debugInfo };
}

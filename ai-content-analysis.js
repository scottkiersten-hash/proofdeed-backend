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
 *   1. Hive AI (thehive.ai) — a purpose-built, trained AI-content
 *      classifier. Only used if HIVE_API_KEY is set. UNVERIFIED as of
 *      this writing — built from Hive's published docs but never
 *      exercised against a real Hive account/API key. Needs a live
 *      test with a real key before being trusted in production.
 *   2. Claude vision (Anthropic) — a general-purpose model's calibrated
 *      opinion. Always available as long as ANTHROPIC_API_KEY is set
 *      (same key the rest of this app already uses). This is the
 *      verified, tested default.
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

// Hive's response uses a binary ai_generated/not_ai_generated class pair with
// a 0-1 score for whichever class it picked. Map that to our 4-value scale.
function mapHiveScoreToAssessment(aiGeneratedScore) {
  if (aiGeneratedScore == null) return "inconclusive";
  if (aiGeneratedScore >= 0.85) return "likely";
  if (aiGeneratedScore >= 0.4) return "possible";
  return "unlikely";
}

async function analyzeWithHive(buffer, imageType) {
  const hiveKey = process.env.HIVE_API_KEY;
  if (!hiveKey) return null;

  const form = new FormData();
  // Field name per Hive's docs ("Use this key to send a binary file through
  // a post request"); UNVERIFIED against a live account — if this field
  // name is wrong, Hive will reject the request and we fall back to Claude.
  form.append("media", new Blob([buffer], { type: imageType }));

  const res = await fetch("https://api.thehive.ai/api/v2/task/sync", {
    method: "POST",
    headers: { authorization: `token ${hiveKey}` },
    body: form,
  });

  if (!res.ok) {
    throw new Error(`Hive API returned ${res.status}: ${await res.text().catch(() => "")}`);
  }

  const json = await res.json();
  const classes = json?.status?.[0]?.response?.output?.[0]?.classes || [];
  const aiGeneratedClass = classes.find((c) => c.class === "ai_generated");

  return {
    assessment: mapHiveScoreToAssessment(aiGeneratedClass?.score),
    summary: aiGeneratedClass
      ? `Hive's AI-content classifier scored this image ${(aiGeneratedClass.score * 100).toFixed(1)}% likely to be AI-generated.`
      : "Hive's classifier returned a result that could not be interpreted.",
    method: "hive",
  };
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
export async function analyzeImageForAIContent(buffer, mimetype) {
  const imageType = detectImageType(buffer, mimetype);
  if (!imageType) return null;
  if (!process.env.HIVE_API_KEY && !process.env.ANTHROPIC_API_KEY) return null;

  // Claude's vision API rejects images over 5MB, and without this cap every
  // 5–10MB photo (most phone photos) would fail and come back "inconclusive".
  if (buffer.length > 5 * 1024 * 1024) {
    return { assessment: "inconclusive", summary: "This image is over 5MB, which is too large for the AI check.", method: null, analyzed_at: new Date().toISOString() };
  }

  if (process.env.HIVE_API_KEY) {
    try {
      const hiveResult = await analyzeWithHive(buffer, imageType);
      if (hiveResult) return { ...hiveResult, analyzed_at: new Date().toISOString() };
    } catch (err) {
      console.error("[AIContentAnalysis] Hive failed, falling back to Claude:", err.message);
    }
  }

  try {
    const claudeResult = await analyzeWithClaude(buffer, imageType);
    if (claudeResult) return { ...claudeResult, analyzed_at: new Date().toISOString() };
  } catch (err) {
    console.error("[AIContentAnalysis] Claude failed:", err.message);
  }

  // Both backends unavailable or failed, but analysis was genuinely
  // attempted — say so honestly rather than disappearing silently.
  return { assessment: "inconclusive", summary: "AI content analysis failed to run for this image.", method: null, analyzed_at: new Date().toISOString() };
}

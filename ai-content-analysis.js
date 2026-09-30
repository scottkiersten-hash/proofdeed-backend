/**
 * ProofDeed AI Content Analysis
 *
 * A probabilistic visual heuristic — Claude looks at an uploaded image and
 * gives a calibrated, honest opinion on whether it shows signs of AI
 * generation or digital manipulation. This is NOT a certified forensic
 * result and is NOT the same thing as forensics.js's document-metadata
 * checks (timestamp mismatches, edit history, authoring software) — that
 * system is deterministic and rule-based; this one is a general-purpose
 * vision model's best-effort read of the pixels themselves, and must
 * always be shown as a supporting signal, never a guarantee.
 *
 * Supported: JPEG, PNG (same image types forensics.js handles)
 */

import Anthropic from "@anthropic-ai/sdk";

const SUPPORTED_MIME = new Set(["image/jpeg", "image/png"]);

function detectImageType(buffer, mimetype) {
  if (mimetype === "image/jpeg" || (buffer[0] === 0xff && buffer[1] === 0xd8)) return "image/jpeg";
  if (mimetype === "image/png" || buffer.slice(0, 4).toString("hex") === "89504e47") return "image/png";
  return null;
}

/**
 * analyzeImageForAIContent(buffer, mimetype)
 *
 * Returns null if the file isn't a supported image type, or if
 * ANTHROPIC_API_KEY isn't configured — callers should treat null as
 * "not analyzed," not as a negative result.
 *
 * On success, returns:
 * {
 *   assessment: 'unlikely' | 'possible' | 'likely' | 'inconclusive',
 *   summary: string,
 *   analyzed_at: string,
 * }
 */
export async function analyzeImageForAIContent(buffer, mimetype) {
  const imageType = detectImageType(buffer, mimetype);
  if (!imageType) return null;

  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  if (!anthropicKey) return null;

  // Vision requests get expensive/slow on very large images — cap at 10MB,
  // consistent with typical multer upload limits elsewhere in this app.
  if (buffer.length > 10 * 1024 * 1024) {
    return {
      assessment: "inconclusive",
      summary: "Image too large to analyze for this check.",
      analyzed_at: new Date().toISOString(),
    };
  }

  try {
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
      if (!["unlikely", "possible", "likely", "inconclusive"].includes(parsed.assessment) || typeof parsed.summary !== "string") {
        throw new Error("unexpected shape");
      }
    } catch {
      parsed = { assessment: "inconclusive", summary: "AI content analysis could not produce a valid reading for this image." };
    }

    return {
      assessment: parsed.assessment,
      summary: parsed.summary,
      analyzed_at: new Date().toISOString(),
    };
  } catch (err) {
    console.error("[AIContentAnalysis] Error:", err.message);
    return {
      assessment: "inconclusive",
      summary: "AI content analysis failed to run for this image.",
      analyzed_at: new Date().toISOString(),
    };
  }
}

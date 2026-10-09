/**
 * Certified upload links.
 *
 * A signed-in customer (an adjuster, attorney, title agent...) creates a link and sends it to
 * someone. Whoever opens the link picks a photo or document; their browser fingerprints it and
 * the record lands in the customer's account the moment it is sent.
 *
 * ProofDeed does not store files, and this feature does not change that. The sender's browser
 * computes the fingerprint and only the fingerprint, a file name, and the sender's optional
 * name and note reach this server. Photos can optionally be sent a second time for the AI photo
 * check; that request is held in memory only, exactly like the check on a normal web upload.
 * The sender then passes the file itself to the requester (the page offers the phone's share
 * sheet), and the requester can confirm it is the same file at /verify.
 *
 * Tables: upload_links, upload_link_submissions (created in server.js on startup).
 */

import crypto from "crypto";
import rateLimit from "express-rate-limit";

const LINK_EXPIRY_DAYS = [1, 7, 14, 30];
const MAX_ACTIVE_LINKS_PER_ACCOUNT = 25;
const SITE = "https://proofdeed.com";

// Plain strings only, trimmed, no control characters, capped in length.
export function cleanText(value, max) {
  if (typeof value !== "string") return "";
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}

export function linkStatus(link, received, now = new Date()) {
  if (link.revoked_at) return "revoked";
  if (new Date(link.expires_at) <= now) return "expired";
  if (received >= link.max_uploads) return "full";
  return "open";
}

function newToken() {
  return crypto.randomBytes(16).toString("base64url");
}

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

export function registerUploadLinks(app, deps) {
  const { pool, upload, authenticateToken, sendEmail, logCertEvent, anchorToPolygon, analyzeImageForAIContent, saveContentCredentials, contentCredentialsView } = deps;

  const submitLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 20,
    message: { error: "Too many uploads from this connection. Please wait a while and try again." },
  });
  const lookupLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 60,
    message: { error: "Too many requests. Please wait and try again." },
  });
  const photoCheckLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 20,
    message: { error: "Too many photo checks from this connection. Please wait a while and try again." },
  });

  // How many more certifications the account can make this month. Mirrors /create-proof so a
  // link can never certify past what the owner's plan allows.
  async function ownerAllowance(userId, email) {
    const keyRes = await pool.query("SELECT plan, monthly_limit FROM api_keys WHERE email = $1 AND active = TRUE", [email]);
    const apiKey = keyRes.rows[0];
    const plan = apiKey?.plan || "starter";
    const limit = apiKey?.monthly_limit || 25;
    const usedRes = await pool.query(
      plan === "individual-onetime"
        ? "SELECT COUNT(*) FROM certifications WHERE user_id = $1"
        : "SELECT COUNT(*) FROM certifications WHERE user_id = $1 AND created_at > date_trunc('month', NOW())",
      [userId]
    );
    const used = parseInt(usedRes.rows[0].count, 10) || 0;
    return { plan, limit, used, remaining: Math.max(limit - used, 0), hasPlan: !!apiKey };
  }

  async function requesterName(link) {
    if (link.requester_name) return link.requester_name;
    const r = await pool.query("SELECT organization_name FROM api_keys WHERE email = $1", [link.owner_email]);
    return r.rows[0]?.organization_name || null;
  }

  /* ---------------------------- Owner: create, list, revoke ---------------------------- */

  app.post(["/api/upload-links", "/upload-links"], authenticateToken, async (req, res) => {
    try {
      const title = cleanText(req.body?.title, 100);
      if (!title) return res.status(400).json({ error: "Give the request a short title, for example \"Roof photos, claim 4471\"." });
      const instructions = cleanText(req.body?.instructions, 500);
      const requester = cleanText(req.body?.requester_name, 80);
      const days = LINK_EXPIRY_DAYS.includes(Number(req.body?.expires_in_days)) ? Number(req.body.expires_in_days) : 14;
      const maxUploads = Math.min(Math.max(parseInt(req.body?.max_uploads, 10) || 25, 1), 100);
      const aiCheck = req.body?.ai_check === false ? false : true;

      const userRes = await pool.query("SELECT id, email FROM users WHERE email = $1", [req.user.email]);
      const user = userRes.rows[0];
      if (!user) return res.status(401).json({ error: "User not found." });

      const allowance = await ownerAllowance(user.id, user.email);
      if (!allowance.hasPlan || allowance.plan === "individual-onetime") {
        return res.status(403).json({ error: "Upload links are included with the Professional, Business, Enterprise and Government plans." });
      }

      const active = await pool.query(
        "SELECT COUNT(*) FROM upload_links WHERE owner_user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()",
        [user.id]
      );
      if (parseInt(active.rows[0].count, 10) >= MAX_ACTIVE_LINKS_PER_ACCOUNT) {
        return res.status(400).json({ error: `You have ${MAX_ACTIVE_LINKS_PER_ACCOUNT} active links. Turn one off before making another.` });
      }

      const token = newToken();
      const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
      const ins = await pool.query(
        `INSERT INTO upload_links (token, owner_user_id, owner_email, title, instructions, requester_name, ai_check, max_uploads, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING id, token, title, instructions, requester_name, ai_check, max_uploads, expires_at, created_at`,
        [token, user.id, user.email, title, instructions || null, requester || null, aiCheck, maxUploads, expiresAt]
      );
      const link = ins.rows[0];
      res.json({ success: true, link: { ...link, url: `${SITE}/send/${link.token}`, status: "open", received: 0, submissions: [] } });
    } catch (err) {
      console.error("[UploadLinks] create error:", err);
      res.status(500).json({ error: "Internal server error." });
    }
  });

  app.get(["/api/upload-links", "/upload-links"], authenticateToken, async (req, res) => {
    try {
      const links = await pool.query(
        `SELECT l.id, l.token, l.title, l.instructions, l.requester_name, l.ai_check, l.max_uploads, l.expires_at, l.revoked_at, l.created_at,
                (SELECT COUNT(*) FROM upload_link_submissions s WHERE s.link_id = l.id) AS received
         FROM upload_links l
         JOIN users u ON u.id = l.owner_user_id
         WHERE u.email = $1
         ORDER BY l.created_at DESC
         LIMIT 100`,
        [req.user.email]
      );
      const ids = links.rows.map((l) => l.id);
      const subs = ids.length
        ? await pool.query(
            `SELECT s.link_id, s.certification_id, s.sender_name, s.sender_note, s.file_name, s.file_type, s.file_size, s.created_at,
                    c.polygon_tx, c.ai_content_assessment, c.ai_content_summary, c.content_credentials
             FROM upload_link_submissions s
             LEFT JOIN certifications c ON c.certification_id = s.certification_id
             WHERE s.link_id = ANY($1)
             ORDER BY s.created_at DESC
             LIMIT 1000`,
            [ids]
          )
        : { rows: [] };
      const byLink = new Map();
      for (const s of subs.rows) {
        const list = byLink.get(s.link_id) || [];
        if (list.length < 50) {
          const { content_credentials: cc, ...rest } = s;
          // Only what the list needs: whether a credential was found, and whether it declares AI.
          list.push({ ...rest, link_id: undefined, credentials_status: cc?.status || null, credentials_ai: !!cc?.ai_declared });
        }
        byLink.set(s.link_id, list);
      }
      res.json({
        links: links.rows.map((l) => {
          const received = parseInt(l.received, 10) || 0;
          return {
            id: l.id, title: l.title, instructions: l.instructions, requester_name: l.requester_name, ai_check: l.ai_check,
            max_uploads: l.max_uploads, expires_at: l.expires_at, revoked_at: l.revoked_at, created_at: l.created_at,
            url: `${SITE}/send/${l.token}`,
            status: linkStatus(l, received),
            received,
            submissions: byLink.get(l.id) || [],
          };
        }),
      });
    } catch (err) {
      console.error("[UploadLinks] list error:", err);
      res.status(500).json({ error: "Internal server error." });
    }
  });

  app.post(["/api/upload-links/:id/revoke", "/upload-links/:id/revoke"], authenticateToken, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!Number.isInteger(id)) return res.status(404).json({ error: "Link not found." });
      const r = await pool.query(
        `UPDATE upload_links SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE id = $1 AND owner_user_id = (SELECT id FROM users WHERE email = $2)
         RETURNING id`,
        [id, req.user.email]
      );
      if (r.rows.length === 0) return res.status(404).json({ error: "Link not found." });
      res.json({ success: true });
    } catch (err) {
      console.error("[UploadLinks] revoke error:", err);
      res.status(500).json({ error: "Internal server error." });
    }
  });

  /* ---------------------------- Sender: no account needed ---------------------------- */

  app.get(["/api/send/:token", "/send/:token"], lookupLimiter, async (req, res) => {
    try {
      const token = cleanText(req.params.token, 64);
      const r = await pool.query(
        `SELECT l.*, (SELECT COUNT(*) FROM upload_link_submissions s WHERE s.link_id = l.id) AS received
         FROM upload_links l WHERE l.token = $1`,
        [token]
      );
      const link = r.rows[0];
      if (!link) return res.status(404).json({ status: "not_found" });
      const received = parseInt(link.received, 10) || 0;
      const status = linkStatus(link, received);
      if (status === "revoked") return res.json({ status });
      res.json({
        status,
        title: link.title,
        instructions: link.instructions,
        requester: await requesterName(link),
        ai_check: link.ai_check,
        expires_at: link.expires_at,
      });
    } catch (err) {
      console.error("[UploadLinks] lookup error:", err);
      res.status(500).json({ error: "Internal server error." });
    }
  });

  app.post(["/api/send/:token/submit", "/send/:token/submit"], submitLimiter, async (req, res) => {
    const token = cleanText(req.params.token, 64);
    const hash = typeof req.body?.documentHash === "string" ? req.body.documentHash.toLowerCase() : "";
    if (!/^[0-9a-f]{64}$/.test(hash)) {
      return res.status(400).json({ error: "Invalid fingerprint." });
    }
    const fileName = cleanText(req.body?.fileName, 160);
    const fileType = cleanText(req.body?.fileType, 100);
    const fileSize = Number.isFinite(Number(req.body?.fileSize)) ? Math.max(0, Math.min(Math.floor(Number(req.body.fileSize)), 1e11)) : null;
    const senderName = cleanText(req.body?.senderName, 80);
    const senderNote = cleanText(req.body?.senderNote, 500);

    const client = await pool.connect();
    let committed = false;
    try {
      await client.query("BEGIN");
      // Lock the link row so two simultaneous uploads cannot both take the last slot.
      const lr = await client.query("SELECT * FROM upload_links WHERE token = $1 FOR UPDATE", [token]);
      const link = lr.rows[0];
      if (!link) { await client.query("ROLLBACK"); return res.status(404).json({ error: "This link is not valid." }); }

      const cnt = await client.query("SELECT COUNT(*) FROM upload_link_submissions WHERE link_id = $1", [link.id]);
      const received = parseInt(cnt.rows[0].count, 10) || 0;
      const status = linkStatus(link, received);
      if (status !== "open") {
        await client.query("ROLLBACK");
        const messages = {
          revoked: "This link has been turned off.",
          expired: "This link has expired.",
          full: "This link has already received all the files it accepts.",
        };
        return res.status(410).json({ error: messages[status] || "This link is not available.", status });
      }

      // Same file sent twice through the same link: return the first record instead of
      // certifying (and billing the owner for) it again.
      const dup = await client.query(
        `SELECT s.certification_id, s.created_at FROM upload_link_submissions s
         JOIN certifications c ON c.certification_id = s.certification_id
         WHERE s.link_id = $1 AND c.hash = $2 LIMIT 1`,
        [link.id, hash]
      );
      if (dup.rows[0]) {
        await client.query("ROLLBACK");
        return res.json({
          success: true,
          alreadyReceived: true,
          proofId: dup.rows[0].certification_id,
          timestamp: new Date(dup.rows[0].created_at).toISOString(),
          verifyUrl: `${SITE}/verify/${dup.rows[0].certification_id}`,
          requester: await requesterName(link),
          title: link.title,
          photoCheck: false,
        });
      }

      const allowance = await ownerAllowance(link.owner_user_id, link.owner_email);
      if (allowance.remaining <= 0) {
        await client.query("ROLLBACK");
        return res.status(429).json({ error: "This request can't accept files right now. Please let the person who sent you the link know.", status: "unavailable" });
      }

      const proofId = `PD-${Date.now()}${crypto.randomInt(10, 100)}`;
      const timestamp = new Date().toISOString();
      const receiptKey = crypto.randomBytes(16).toString("hex");

      await client.query(
        `INSERT INTO certifications (certification_id, hash, polygon_tx, user_id, label, created_at)
         VALUES ($1, $2, NULL, $3, $4, NOW())`,
        [proofId, hash, link.owner_user_id, fileName || link.title]
      );
      await client.query(
        `INSERT INTO upload_link_submissions (link_id, certification_id, sender_name, sender_note, file_name, file_type, file_size, receipt_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [link.id, proofId, senderName || null, senderNote || null, fileName || null, fileType || null, fileSize, receiptKey]
      );
      await client.query("COMMIT");
      committed = true;

      const isPhoto = /^image\/(jpeg|png)$/i.test(fileType);
      res.json({
        success: true,
        alreadyReceived: false,
        proofId,
        timestamp,
        verifyUrl: `${SITE}/verify/${proofId}`,
        requester: await requesterName(link),
        title: link.title,
        photoCheck: !!(link.ai_check && isPhoto),
        receiptKey,
      });

      // After the response: provenance events, anchoring, and a note to the owner.
      logCertEvent(proofId, "created", "Trust Record Created");
      logCertEvent(proofId, "received_via_link", `Received through upload link: ${link.title}`, { link_id: link.id });

      sendEmail({
        to: link.owner_email,
        subject: `New certified upload: ${link.title}`,
        text: [
          `${senderName || "Someone"} sent a file through your upload link "${link.title}".`,
          "",
          fileName ? `File: ${fileName}` : null,
          senderNote ? `Note: ${senderNote}` : null,
          `Trust ID: ${proofId}`,
          `Certified: ${new Date(timestamp).toUTCString()}`,
          "",
          "ProofDeed recorded the file's fingerprint and the time. ProofDeed does not hold the file itself:",
          "the sender was asked to send it to you directly. When it reaches you, check it at",
          `${SITE}/verify to confirm it is exactly the file that was certified.`,
          "",
          `Record: ${SITE}/verify/${proofId}`,
          `All your requests: ${SITE}/dashboard`,
          "",
          "ProofDeed",
        ].filter((l) => l !== null).join("\n"),
      }).catch(() => {});

      anchorToPolygon(hash).then(async (txHash) => {
        await pool.query("UPDATE certifications SET polygon_tx = $1 WHERE certification_id = $2", [txHash, proofId]);
        logCertEvent(proofId, "anchored", "Provenance Anchored", { tx: txHash });
      }).catch((err) => console.error("[UploadLinks] anchor failed for", proofId, err.message));
    } catch (err) {
      if (!committed) await client.query("ROLLBACK").catch(() => {});
      console.error("[UploadLinks] submit error:", err);
      if (!res.headersSent) res.status(500).json({ error: "Something went wrong. Please try again." });
    } finally {
      client.release();
    }
  });

  // The optional photo check for a file that was just sent. The browser sends the image a second
  // time with the receipt key it was given; we confirm the bytes are the exact file that was
  // fingerprinted, run the check, and store the result on the record. Nothing is kept.
  app.post(["/api/send/:token/photo-check", "/send/:token/photo-check"], photoCheckLimiter, upload.single("file"), async (req, res) => {
    try {
      const token = cleanText(req.params.token, 64);
      const certId = cleanText(req.body?.certId, 64);
      const receiptKey = cleanText(req.body?.receiptKey, 64);
      if (!req.file) return res.status(400).json({ error: "No image uploaded." });

      const r = await pool.query(
        `SELECT s.receipt_key, s.certification_id, l.ai_check, c.hash, c.ai_content_assessment
         FROM upload_link_submissions s
         JOIN upload_links l ON l.id = s.link_id
         JOIN certifications c ON c.certification_id = s.certification_id
         WHERE l.token = $1 AND s.certification_id = $2`,
        [token, certId]
      );
      const row = r.rows[0];
      if (!row || !receiptKey || !safeEqual(row.receipt_key, receiptKey)) {
        return res.status(404).json({ error: "Record not found." });
      }
      if (!row.ai_check) return res.json({ ai_content_analysis: null });
      if (row.ai_content_assessment) return res.json({ already_checked: true });

      const uploadedHash = crypto.createHash("sha256").update(req.file.buffer).digest("hex");
      if (uploadedHash !== row.hash) {
        return res.status(400).json({ error: "This image does not match the file that was certified." });
      }

      // The photo's Content Credentials are read here, with no outside service.
      const credentials = contentCredentialsView(await saveContentCredentials(row.certification_id, req.file.buffer));

      const result = await analyzeImageForAIContent(req.file.buffer, req.file.mimetype);
      if (!result) return res.json({ ai_content_analysis: null, content_credentials: credentials });
      // A check that could not run is shown but never written to the permanent record.
      if (!result.method) return res.json({ ai_content_analysis: { assessment: result.assessment, summary: result.summary, method: null }, content_credentials: credentials });

      await pool.query(
        `UPDATE certifications
         SET ai_content_assessment = $1, ai_content_summary = $2, ai_content_analyzed_at = $3, ai_content_method = $4
         WHERE certification_id = $5`,
        [result.assessment, result.summary, new Date(result.analyzed_at), result.method, row.certification_id]
      );
      logCertEvent(row.certification_id, "ai_content_analyzed", "AI Content Analysis Completed", { assessment: result.assessment });
      res.json({ ai_content_analysis: { assessment: result.assessment, summary: result.summary, method: result.method }, content_credentials: credentials });
    } catch (err) {
      console.error("[UploadLinks] photo check error:", err);
      res.status(500).json({ error: "Internal server error." });
    }
  });
}

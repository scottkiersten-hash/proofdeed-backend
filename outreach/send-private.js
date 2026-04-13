import { Resend } from 'resend';
import { readFileSync, writeFileSync } from 'fs';
import { parse } from 'csv-parse/sync';
import { fileURLToPath } from 'url';
import { randomBytes } from 'crypto';
import path from 'path';
import pg from 'pg';
import dotenv from 'dotenv';
dotenv.config({ path: path.join(path.dirname(fileURLToPath(import.meta.url)), '../.env') });

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const resend = new Resend(process.env.RESEND_API_KEY);

// Optional: connect to DB to store message IDs (skips gracefully if no DB_URL)
let pool = null;
if (process.env.DATABASE_URL) {
  const { Pool } = pg;
  pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
}

const csvFile = process.argv[2] || path.join(__dirname, 'contacts-auto.csv');
const contacts = parse(readFileSync(csvFile, 'utf8'), { columns: true, skip_empty_lines: true });

const attachment = {
  filename: 'ProofDeed-FRE901.pdf',
  content: readFileSync(path.join(__dirname, 'ProofDeed-FRE901.pdf')),
};

function buildSubject(contact) {
  return `Blockchain Document Certification for ${contact.company}`;
}

function buildEmail(contact) {
  const first = contact.name.split(' ')[0];
  const useCase = contact.use_case || '';
  return `Hi ${first},

I'm reaching out because ${contact.company}'s document workflow is a strong fit for what we've built at ProofDeed.

${useCase}

ProofDeed certifies documents at the moment of creation — a SHA-256 hash anchored permanently to the Polygon public blockchain — creating a tamper-evident, court-admissible timestamp that any court, auditor, regulator, or counterparty can verify independently, with no ongoing dependency on ProofDeed's servers.

What makes it relevant for ${contact.company}:

- Court-admissible under Federal Rules of Evidence Rule 901(b)(9) — the blockchain certification itself is authentication evidence
- No system replacement — one lightweight API call added to your existing workflow, nothing disrupted
- Scales to any volume — each document gets its own individual cryptographic Merkle proof
- Zero document storage — SHA-256 hashing is client-side, originals never leave your control
- Public verification — anyone can independently verify any certified document at verify.proofdeed.com

The liability protection alone makes this worth a look — a single disputed document or fraudulent record can cost far more than the entire implementation.

See it live in 2 minutes: proofdeed.com/demo

Or if you'd prefer a walkthrough — I'm happy to show you exactly how it integrates into your current stack over a quick 20-minute call.

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com
proofdeed.com

P.S. I've attached a one-page overview of how ProofDeed certifications satisfy Federal Rules of Evidence Rule 901 for court admissibility — same standard used in federal litigation.`;
}

async function sendOutreach() {
  const log = [];
  let sent = 0, failed = 0;

  console.log(`\nProofDeed Private Sector Outreach — ${contacts.length} contacts loaded\n`);

  for (const contact of contacts) {
    if (!contact.email) {
      console.log(`⚠️  SKIP  ${contact.name} (${contact.company}) — no email`);
      continue;
    }

    try {
      const subject = buildSubject(contact);
      const body = buildEmail(contact);
      const replyTag = randomBytes(8).toString('hex');

      const result = await resend.emails.send({
        from: 'Scott Kiersten <gov@send.proofdeed.com>',
        reply_to: `reply+${replyTag}@send.proofdeed.com`,
        to: contact.email,
        subject,
        text: body,
        attachments: [attachment],
        tags: [
          { name: 'campaign', value: 'private-outreach' },
          { name: 'industry', value: contact.industry || 'private' },
        ],
      });

      const messageId = result?.data?.id || result?.id || null;

      // Store in DB if available
      if (pool) {
        try {
          await pool.query(`
            INSERT INTO outreach_contacts (name, email, company, title, industry, status, reply_to_tag, resend_message_id, first_sent_at, last_contact_at)
            VALUES ($1,$2,$3,$4,$5,'sent',$6,$7,NOW(),NOW())
            ON CONFLICT (email) DO UPDATE SET
              resend_message_id = EXCLUDED.resend_message_id,
              reply_to_tag = COALESCE(outreach_contacts.reply_to_tag, EXCLUDED.reply_to_tag),
              status = CASE WHEN outreach_contacts.status = 'pending' THEN 'sent' ELSE outreach_contacts.status END,
              last_contact_at = NOW()
          `, [contact.name, contact.email, contact.company, contact.title || '', contact.industry || 'private', replyTag, messageId]);

          if (messageId) {
            const c = await pool.query('SELECT id FROM outreach_contacts WHERE email=$1', [contact.email]);
            if (c.rows[0]) {
              await pool.query(`
                INSERT INTO outreach_events (contact_id, event_type, event_source, metadata, occurred_at)
                VALUES ($1,'sent','send_script',$2,NOW())
              `, [c.rows[0].id, JSON.stringify({ resend_message_id: messageId, subject })]);
            }
          }
        } catch (dbErr) {
          console.warn(`  DB log skipped: ${dbErr.message}`);
        }
      }

      console.log(`✅ SENT   ${contact.name} (${contact.company}) → ${contact.email} [${messageId || 'no-id'}]`);
      log.push({ name: contact.name, company: contact.company, email: contact.email, subject, messageId, status: 'sent', timestamp: new Date().toISOString() });
      sent++;

      await new Promise(r => setTimeout(r, 3000));
    } catch (err) {
      console.error(`❌ FAIL   ${contact.name} (${contact.company}) — ${err.message}`);
      log.push({ name: contact.name, company: contact.company, email: contact.email, status: 'failed', error: err.message, timestamp: new Date().toISOString() });
      failed++;
    }
  }

  if (pool) await pool.end();

  const logFile = path.join(__dirname, `send-log-${Date.now()}.json`);
  writeFileSync(logFile, JSON.stringify(log, null, 2));

  console.log(`\n─────────────────────────────`);
  console.log(`✅ Sent:   ${sent}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`📄 Log:    ${logFile}`);
  console.log(`─────────────────────────────\n`);
}

sendOutreach();

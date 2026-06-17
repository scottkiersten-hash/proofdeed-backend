import pg from '/workspace/node_modules/pg/lib/index.js';
import { Resend } from 'resend';
import { readFileSync } from 'fs';
import { randomBytes } from 'crypto';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const resend = new Resend(process.env.RESEND_API_KEY);

const DAILY_CAP = 80;
const DELAY_MS = 4000;

const attachment = {
  filename: 'ProofDeed-FRE901.pdf',
  content: readFileSync(path.join(__dirname, 'ProofDeed-FRE901.pdf')),
};

function buildEmail(contact) {
  const first = (contact.name || '').split(' ')[0] || 'there';
  return `Hi ${first},

Quick question — does ${contact.company} have a way to prove a document hasn't been altered after it was signed?

Most organizations don't. We built ProofDeed to solve that — it adds a permanent blockchain timestamp to any document at the moment of creation, court-admissible under FRE Rule 901. One API call, nothing replaced, live in days.

Worth a 15-minute call?

Scott Kiersten
Founder, ProofDeed
gov@proofdeed.com`;
}

async function run() {
  const { rows: contacts } = await pool.query(
    `SELECT id, name, email, company, title, industry
     FROM outreach_contacts
     WHERE status = 'pending'
     ORDER BY created_at ASC
     LIMIT $1`,
    [DAILY_CAP]
  );

  console.log(`\nProofDeed Pending Outreach — ${contacts.length} contacts to send today\n`);

  let sent = 0, failed = 0;

  for (const contact of contacts) {
    try {
      const replyTag = randomBytes(8).toString('hex');
      const subject = `Blockchain Document Certification for ${contact.company}`;
      const body = buildEmail(contact);

      const result = await resend.emails.send({
        from: 'Scott Kiersten <gov@proofdeed.com>',
        reply_to: `reply+${replyTag}@proofdeed.com`,
        to: contact.email,
        subject,
        text: body,
        attachments: [attachment],
        tags: [
          { name: 'campaign', value: 'pending-outreach' },
          { name: 'industry', value: contact.industry || 'private' },
        ],
      });

      const messageId = result?.data?.id || result?.id || null;

      await pool.query(
        `UPDATE outreach_contacts
         SET status='sent', reply_to_tag=$1, resend_message_id=$2,
             first_sent_at=COALESCE(first_sent_at, NOW()), last_contact_at=NOW()
         WHERE id=$3`,
        [replyTag, messageId, contact.id]
      );

      console.log(`✅ SENT   ${contact.name} (${contact.company}) → ${contact.email}`);
      sent++;

      await new Promise(r => setTimeout(r, DELAY_MS));

    } catch (err) {
      console.error(`❌ FAIL   ${contact.name} (${contact.company}) — ${err.message}`);
      failed++;
    }
  }

  await pool.end();

  console.log(`\n─────────────────────────────`);
  console.log(`✅ Sent:   ${sent}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`─────────────────────────────\n`);
}

run();

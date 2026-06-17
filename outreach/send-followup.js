import { Resend } from 'resend';
import { readFileSync, writeFileSync } from 'fs';
import { parse } from 'csv-parse/sync';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const resend = new Resend(process.env.RESEND_API_KEY);

const csvFile = process.argv[2] || path.join(__dirname, 'contacts-followup1.csv');
const contacts = parse(
  readFileSync(csvFile, 'utf8'),
  { columns: true, skip_empty_lines: true }
);

const attachment = {
  filename: 'ProofDeed-FRE901.pdf',
  content: readFileSync('/Users/sjk/proofdeed-backend/outreach/ProofDeed-FRE901.pdf')
};

function buildFollowUp(contact) {
  const first = contact.name.split(' ')[0];
  return `Hi ${first},

Just following up on my note from last week.

I know this landed during a busy time — I'll keep it short. ProofDeed puts a permanent, court-admissible timestamp on any document your office records. One API call, no new systems, takes days to go live.

Is there a better person on your team to talk to, or would a quick 15-minute call work for you?

Scott Kiersten
Founder, ProofDeed
gov@proofdeed.com`;
}

async function sendFollowUps() {
  const log = [];
  let sent = 0, failed = 0;

  console.log(`\nProofDeed Follow-Up — ${contacts.length} contacts loaded\n`);

  for (const contact of contacts) {
    try {
      const body = buildFollowUp(contact);

      await resend.emails.send({
        from: 'Scott Kiersten <gov@proofdeed.com>',
        reply_to: 'gov@proofdeed.com',
        to: contact.email,
        subject: `Re: Blockchain Document Certification for ${contact.county} County`,
        text: body,
        attachments: [attachment],
      });

      console.log(`✅ SENT   ${contact.name} (${contact.county}) → ${contact.email}`);
      log.push({
        name: contact.name,
        county: contact.county,
        email: contact.email,
        status: 'sent',
        timestamp: new Date().toISOString()
      });
      sent++;

      await new Promise(r => setTimeout(r, 3000));

    } catch (err) {
      console.error(`❌ FAIL   ${contact.name} (${contact.county}) — ${err.message}`);
      log.push({
        name: contact.name,
        county: contact.county,
        email: contact.email,
        status: 'failed',
        error: err.message,
        timestamp: new Date().toISOString()
      });
      failed++;
    }
  }

  const logFile = path.join(__dirname, `followup-log-${Date.now()}.json`);
  writeFileSync(logFile, JSON.stringify(log, null, 2));

  console.log(`\n─────────────────────────────`);
  console.log(`✅ Sent:    ${sent}`);
  console.log(`❌ Failed:  ${failed}`);
  console.log(`📄 Log:     ${logFile}`);
  console.log(`─────────────────────────────\n`);
}

sendFollowUps();

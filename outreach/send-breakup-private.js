import { Resend } from 'resend';
import { readFileSync, writeFileSync } from 'fs';
import { parse } from 'csv-parse/sync';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const resend = new Resend(process.env.RESEND_API_KEY);

const csvFile = process.argv[2] || path.join(__dirname, 'contacts-auto.csv');
const contacts = parse(
  readFileSync(csvFile, 'utf8'),
  { columns: true, skip_empty_lines: true }
);

const attachment = {
  filename: 'ProofDeed-FRE901.pdf',
  content: readFileSync('/Users/sjk/proofdeed-backend/outreach/ProofDeed-FRE901.pdf')
};

function buildBreakup(contact) {
  const first = contact.name.split(' ')[0];
  return `Hi ${first},

I've sent a couple of notes and haven't heard back — I'll take that as not the right time and won't follow up again.

If anything changes or a document dispute ever comes up, we're at proofdeed.com.

Scott Kiersten
Founder, ProofDeed
gov@proofdeed.com`;
}

async function sendBreakups() {
  const log = [];
  let sent = 0, failed = 0;

  console.log(`\nProofDeed Day 21 Breakup — ${contacts.length} contacts loaded\n`);

  for (const contact of contacts) {
    try {
      const body = buildBreakup(contact);

      await resend.emails.send({
        from: 'Scott Kiersten <gov@send.proofdeed.com>',
        reply_to: 'gov@proofdeed.com',
        to: contact.email,
        subject: `Re: Blockchain Document Certification for ${contact.company}`,
        text: body,
        attachments: [attachment],
      });

      console.log(`✅ SENT   ${contact.name} (${contact.company}) → ${contact.email}`);
      log.push({
        name: contact.name,
        company: contact.company,
        email: contact.email,
        status: 'sent',
        timestamp: new Date().toISOString()
      });
      sent++;

      await new Promise(r => setTimeout(r, 3000));

    } catch (err) {
      console.error(`❌ FAIL   ${contact.name} (${contact.company}) — ${err.message}`);
      log.push({
        name: contact.name,
        company: contact.company,
        email: contact.email,
        status: 'failed',
        error: err.message,
        timestamp: new Date().toISOString()
      });
      failed++;
    }
  }

  const logFile = path.join(__dirname, `breakup-log-private-${Date.now()}.json`);
  writeFileSync(logFile, JSON.stringify(log, null, 2));

  console.log(`\n─────────────────────────────`);
  console.log(`✅ Sent:   ${sent}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`📄 Log:    ${logFile}`);
  console.log(`─────────────────────────────\n`);
}

sendBreakups();

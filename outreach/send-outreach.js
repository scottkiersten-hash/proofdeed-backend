import { Resend } from 'resend';
import { readFileSync, writeFileSync } from 'fs';
import { parse } from 'csv-parse/sync';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const resend = new Resend(process.env.RESEND_API_KEY);

const csvFile = process.argv[2] || path.join(__dirname, 'contacts.csv');
const contacts = parse(
  readFileSync(csvFile, 'utf8'),
  { columns: true, skip_empty_lines: true }
);

const attachment = {
  filename: 'ProofDeed-FRE901.pdf',
  content: readFileSync(path.join(__dirname, 'ProofDeed-FRE901.pdf'))
};

function buildEmail(contact) {
  const first = contact.name.split(' ')[0];
  return `Hi ${first},

${contact.opening}

ProofDeed certifies documents at the moment of recording — SHA-256 hash anchored permanently to the Polygon public blockchain — creating a tamper-evident, court-admissible timestamp that any court, auditor, or citizen can verify independently without contacting your office.

What's relevant for ${contact.county} County:

- Court-admissible under Federal Rules of Evidence Rule 901(b)(9) — the certification itself is authentication evidence
- No system replacement — one API call added to your existing recording workflow, nothing disrupted
- Any volume, one transaction — each document gets its own individual cryptographic Merkle proof
- Zero document storage — hashing is client-side, originals never leave your control
- Public verification — anyone can verify any document at verify.proofdeed.com, no account required

See it live in 2 minutes: proofdeed.com/demo

Or if you'd prefer a personal walkthrough, I'd be happy to connect for 20 minutes.

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com
proofdeed.com

P.S. I've attached a one-page overview of how ProofDeed certifications satisfy Federal Rules of Evidence Rule 901 for court admissibility.`;
}

async function sendOutreach() {
  const log = [];
  let sent = 0, skipped = 0, failed = 0;

  console.log(`\nProofDeed Outreach — ${contacts.length} contacts loaded\n`);

  for (const contact of contacts) {
    if (!contact.email || contact.email === 'WEBFORM') {
      console.log(`⚠️  SKIP  ${contact.name} (${contact.county}) — web form only, send manually`);
      log.push({ name: contact.name, county: contact.county, email: 'WEBFORM', status: 'skipped', reason: 'web form only' });
      skipped++;
      continue;
    }

    try {
      const body = buildEmail(contact);

      await resend.emails.send({
        from: 'Scott Kiersten <gov@proofdeed.com>',
        reply_to: 'gov@proofdeed.com',
        to: contact.email,
        subject: contact.subject,
        text: body,
        attachments: [attachment],
      });

      console.log(`✅ SENT   ${contact.name} (${contact.county}) → ${contact.email}`);
      log.push({
        name: contact.name,
        county: contact.county,
        email: contact.email,
        subject: contact.subject,
        status: 'sent',
        timestamp: new Date().toISOString()
      });
      sent++;

      // 3 second delay between sends — avoids spam triggers
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

  const logFile = path.join(__dirname, `send-log-${Date.now()}.json`);
  writeFileSync(logFile, JSON.stringify(log, null, 2));

  console.log(`\n─────────────────────────────`);
  console.log(`✅ Sent:    ${sent}`);
  console.log(`⚠️  Skipped: ${skipped} (web forms — send manually)`);
  console.log(`❌ Failed:  ${failed}`);
  console.log(`📄 Log:     ${logFile}`);
  console.log(`─────────────────────────────\n`);
}

sendOutreach();

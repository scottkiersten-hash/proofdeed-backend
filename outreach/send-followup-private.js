import { Resend } from 'resend';
import { readFileSync, writeFileSync } from 'fs';
import { parse } from 'csv-parse/sync';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const resend = new Resend(process.env.RESEND_API_KEY);

// Pass CSV file as argument, or defaults to auto
const csvFile = process.argv[2] || path.join(__dirname, 'contacts-auto.csv');
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

Following up on my note from last week about blockchain document certification for ${contact.company}.

Document fraud and post-transaction disputes are rising across every industry that handles high-value records — and organizations that have already anchored their document workflows to blockchain certification are in the strongest position to protect themselves and satisfy court admissibility requirements under FRE Rule 901.

ProofDeed requires no system replacement, integrates via a single lightweight API call, and can go live within days of a decision.

The liability exposure from a single disputed or fraudulent document typically dwarfs the entire cost of implementation — which is why this is usually an easy call for legal and compliance teams once they see how it works.

Would you have 20 minutes this week for a quick walkthrough? I'm flexible on timing.

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com
proofdeed.com

P.S. Attaching our FRE Rule 901 admissibility overview again for easy reference.`;
}

async function sendFollowUps() {
  const log = [];
  let sent = 0, failed = 0;

  console.log(`\nProofDeed Private Follow-Up — ${contacts.length} contacts loaded\n`);

  for (const contact of contacts) {
    try {
      const body = buildFollowUp(contact);

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

  const logFile = path.join(__dirname, `followup-log-private-${Date.now()}.json`);
  writeFileSync(logFile, JSON.stringify(log, null, 2));

  console.log(`\n─────────────────────────────`);
  console.log(`✅ Sent:   ${sent}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`📄 Log:    ${logFile}`);
  console.log(`─────────────────────────────\n`);
}

sendFollowUps();

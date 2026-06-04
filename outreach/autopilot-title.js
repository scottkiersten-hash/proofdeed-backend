/**
 * ProofDeed Outreach Autopilot — Title Companies & Real Estate Attorneys
 *
 * Usage: node outreach/autopilot-title.js [number_of_contacts]
 * Example: node outreach/autopilot-title.js 20
 *
 * Researches title companies and real estate attorneys, writes personalized
 * emails, and sends them automatically via Resend.
 */

import { Resend } from 'resend';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import Anthropic from '@anthropic-ai/sdk';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const resend = new Resend(process.env.RESEND_API_KEY);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const SENT_LOG = path.join(__dirname, 'sent-contacts-title.json');
const BATCH_SIZE = parseInt(process.argv[2]) || 20;
const TARGET_TYPE = process.argv[3] || 'mixed'; // 'title', 'attorney', or 'mixed'

function loadSentContacts() {
  if (existsSync(SENT_LOG)) {
    return JSON.parse(readFileSync(SENT_LOG, 'utf8'));
  }
  return [];
}

function saveSentContact(contact) {
  const sent = loadSentContacts();
  sent.push({ ...contact, timestamp: new Date().toISOString() });
  writeFileSync(SENT_LOG, JSON.stringify(sent, null, 2));
}

async function researchNewContacts(count, alreadySent) {
  const sentEmails = alreadySent.map(c => c.email).join(', ');

  const half = Math.floor(count / 2);
  const titleCount = TARGET_TYPE === 'attorney' ? 0 : TARGET_TYPE === 'title' ? count : half;
  const attorneyCount = count - titleCount;

  console.log(`\n🔍 Researching ${titleCount} title companies + ${attorneyCount} real estate attorneys...\n`);

  const response = await anthropic.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 5000,
    system: 'You are a research assistant. You respond ONLY with valid JSON arrays. No explanation, no markdown, no code blocks. Just the raw JSON array.',
    messages: [{
      role: 'user',
      content: `Find ${count} US contacts for ProofDeed outreach — a mix of title company owners/executives and real estate attorneys.

Do NOT include these already-contacted emails: ${sentEmails || 'none yet'}

Split approximately:
- ${titleCount} title company contacts (owners, presidents, VP of Operations, closing managers)
- ${attorneyCount} real estate attorney contacts (real estate law firm partners or solo practitioners)

Return a JSON array with exactly ${count} objects in this format:
[{
  "name": "First Last",
  "email": "email@company.com",
  "company": "Company Name",
  "city": "City",
  "state": "XX",
  "role": "Title/Role",
  "type": "title_company" or "real_estate_attorney",
  "angle": "One sentence why blockchain document certification solves a real problem they face"
}]

Rules:
- Real, confirmed business emails only (no info@ generics — find named person emails)
- Focus on companies that handle high document volumes or have faced fraud issues
- Spread across different states
- For title companies: focus on independent/regional companies (not huge nationals like First American)
- For attorneys: solo or small firm real estate attorneys are best — they feel pain more directly`
    }]
  });

  const text = response.content[0].text.trim();
  const jsonMatch = text.match(/\[[\s\S]*\]/);
  if (!jsonMatch) {
    console.error('Raw response:', text.substring(0, 500));
    throw new Error('No JSON found in research response');
  }
  return JSON.parse(jsonMatch[0]);
}

async function writeEmail(contact) {
  const isTitleCompany = contact.type === 'title_company';

  const response = await anthropic.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 600,
    messages: [{
      role: 'user',
      content: `Write a short, personalized cold outreach email from Scott Kiersten, Founder & CEO of ProofDeed, to ${contact.name}, ${contact.role} at ${contact.company} in ${contact.city}, ${contact.state}.

Why they are a good target: ${contact.angle}

${isTitleCompany ? `Context for title companies:
ProofDeed anchors closing documents to the Polygon blockchain at the moment they are executed — creating tamper-proof, independently verifiable proof of authenticity under FRE Rule 901. No system replacement. Works alongside your existing closing software. One API call per document. Title companies use it to protect against post-closing deed fraud and document alteration claims.` :
`Context for real estate attorneys:
ProofDeed creates court-admissible blockchain certificates for any document at the moment of signing — proving authenticity and timing under FRE Rule 901. Built specifically for the kind of document disputes real estate attorneys deal with: forged deeds, back-dated agreements, altered contracts. No system replacement — works via simple API or manual upload.`}

Requirements:
- Start with "Hi ${contact.name.split(' ')[0]},"
- Reference their specific situation or company in the opening line
- Keep it under 200 words total
- End with asking for a 20-minute call
- Sign off as Scott Kiersten, Founder & CEO, ProofDeed, info@proofdeed.com, proofdeed.com
- Add P.S. mentioning the attached FRE Rule 901 overview
- Plain text only, no markdown

Return only the email body, nothing else.`
    }]
  });

  return response.content[0].text.trim();
}

async function writeSubject(contact) {
  const response = await anthropic.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 100,
    messages: [{
      role: 'user',
      content: `Write a compelling email subject line for a cold outreach email to ${contact.name}, ${contact.role} at ${contact.company} about blockchain document certification for ${contact.type === 'title_company' ? 'title companies' : 'real estate attorneys'}.

Context: ${contact.angle}

Rules:
- Under 70 characters
- Reference their company or a real problem they face
- No clickbait or salesy language
- Return only the subject line, nothing else`
    }]
  });

  return response.content[0].text.trim().replace(/^["']|["']$/g, '');
}

async function sendEmail(contact, subject, body) {
  const attachment = {
    filename: 'ProofDeed-FRE901.pdf',
    content: readFileSync('/Users/sjk/proofdeed-backend/outreach/ProofDeed-FRE901.pdf')
  };

  await resend.emails.send({
    from: 'Scott Kiersten <info@send.proofdeed.com>',
    reply_to: 'info@proofdeed.com',
    to: contact.email,
    subject,
    text: body,
    attachments: [attachment],
  });
}

async function runAutopilot() {
  console.log(`\n🚀 ProofDeed Outreach Autopilot — Title Companies & Real Estate Attorneys`);
  console.log(`   Target: ${BATCH_SIZE} contacts | Mode: ${TARGET_TYPE}\n`);

  const alreadySent = loadSentContacts();
  console.log(`📋 ${alreadySent.length} contacts already in sent log\n`);

  let contacts;
  try {
    contacts = await researchNewContacts(BATCH_SIZE, alreadySent);
    console.log(`✅ Found ${contacts.length} new contacts\n`);
  } catch (err) {
    console.error(`❌ Research failed: ${err.message}`);
    process.exit(1);
  }

  let sent = 0, failed = 0;

  for (const contact of contacts) {
    try {
      const typeLabel = contact.type === 'title_company' ? '🏠 Title Co' : '⚖️  Attorney';
      console.log(`\n${typeLabel} | Writing email for ${contact.name} (${contact.company}, ${contact.state})...`);

      const [subject, body] = await Promise.all([
        writeSubject(contact),
        writeEmail(contact)
      ]);

      await sendEmail(contact, subject, body);

      saveSentContact({ ...contact, subject });

      console.log(`✅ SENT   ${contact.name} (${contact.company}) → ${contact.email}`);
      sent++;

      // 4 second delay between sends
      await new Promise(r => setTimeout(r, 4000));

    } catch (err) {
      console.error(`❌ FAIL   ${contact.name} (${contact.company}) — ${err.message}`);
      failed++;
    }
  }

  console.log(`\n─────────────────────────────`);
  console.log(`✅ Sent:   ${sent}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`─────────────────────────────\n`);
}

runAutopilot();

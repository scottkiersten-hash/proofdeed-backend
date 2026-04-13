/**
 * ProofDeed Outreach Autopilot
 *
 * Usage: node outreach/autopilot.js [number_of_contacts]
 * Example: node outreach/autopilot.js 20
 *
 * Researches new county recorder contacts, writes personalized emails,
 * and sends them automatically via Resend.
 */

import { Resend } from 'resend';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import Anthropic from '@anthropic-ai/sdk';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const resend = new Resend(process.env.RESEND_API_KEY);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const SENT_LOG = path.join(__dirname, 'sent-contacts.json');
const BATCH_SIZE = parseInt(process.argv[2]) || 20;

// Load previously sent contacts to avoid duplicates
function loadSentContacts() {
  if (existsSync(SENT_LOG)) {
    return JSON.parse(readFileSync(SENT_LOG, 'utf8'));
  }
  return [];
}

// Save sent contact to master log
function saveSentContact(contact) {
  const sent = loadSentContacts();
  sent.push({ ...contact, timestamp: new Date().toISOString() });
  writeFileSync(SENT_LOG, JSON.stringify(sent, null, 2));
}

// Research new contacts using Claude
async function researchNewContacts(count, alreadySent) {
  const sentCounties = alreadySent.map(c => `${c.county} ${c.state}`).join(', ');

  console.log(`\n🔍 Researching ${count} new county recorder contacts...\n`);

  const response = await anthropic.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 4000,
    system: 'You are a research assistant. You respond ONLY with valid JSON arrays. No explanation, no markdown, no code blocks. Just the raw JSON array.',
    messages: [{
      role: 'user',
      content: `Find ${count} US county recorder/register of deeds contacts for ProofDeed outreach. Do NOT include these already-contacted counties: ${sentCounties}

Return a JSON array with exactly ${count} objects in this format:
[{"name":"First Last","email":"confirmed@email.gov","county":"County Name","state":"XX","role":"Title","fraud_angle":"One sentence why they are a good target"}]

Rules: confirmed direct emails only, real names only, focus on deed fraud issues or large recording volumes, spread across different states.`
    }]
  });

  const text = response.content[0].text.trim();
  // Try to extract JSON array from response
  const jsonMatch = text.match(/\[[\s\S]*\]/);
  if (!jsonMatch) {
    console.error('Raw response:', text.substring(0, 500));
    throw new Error('No JSON found in research response');
  }
  return JSON.parse(jsonMatch[0]);
}

// Write personalized email using Claude
async function writeEmail(contact) {
  const response = await anthropic.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 600,
    messages: [{
      role: 'user',
      content: `Write a short, personalized cold outreach email from Scott Kiersten, Founder & CEO of ProofDeed, to ${contact.name}, ${contact.role} at ${contact.county} County, ${contact.state}.

Context about why they are a good target: ${contact.fraud_angle}

ProofDeed certifies documents at the moment of recording via SHA-256 hash anchored to Polygon blockchain. Court-admissible under FRE Rule 901. No system replacement. Any volume, one transaction. Each document gets its own Merkle proof.

Requirements:
- Start with "Hi ${contact.name.split(' ')[0]},"
- Reference their specific situation in the opening line
- Keep it under 200 words total
- End with asking for a 20-minute call
- Sign off as Scott Kiersten, Founder & CEO, ProofDeed, gov@proofdeed.com, proofdeed.com
- Add P.S. mentioning the attached FRE Rule 901 overview
- Plain text only, no markdown

Return only the email body, nothing else.`
    }]
  });

  return response.content[0].text.trim();
}

// Generate subject line using Claude
async function writeSubject(contact) {
  const response = await anthropic.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 100,
    messages: [{
      role: 'user',
      content: `Write a compelling email subject line for a cold outreach email to ${contact.name}, ${contact.role} at ${contact.county} County, ${contact.state} about blockchain document certification.

Context: ${contact.fraud_angle}

Rules:
- Under 70 characters
- Reference their specific situation or county
- No clickbait or salesy language
- Return only the subject line, nothing else`
    }]
  });

  return response.content[0].text.trim().replace(/^["']|["']$/g, '');
}

// Send email via Resend
async function sendEmail(contact, subject, body) {
  const attachment = {
    filename: 'ProofDeed-FRE901.pdf',
    content: readFileSync('/Users/sjk/proofdeed-backend/outreach/ProofDeed-FRE901.pdf')
  };

  await resend.emails.send({
    from: 'Scott Kiersten <gov@send.proofdeed.com>',
    reply_to: 'gov@proofdeed.com',
    to: contact.email,
    subject,
    text: body,
    attachments: [attachment],
  });
}

// Main autopilot function
async function runAutopilot() {
  console.log(`\n🚀 ProofDeed Outreach Autopilot — Target: ${BATCH_SIZE} contacts\n`);

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
      console.log(`\n📝 Writing email for ${contact.name} (${contact.county}, ${contact.state})...`);

      const [subject, body] = await Promise.all([
        writeSubject(contact),
        writeEmail(contact)
      ]);

      await sendEmail(contact, subject, body);

      saveSentContact({ ...contact, subject });

      console.log(`✅ SENT   ${contact.name} (${contact.county}) → ${contact.email}`);
      sent++;

      // 4 second delay between sends
      await new Promise(r => setTimeout(r, 4000));

    } catch (err) {
      console.error(`❌ FAIL   ${contact.name} (${contact.county}) — ${err.message}`);
      failed++;
    }
  }

  console.log(`\n─────────────────────────────`);
  console.log(`✅ Sent:   ${sent}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`─────────────────────────────\n`);
}

runAutopilot();

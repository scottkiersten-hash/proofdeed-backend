/**
 * One-time import: loads all sent contacts (gov + auto + institutional)
 * into the outreach_contacts table via the admin API.
 *
 * Usage:
 *   ADMIN_SECRET=your_secret node outreach/import-to-crm.js
 */

import { readFileSync } from 'fs';
import { parse } from 'csv-parse/sync';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const API = 'https://api.proofdeed.com';
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const ADMIN_TOTP   = process.env.ADMIN_TOTP || '';

if (!ADMIN_SECRET) {
  console.error('Set ADMIN_SECRET env var first.');
  process.exit(1);
}

const headers = {
  'Content-Type': 'application/json',
  'x-admin-secret': ADMIN_SECRET,
  'x-admin-totp': ADMIN_TOTP,
};

// Load government contacts from sent-contacts.json
const sentJson = JSON.parse(readFileSync(path.join(__dirname, 'sent-contacts.json'), 'utf8'));
const govContacts = sentJson.map((c) => ({
  name: c.name,
  email: c.email || '',
  company: c.county ? `${c.county} County Recorder` : '',
  county: c.county || '',
  state: c.state || '',
  industry: 'government',
  title: 'County Recorder',
}));

// Load auto industry contacts
const autoContacts = parse(readFileSync(path.join(__dirname, 'contacts-auto.csv'), 'utf8'), {
  columns: true, skip_empty_lines: true
}).map((c) => ({
  name: c.name,
  email: c.email || '',
  company: c.company || '',
  title: c.title || '',
  industry: 'auto',
  county: '',
  state: 'National',
}));

// Load institutional contacts
const instContacts = parse(readFileSync(path.join(__dirname, 'contacts-institutional.csv'), 'utf8'), {
  columns: true, skip_empty_lines: true
}).map((c) => ({
  name: c.name,
  email: c.email || '',
  company: c.company || '',
  title: c.title || '',
  industry: 'institutional',
  county: '',
  state: 'National',
}));

const allContacts = [...govContacts, ...autoContacts, ...instContacts];
console.log(`\nImporting ${allContacts.length} contacts (${govContacts.length} gov, ${autoContacts.length} auto, ${instContacts.length} institutional)…\n`);

const res = await fetch(`${API}/api/admin/outreach/import`, {
  method: 'POST',
  headers,
  body: JSON.stringify({ contacts: allContacts }),
});

const data = await res.json();
if (data.success) {
  console.log(`✅ Imported ${data.imported} contacts into CRM.`);
} else {
  console.error('❌ Import failed:', data.error);
}

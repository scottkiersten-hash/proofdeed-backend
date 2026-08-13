import { readFileSync } from 'fs';
import { parse } from 'csv-parse/sync';
import path from 'path';

const ADMIN_SECRET = process.env.PROOFDEED_ADMIN_SECRET;
if (!ADMIN_SECRET) {
  console.error('Set PROOFDEED_ADMIN_SECRET in the environment before running this script.');
  process.exit(1);
}
const API_URL = 'https://proofdeed.com/api/admin/outreach/import';

const CSV_FILES = [
  '/Users/sjk/Downloads/proofdeed_50_leads.csv',
  '/Users/sjk/Downloads/proofdeed_50_leads_batch2.csv',
  '/Users/sjk/Downloads/proofdeed_50_leads_batch3.csv',
  '/Users/sjk/Downloads/proofdeed_leads_archives.csv',
  '/Users/sjk/Downloads/proofdeed_leads_auto_oem.csv',
  '/Users/sjk/Downloads/proofdeed_leads_blockchain_tech.csv',
  '/Users/sjk/Downloads/proofdeed_leads_construction.csv',
  '/Users/sjk/Downloads/proofdeed_leads_global_insurance.csv',
  '/Users/sjk/Downloads/proofdeed_leads_global_law_firms.csv',
  '/Users/sjk/Downloads/proofdeed_leads_gov_regulators.csv',
  '/Users/sjk/Downloads/proofdeed_leads_healthcare.csv',
  '/Users/sjk/Downloads/proofdeed_leads_pharma.csv',
  '/Users/sjk/Downloads/proofdeed_leads_pharma_global.csv',
  '/Users/sjk/Downloads/proofdeed_leads_real_estate.csv',
  '/Users/sjk/Downloads/proofdeed_leads_universities.csv',
  '/Users/sjk/Downloads/proofdeed_named_executives_batch1.csv',
  '/Users/sjk/Downloads/proofdeed_named_executives_batch2.csv',
  '/Users/sjk/Downloads/proofdeed_named_executives_batch3.csv',
  '/Users/sjk/Downloads/proofdeed_named_executives_batch4.csv',
];

const seen = new Set();
const contacts = [];

for (const file of CSV_FILES) {
  const rows = parse(readFileSync(file, 'utf8'), { columns: true, skip_empty_lines: true });
  for (const r of rows) {
    const email = (r.email || '').trim().toLowerCase();
    if (!email || seen.has(email)) continue;
    seen.add(email);

    const firstName = (r.first_name || '').trim();
    const lastName = (r.last_name || '').trim();
    const name = [firstName, lastName].filter(Boolean).join(' ') || r.company || 'Contact';

    contacts.push({
      name,
      email,
      company: (r.company || '').trim(),
      title: (r.title || '').trim(),
      industry: (r.industry || 'private').trim(),
      state: (r.state || '').trim(),
    });
  }
}

console.log(`\n${contacts.length} unique contacts loaded from ${CSV_FILES.length} files\n`);

// Send in batches of 50
const BATCH_SIZE = 50;
let imported = 0;

for (let i = 0; i < contacts.length; i += BATCH_SIZE) {
  const batch = contacts.slice(i, i + BATCH_SIZE);
  const res = await fetch(API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-admin-secret': ADMIN_SECRET,
    },
    body: JSON.stringify({ contacts: batch }),
  });

  const data = await res.json();
  if (res.ok) {
    imported += data.imported || batch.length;
    console.log(`✅ Batch ${Math.floor(i/BATCH_SIZE)+1}: ${data.imported} imported`);
  } else {
    console.error(`❌ Batch ${Math.floor(i/BATCH_SIZE)+1} failed:`, data);
  }
}

console.log(`\n─────────────────────────────`);
console.log(`✅ Total imported: ${imported}`);
console.log(`─────────────────────────────\n`);

#!/usr/bin/env node
// import_50_leads.js
// Sends outreach emails to 50 targeted B2B leads and records them in the CRM.
//
// REQUIRES:
//   RESEND_API_KEY  — already in .env
//   ADMIN_SECRET    — from DigitalOcean App Platform → urchin-app → Settings → Environment Variables
//
// RUN:
//   ADMIN_SECRET=<paste_from_do> node import_50_leads.js
//
require('dotenv').config();
const https = require('https');
const crypto = require('crypto');

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const ADMIN_SECRET   = process.env.ADMIN_SECRET;
const PROD_HOST      = 'proofdeed.com';
const DAILY_CAP      = 80;

if (!RESEND_API_KEY) { console.error('Missing RESEND_API_KEY'); process.exit(1); }
if (!ADMIN_SECRET)   { console.error('Missing ADMIN_SECRET — get it from DigitalOcean App Platform → urchin-app → Settings → Environment Variables'); process.exit(1); }

// ── Email Templates ──────────────────────────────────────────────────────────

const RECORDER_EMAIL = (first) => `Hi ${first},

When a recorded document gets challenged — contested deed, disputed filing, chain-of-title dispute — your office has to prove it. The question isn't whether it's in your system. It's whether you can prove it hasn't been altered.

ProofDeed anchors documents to the Polygon blockchain at the moment of recording. Every document gets a tamper-proof, timestamped certificate that satisfies FRE Rule 901 in court. No system replacement. No document storage. No IT required. Works alongside your existing workflow — live in days, under $1 per recording.

Several county offices are using this to get ahead of fraud liability before it becomes a headline.

See it in 2 minutes: proofdeed.com/demo

Would a 20-minute call this week make sense?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
gov@proofdeed.com | proofdeed.com`;

const TITLE_EMAIL = (first) => `Hi ${first},

Every real estate closing generates documents that can be disputed years later — deeds, settlement statements, wire instructions. The problem most agencies don't realize: standard PDFs can be altered after signing without triggering any alert, making it impossible to prove what was in the document at the moment of closing.

ProofDeed anchors every closing document to the Polygon blockchain the instant it's processed — buyer name, sale price, legal description, recording date, all individually locked. If a single field is ever changed, it's immediately detectable. Buyers get a public verification link. You get court-admissible proof under FRE Rule 901.

No software to install. No IT required. Works alongside your existing closing platform. Under $1 per file, live in a day.

See it in 2 minutes: proofdeed.com/demo

Worth a 20-minute call this week?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

const LEGAL_EMAIL = (first) => `Hi ${first},

With AI editing tools and deepfake technology now capable of altering signed documents without a trace, proving the exact date and authenticity of a deed, will, or trust in court has become a serious liability for estate and real estate attorneys.

The most damaging thing opposing counsel can do is allege a document was altered after creation — and if you can't prove otherwise independently, you're defending the document instead of the case.

ProofDeed creates an immutable chain of custody for your firm's documents — party names, dates, amounts, terms — each individually hashed on the Polygon blockchain at the moment of creation. Documents become self-authenticating under FRE Rule 901. If opposing counsel claims anything was changed after signing, you prove it in seconds.

No system changes. No IT required. Under $1 per document.

See it in 2 minutes: proofdeed.com/demo

Would 20 minutes make sense?

Best,
Scott Kiersten
Founder & CEO, ProofDeed
info@proofdeed.com | proofdeed.com`;

// ── Lead Data ─────────────────────────────────────────────────────────────────

const SEGMENT1 = [
  { name: 'Stephen Richer',       company: "Maricopa County Recorder's Office", email: 'recorder@maricopa.gov',           title: 'County Recorder',           state: 'AZ', county: 'Maricopa' },
  { name: 'Karen A. Yarbrough',   company: "Cook County Clerk's Office",         email: 'clerk.yarbrough@cookcountyil.gov', title: 'County Clerk',              state: 'IL', county: 'Cook' },
  { name: 'Teneshia Hudspeth',    company: "Harris County Clerk's Office",        email: 'hccerts@cc.hctx.net',            title: 'County Clerk',              state: 'TX', county: 'Harris' },
  { name: 'John F. Warren',       company: "Dallas County Clerk's Office",        email: 'ccclerk@dallascounty.org',       title: 'County Clerk',              state: 'TX', county: 'Dallas' },
  { name: 'Hugh Nguyen',          company: 'Orange County Clerk-Recorder',        email: 'recorder@ocgov.com',             title: 'Clerk-Recorder',            state: 'CA', county: 'Orange' },
  { name: 'Juan Fernandez-Barquin', company: 'Miami-Dade County Clerk of Courts', email: 'clerk.courts@miamidade.gov',    title: 'Clerk & Comptroller',       state: 'FL', county: 'Miami-Dade' },
  { name: 'Debbie Conway',        company: "Clark County Recorder's Office",      email: 'RecWeb@ClarkCountyNV.gov',       title: 'County Recorder',           state: 'NV', county: 'Clark' },
  { name: 'Jon Scholes',          company: "King County Recorder's Office",       email: 'kcref@kingcounty.gov',           title: 'Records Manager',           state: 'WA', county: 'King' },
  { name: 'Bernard J. Youngblood', company: 'Wayne County Register of Deeds',    email: 'rodhelpdesk@waynecounty.com',    title: 'Register of Deeds',         state: 'MI', county: 'Wayne' },
  { name: 'Lucy Adame-Clark',     company: "Bexar County Clerk's Office",         email: 'countyclerk@bexar.org',          title: 'County Clerk',              state: 'TX', county: 'Bexar' },
  { name: 'Ché Alexander',        company: 'Fulton County Clerk of Superior Court', email: 'fulton.clerk@fultoncountyga.gov', title: 'Clerk',                  state: 'GA', county: 'Fulton' },
  { name: 'Brenda D. Forman',     company: 'Broward County Records Division',     email: 'clkinfo@browardclerk.org',       title: 'Clerk',                     state: 'FL', county: 'Broward' },
  { name: 'Cindy Stuart',         company: 'Hillsborough County Clerk',           email: 'hillsclerk@hillsclerk.com',      title: 'Clerk of Court',            state: 'FL', county: 'Hillsborough' },
  { name: "Danny O'Connor",       company: 'Franklin County Recorder',            email: 'recorder@franklincountyohio.gov', title: 'County Recorder',          state: 'OH', county: 'Franklin' },
  { name: 'Martin Long',          company: 'Hennepin County Recorder',            email: 'recorder@hennepin.us',           title: 'County Recorder',           state: 'MN', county: 'Hennepin' },
  { name: 'Michael Chambers',     company: 'Cuyahoga County Fiscal Officer',      email: 'fiscalclerk@cuyahogacounty.us',  title: 'Fiscal Officer / Records',  state: 'OH', county: 'Cuyahoga' },
];

const SEGMENT2 = [
  { name: 'Aaron Davis',          company: 'Florida Agency Network',              email: 'adavis@flagency.net',            title: 'CEO',                       state: 'FL' },
  { name: 'Jay Southworth',       company: 'Independence Title',                  email: 'jsouthworth@indytitle.com',      title: 'Managing Director',         state: 'TX' },
  { name: 'John Obzud',           company: 'Chicago Title Company',               email: 'john.obzud@ctt.com',             title: 'Executive VP',              state: 'IL' },
  { name: 'David J. S. Landis',   company: 'Universal Title',                     email: 'dlandis@universaltitle.com',     title: 'Principal',                 state: 'VA' },
  { name: 'Tami Bonnell',         company: 'Title Forward',                       email: 'info@titleforward.com',          title: 'Operations Lead',           state: 'PA' },
  { name: 'David V. Gagliano',    company: 'Alliant National Title Insurance',    email: 'dgagliano@alliantnational.com',  title: 'Chief Information Officer', state: 'CO' },
  { name: 'Mark Myers',           company: 'Meridian Title Corporation',          email: 'mmyers@meridiantitle.com',       title: 'President',                 state: 'IN' },
  { name: 'Dan Knise',            company: 'Ames & Gough',                        email: 'dknise@amesgough.com',           title: 'CEO',                       state: 'MA' },
  { name: 'Steven M. Swenson',    company: 'Broadway Title',                      email: 'sswenson@broadwaytitle.com',     title: 'Owner',                     state: 'NY' },
  { name: 'Vicki Etherton',       company: 'Landmark Title Assurance Agency',     email: 'vicki.etherton@ltaz.com',        title: 'President',                 state: 'AZ' },
  { name: 'Bill Shaddock',        company: 'Capital Title of Texas',              email: 'bshaddock@ctot.com',             title: 'CEO',                       state: 'TX' },
  { name: 'Kim R. Holbrook',      company: 'Founders Title Company',              email: 'kholbrook@founderstitle.com',    title: 'President',                 state: 'UT' },
  { name: 'Jerry S. Schmidt',     company: 'Guardian Title Agency',               email: 'jschmidt@guardiantitle.com',     title: 'President',                 state: 'OH' },
  { name: 'Cloy Ann King',        company: 'Lenders Title Company',               email: 'caking@lenderstitle.com',        title: 'President',                 state: 'AR' },
  { name: 'Steve Sgarlatelli',    company: 'Blueprint Title',                     email: 'steve@blueprinttitle.com',       title: 'Head of Operations',        state: 'TN' },
  { name: 'Thomas G. Miller',     company: 'Network Title',                       email: 'tmiller@networktitle.com',       title: 'President',                 state: 'MN' },
  { name: 'Matthew Cohen',        company: 'Two Rivers Title Company',            email: 'mcohen@tworiverstitle.com',      title: 'CEO',                       state: 'NJ' },
];

const SEGMENT3 = [
  { name: 'Brenda Lyons',         company: 'Ropes & Gray LLP',                   email: 'brenda.lyons@ropesgray.com',     title: 'Managing Partner',          state: 'MA' },
  { name: 'Christopher Kelly',    company: 'Holland & Knight LLP',               email: 'christopher.kelly@hklaw.com',    title: 'Partner - Real Estate',     state: 'FL' },
  { name: 'Robert J. Ivanhoe',    company: 'Greenberg Traurig LLP',              email: 'ivanhoer@gtlaw.com',             title: 'Senior Partner',            state: 'NY' },
  { name: 'Edward A. Gores',      company: 'Cox & Palmer',                        email: 'egores@coxandpalmer.com',        title: 'Partner',                   state: 'ME' },
  { name: 'Andrea Geraghty',      company: 'Meyer, Unkovic & Scott LLP',         email: 'acg@muslaw.com',                 title: 'Real Estate Chair',         state: 'PA' },
  { name: 'Jennifer B. Cona',     company: 'Genser Cona Elder Law',              email: 'jennifer@conalaw.com',           title: 'Managing Partner',          state: 'NY' },
  { name: 'Angela Stout',         company: 'Stout Law Firm',                     email: 'astout@stoutlawfirm.com',        title: 'Managing Partner',          state: 'TX' },
  { name: 'Jaimie P. Schwartz',   company: 'Bernstein Shur',                     email: 'jschwartz@bernsteinshur.com',    title: 'Shareholder - Real Estate', state: 'ME' },
  { name: 'Vincent J. Russo',     company: 'Russo Law Group',                    email: 'vrusso@vjrussolaw.com',          title: 'Managing Partner',          state: 'NY' },
  { name: 'Theron M. Hall',       company: 'Moser, Lovelace & Beierle',          email: 'thall@mlbazlaw.com',             title: 'Estate Attorney',           state: 'AZ' },
  { name: 'Douglas G. Chalgian',  company: 'Chalgian & Tripp Law Offices',       email: 'chalgian@mielderlaw.com',        title: 'Partner',                   state: 'MI' },
  { name: 'Edgardo Diaz',         company: 'Clancy & Diaz LLP',                  email: 'edgardo@clancydiaz.com',         title: 'Partner',                   state: 'CA' },
  { name: 'Thelen K. Jones',      company: 'The Elder Law Firm',                 email: 'tjones@elderlawfirm.com',        title: 'Lead Counsel',              state: 'MI' },
  { name: 'Mark Satter',          company: 'Heiligman & Satter LLP',             email: 'msatter@hslaw.org',              title: 'Partner',                   state: 'PA' },
  { name: 'Robert Kravitz',       company: 'Kravitz Law Office',                 email: 'rkravitz@kravitzlaw.com',        title: 'Lead Partner',              state: 'FL' },
  { name: 'Harry Borders',        company: 'Borders & Borders Attorneys',        email: 'harry@bordersandborders.com',    title: 'Partner',                   state: 'KY' },
  { name: 'Thomas Fileti',        company: 'Morrison & Foerster LLP',            email: 'tfileti@mofo.com',               title: 'Partner',                   state: 'CA' },
];

// ── Resend send helper ────────────────────────────────────────────────────────

function sendEmail({ to, from, replyTo, subject, text }) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ from, reply_to: replyTo, to, subject, text });
    const req = https.request({
      hostname: 'api.resend.com',
      path: '/emails',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(JSON.parse(data)); } catch { resolve({ id: null }); }
        } else {
          reject(new Error(`Resend ${res.statusCode}: ${data}`));
        }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ── Production API import helper ──────────────────────────────────────────────

function importContacts(contacts) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ contacts });
    const req = https.request({
      hostname: PROD_HOST,
      path: '/api/admin/outreach/import',
      method: 'POST',
      headers: {
        'x-admin-secret': ADMIN_SECRET,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch { resolve({ imported: 0 }); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ── Daily cap check ───────────────────────────────────────────────────────────

function checkDailyStats() {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: PROD_HOST,
      path: '/api/admin/outreach/stats',
      method: 'GET',
      headers: { 'x-admin-secret': ADMIN_SECRET },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.end();
  });
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function run() {
  console.log('ProofDeed — 50 Lead Import & Outreach');
  console.log('======================================');

  const stats = await checkDailyStats();
  const sentToday = stats?.eventsToday || 0;
  console.log(`Outreach events last 24h: ${sentToday} / ${DAILY_CAP} cap`);
  const budget = DAILY_CAP - sentToday;
  if (budget <= 0) {
    console.error('Daily cap reached. Run again tomorrow.');
    process.exit(1);
  }
  console.log(`Budget remaining: ${budget} sends\n`);

  const segments = [
    {
      name: 'County Recorders',
      leads: SEGMENT1,
      industry: 'government',
      from: 'Scott Kiersten <gov@proofdeed.com>',
      emailFn: (lead) => RECORDER_EMAIL(lead.name.split(' ')[0]),
    },
    {
      name: 'Title Agencies',
      leads: SEGMENT2,
      industry: 'title_escrow',
      from: 'Scott Kiersten <info@proofdeed.com>',
      emailFn: (lead) => TITLE_EMAIL(lead.name.split(' ')[0]),
    },
    {
      name: 'Law Firms',
      leads: SEGMENT3,
      industry: 'legal',
      from: 'Scott Kiersten <info@proofdeed.com>',
      emailFn: (lead) => LEGAL_EMAIL(lead.name.split(' ')[0]),
    },
  ];

  let totalSent = 0, totalFailed = 0, totalSkipped = 0;

  for (const seg of segments) {
    console.log(`\n── ${seg.name} (${seg.leads.length} leads) ──`);

    const importBatch = [];

    for (const lead of seg.leads) {
      if (totalSent >= budget) {
        console.log(`  [SKIP] Daily cap reached — ${lead.name} (${lead.company}) not sent`);
        totalSkipped++;
        continue;
      }

      const replyTag = crypto.randomBytes(8).toString('hex');
      const subject = `Quick question for ${lead.company}`;
      const text = seg.emailFn(lead);

      try {
        const result = await sendEmail({
          to: lead.email,
          from: seg.from,
          replyTo: `reply+${replyTag}@proofdeed.com`,
          subject,
          text,
        });
        console.log(`  ✓ Sent → ${lead.name} (${lead.company}) [${lead.email}]`);
        totalSent++;

        importBatch.push({
          name: lead.name,
          email: lead.email.toLowerCase(),
          company: lead.company,
          title: lead.title,
          industry: seg.industry,
          county: lead.county || '',
          state: lead.state || '',
        });

        await sleep(1500);
      } catch (e) {
        console.error(`  ✗ Failed → ${lead.name} (${lead.email}): ${e.message}`);
        totalFailed++;
      }
    }

    // Record segment in DB via production API
    if (importBatch.length > 0) {
      try {
        const importResult = await importContacts(importBatch);
        console.log(`  ✓ Recorded ${importBatch.length} contacts in CRM`);
      } catch (e) {
        console.error(`  ✗ CRM import failed for ${seg.name}: ${e.message}`);
      }
    }
  }

  console.log('\n══════════════════════════════════');
  console.log(`DONE — Sent: ${totalSent} | Failed: ${totalFailed} | Skipped (cap): ${totalSkipped}`);
  console.log('Day-7/14/21 follow-ups will fire automatically via the autopilot scheduler.');
}

run().catch(err => { console.error('Fatal:', err.message); process.exit(1); });

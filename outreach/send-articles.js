import { Resend } from 'resend';
import { readFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const resend = new Resend(process.env.RESEND_API_KEY);

const altaArticle = readFileSync(path.join(__dirname, 'article_alta.md'), 'utf8');
const govtechArticle = readFileSync(path.join(__dirname, 'article_govtech.txt'), 'utf8');
const igoArticle = readFileSync(path.join(__dirname, 'article_igo.txt'), 'utf8');

const emails = [
  {
    to: 'service@alta.org',
    subject: 'Article Pitch — How Blockchain Certification Closes the Gap in Deed Fraud Prevention',
    body: `Dear TitleNews Editorial Team,

I'm Scott Kiersten, Founder & CEO of ProofDeed LLC, a Veteran-Owned Small Business in Oshkosh, Wisconsin. We provide blockchain document certification for title companies and real estate attorneys — creating FRE Rule 901-admissible certificates at the moment of closing.

I'd like to contribute a 900-word article for TitleNews:

"Deed Fraud Is Happening After Closing — Here's the Technology That Stops It"

The piece covers:
- Why current deed fraud alerts are reactive, not preventive
- How SHA-256 blockchain anchoring creates a tamper-proof record at recording
- Real cases where post-closing document alteration exposed title companies to liability
- What FRE Rule 901 court-admissible certification means in practice
- How title companies implement this alongside existing software — no system replacement

The article is educational and objective. I can limit or remove any mention of ProofDeed per your guidelines. The full article is below for your review.

Scott Kiersten | Founder & CEO | ProofDeed LLC | VOSB
info@proofdeed.com | proofdeed.com

---

${altaArticle}`
  },
  {
    to: 'lkinkade@govtech.com',
    subject: 'Guest Commentary Pitch — County Recorders Have a Document Fraud Problem. Blockchain Fixes It.',
    body: `Dear Lauren,

I'm Scott Kiersten, Founder & CEO of ProofDeed LLC, a Veteran-Owned Small Business providing blockchain document certification for county recorder offices and government agencies.

I'd like to pitch a guest commentary for Govtech.com:

"County Recorders Have a Document Fraud Problem. Blockchain Fixes It."

The piece covers:
- Why deed fraud keeps succeeding despite existing alert systems
- How cryptographic document anchoring at recording creates mathematical proof of authenticity
- What FRE Rule 901 means for government agencies in litigation and audit
- Real-world implementation: no system replacement, API integration in days
- Why this matters now: FBI warnings, 240% increase in NY deed theft complaints

The commentary is policy and technology focused — not a product pitch. My company has submitted proposals to NSF SBIR and DHS LRBAA for this technology. The full article is below.

Scott Kiersten | Founder & CEO | ProofDeed LLC | VOSB
gov@proofdeed.com | proofdeed.com

---

${govtechArticle}`
  },
  {
    to: 'kim@iaogo.org',
    subject: 'Article for iGO Newsletter — After the FBI Warning on Deed Fraud: What Recorder Offices Can Do Right Now',
    body: `Dear Kim,

I'm Scott Kiersten, Founder & CEO of ProofDeed LLC, a Veteran-Owned Small Business in Wisconsin. We provide blockchain document certification specifically for county recorder offices — creating tamper-proof, court-admissible records at the moment of recording.

I'm reaching out to ask whether iGO's newsletter or publications accept contributed articles from vendors working in the government records space.

I've written a piece specifically for county recorder audiences:

"After the FBI Warning on Deed Fraud — What Recorder Offices Can Do Right Now"

The article is educational and non-promotional. It covers the technology that closes the deed fraud gap the FBI warned about — and what recorder offices can implement right now without changing existing systems. Full article below.

Scott Kiersten | Founder & CEO | ProofDeed LLC | VOSB
gov@proofdeed.com | proofdeed.com

---

${igoArticle}`
  }
];

async function sendAll() {
  for (const email of emails) {
    try {
      const result = await resend.emails.send({
        from: 'Scott Kiersten <gov@proofdeed.com>',
        reply_to: 'gov@proofdeed.com',
        to: email.to,
        subject: email.subject,
        text: email.body
      });
      console.log(`✅ SENT to ${email.to} | ID: ${result.data?.id}`);
      await new Promise(r => setTimeout(r, 3000));
    } catch (err) {
      console.error(`❌ FAILED to ${email.to}: ${err.message}`);
    }
  }
  console.log('\nDone.');
}

sendAll();

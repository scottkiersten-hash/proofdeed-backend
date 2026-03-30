/* ---------------- CONTACT / AFFILIATE FORM ---------------- */
app.post(["/contact", "/api/contact"], async (req, res) => {
  try {
    const { name, company, organization, email, notes, message, phone, request_type, subject, proofId, documentHash, timestamp } = req.body;
    const resolvedCompany = company || organization || null;
    const resolvedNotes = notes || message || null;

    if (!email || !name) {
      return res.status(400).json({ error: "Name and email are required." });
    }

    await pool.query(
      `INSERT INTO contact_submissions (name, company, email, notes, request_type, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())`,
      [name, resolvedCompany, email, resolvedNotes, request_type || "contact"]
    );

    // Auto-assign referral code for affiliate submissions
    if (request_type === "affiliate") {
      try {
        const code = name.split(' ')[0].toUpperCase() + Math.floor(1000 + Math.random() * 9000);

        await pool.query(
          `INSERT INTO users (email, referral_code, created_at)
           VALUES ($1, $2, NOW())
           ON CONFLICT (email) DO UPDATE SET referral_code = $2`,
          [email, code]
        );

        const mailgunDomain = process.env.MAILGUN_DOMAIN;
        const mailgunApiKey = process.env.MAILGUN_API_KEY;

        if (mailgunDomain && mailgunApiKey) {
          const affiliateHtml = "<!DOCTYPE html><html><body style='margin:0;padding:0;background:#f0f0ee;font-family:Georgia,serif;'><div style='max-width:600px;margin:40px auto;background:#ffffff;border:1px solid #ddd;border-radius:4px;overflow:hidden;'><div style='height:4px;background:linear-gradient(90deg,#1a3a8e,#4080d0,#1a3a8e);'></div><div style='padding:40px;'><h1 style='font-size:22px;font-weight:700;color:#111;margin:0 0 8px;'>Welcome to ProofDeed Affiliates</h1><p style='font-size:14px;color:#666;margin:0 0 32px;'>Your affiliate account is ready. Start sharing your unique referral link below.</p><div style='background:#f8f8f6;border:1px solid #e5e5e5;border-radius:4px;padding:24px;margin-bottom:24px;'><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Your Referral Code</p><p style='font-size:24px;font-family:monospace;color:#1a3a8e;font-weight:700;margin:0 0 20px;'>" + code + "</p><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Your Referral Links</p><p style='font-size:13px;font-family:monospace;color:#333;margin:0 0 8px;'>https://proofdeed.com/auto?ref=" + code + "</p><p style='font-size:13px;font-family:monospace;color:#333;margin:0 0 8px;'>https://proofdeed.com/document?ref=" + code + "</p></div><p style='font-size:14px;color:#555;margin:0 0 16px;'>Every customer who signs up through your link will be tracked automatically. You can share either link.</p><p style='font-size:14px;color:#555;margin:0 0 32px;'>Questions? Contact us at <a href=\"mailto:info@proofdeed.com\" style=\"color:#1a3a8e;\">info@proofdeed.com</a></p><hr style='border:none;border-top:1px solid #e5e5e5;margin:24px 0;'><p style='font-size:12px;color:#999;font-family:sans-serif;margin:0;'>ProofDeed &mdash; Blockchain Document Certification</p><p style='font-size:12px;color:#999;font-family:sans-serif;margin:4px 0 0;'><a href='https://proofdeed.com' style='color:#1a3a8e;'>proofdeed.com</a></p></div><div style='height:4px;background:linear-gradient(90deg,#1a3a8e,#4080d0,#1a3a8e);'></div></div></body></html>";

          await fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
            method: "POST",
            headers: {
              "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
              "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
              from: process.env.MAIL_FROM || "ProofDeed <mailgun@" + mailgunDomain + ">",
              to: email,
              subject: "Your ProofDeed Affiliate Code — " + code,
              html: affiliateHtml
            })
          });
          console.log("Affiliate code " + code + " sent to " + email);
        }
      } catch (affiliateErr) {
        console.error("Affiliate setup error (non-fatal):", affiliateErr.message);
      }
    }

    const mailgunDomain = process.env.MAILGUN_DOMAIN;
    const mailgunApiKey = process.env.MAILGUN_API_KEY;

    if (mailgunDomain && mailgunApiKey) {
      const isProofEmail = !!proofId;
      const emailSubject = subject || (isProofEmail ? "Your ProofDeed Certificate" : "ProofDeed Contact Confirmation");

      const htmlProofEmail = "<!DOCTYPE html><html><body style='margin:0;padding:0;background:#f0f0ee;font-family:Georgia,serif;'><div style='max-width:600px;margin:40px auto;background:#ffffff;border:1px solid #ddd;border-radius:4px;overflow:hidden;'><div style='height:4px;background:linear-gradient(90deg,#1a3a8e,#4080d0,#1a3a8e);'></div><div style='padding:40px;'><h1 style='font-size:22px;font-weight:700;color:#111;margin:0 0 8px;'>Document Certified</h1><p style='font-size:14px;color:#666;margin:0 0 32px;'>Your document has been permanently recorded on the Polygon blockchain.</p><div style='background:#f8f8f6;border:1px solid #e5e5e5;border-radius:4px;padding:24px;margin-bottom:24px;'><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Proof ID</p><p style='font-size:18px;font-family:monospace;color:#1a3a8e;font-weight:700;margin:0 0 20px;'>" + proofId + "</p><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Document Hash</p><p style='font-size:11px;font-family:monospace;color:#333;word-break:break-all;margin:0 0 20px;'>" + documentHash + "</p><p style='font-size:11px;font-weight:700;color:#999;text-transform:uppercase;letter-spacing:0.1em;margin:0 0 6px;'>Timestamp</p><p style='font-size:13px;color:#333;margin:0;'>" + timestamp + "</p></div><a href='https://proofdeed.com/verify' style='display:inline-block;background:#0f172a;color:#ffffff;text-decoration:none;padding:14px 28px;border-radius:6px;font-family:sans-serif;font-size:14px;font-weight:600;margin-bottom:24px;'>Verify Certificate</a><hr style='border:none;border-top:1px solid #e5e5e5;margin:24px 0;'><p style='font-size:12px;color:#999;font-family:sans-serif;margin:0;'>ProofDeed &mdash; Blockchain Document Certification</p><p style='font-size:12px;color:#999;font-family:sans-serif;margin:4px 0 0;'><a href='https://proofdeed.com' style='color:#1a3a8e;'>proofdeed.com</a></p></div><div style='height:4px;background:linear-gradient(90deg,#1a3a8e,#4080d0,#1a3a8e);'></div></div></body></html>";

      const textContactEmail = "New contact submission from ProofDeed.\n\nName: " + name + "\nEmail: " + email + "\nOrganization: " + (resolvedCompany || "N/A") + "\nPhone: " + (phone || "N/A") + "\nMessage: " + (resolvedNotes || "N/A") + "\n\nProofDeed\nhttps://proofdeed.com";

      try {
        const mailParams = {
          from: process.env.MAIL_FROM || "ProofDeed <mailgun@" + mailgunDomain + ">",
          to: process.env.MAIL_TO || email,
          subject: emailSubject,
        };

        if (isProofEmail) {
          mailParams.html = htmlProofEmail;
        } else {
          mailParams.text = textContactEmail;
        }

        await fetch("https://api.mailgun.net/v3/" + mailgunDomain + "/messages", {
          method: "POST",
          headers: {
            "Authorization": "Basic " + Buffer.from("api:" + mailgunApiKey).toString("base64"),
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams(mailParams)
        });
        console.log("Email sent to " + email);
      } catch (mailErr) {
        console.error("Mailgun error (non-fatal):", mailErr.message);
      }
    }

    console.log("New " + (request_type || "contact") + " submission from: " + email);
    res.json({ success: true });

  } catch (error) {
    console.error("Contact form error:", error);
    res.status(500).json({ error: error.message });
  }
});

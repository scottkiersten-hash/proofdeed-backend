app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, message } = req.body;

    if (!name || !email || !message) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }

    await mg.messages.create(process.env.MAILGUN_DOMAIN, {
      from: `ProofDeed <mailgun@${process.env.MAILGUN_DOMAIN}>`,
      to: ['info@proofdeed.com'],
      subject: 'New Inquiry Submission',
      text: `
Name: ${name}
Email: ${email}

Message:
${message}
      `,
    });

    return res.json({ success: true });

  } catch (error) {
    console.error('Mailgun error:', error);
    return res.status(500).json({ success: false, error: 'Email failed to send' });
  }
});

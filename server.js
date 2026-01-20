app.get("/upload", (req, res) => {
  res.send(`
    <html>
      <head>
        <title>ProofDeed – Create Proof</title>
      </head>
      <body style="font-family: Arial; max-width: 600px; margin: 40px auto;">
        <h2>Create a Proof</h2>
        <p>Select a document. ProofDeed will create a digital fingerprint.</p>

        <input type="file" id="file" />
        <br><br>
        <button onclick="createProof()">Create Proof</button>

        <pre id="result"></pre>

        <script>
          async function createProof() {
            const fileInput = document.getElementById("file");
            if (!fileInput.files.length) {
              alert("Please select a file");
              return;
            }

            const file = fileInput.files[0];
            const buffer = await file.arrayBuffer();
            const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

            const response = await fetch("/create-proof", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ documentHash: hashHex })
            });

            const data = await response.json();
            document.getElementById("result").textContent = JSON.stringify(data, null, 2);
          }
        </script>
      </body>
    </html>
  `);
});

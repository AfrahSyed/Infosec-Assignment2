# Manual evidence checklist

- Capture: Wireshark on **Npcap Loopback Adapter** (if localhost).
  - **Capture filter:** `tcp port 9000`
  - **Display filter:** `tcp.port == 9000`
  - Show that `ct` is base64 gibberish (no plaintext).
- **BAD CERT**: try a self-signed/expired client cert; show server rejection + packets.
- **SIG FAIL**: flip a byte in `ct` or `sig`; server responds `SIG FAIL`.
- **REPLAY**: resend a previous `seqno`; server responds `REPLAY`.
- **Non-repudiation**: run `python scripts/verify_receipt.py transcripts/server.log transcripts/server-receipt.json certs/server_cert.pem`
  and similar for client; screenshot OK output.

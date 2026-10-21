# Architecture and Design Rationale

Everything is client-side. Facts are checked against `app.js`, `index.html` and the README.

- **No signalling server.** The two invite and reply codes are the WebRTC offer and answer. The codes carry the connection setup; GitHub Pages only serves files. *(from README "How it works")*
- **Ephemeral ECDH P-256 keys, non-extractable.** Generated in memory, so the private key cannot be exported (`app.js`, `generateKey(..., false, ['deriveBits'])`).
- **Out-of-band verification.** A short authentication string is derived with HKDF from the transcript (public keys, DTLS fingerprints, shared secret). Mismatched keys or fingerprints produce different codes on the two screens. The design relies on people comparing codes over another channel.
- **Per-message keys from a one-way ratchet.** HMAC-SHA-256 chain with the old chain key zeroed, so earlier messages stay unreadable if a later key is captured (forward secrecy within a session). AES-256-GCM per message, with sequence number in the nonce and AAD.
- **Length padding and strict framing.** Plaintext padded to 256-byte blocks; frame sizes are bounded; replays or reordering end the session.
- **Strict CSP and `textContent` only.** Inline scripts and third-party loads are blocked by the CSP in `index.html`; messages are rendered with `textContent` to avoid HTML injection.
- **Nothing persisted.** No localStorage, IndexedDB or cookies. *(README; the code keeps state in memory.)*
- **Trade-off, stated in README:** no TURN relay, because one cannot be hosted on Pages. Some networks will fail to connect.

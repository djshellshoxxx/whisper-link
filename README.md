# whisper-link

Temporary, end-to-end encrypted chat for **two people**. It runs entirely in the browser and is hosted on GitHub Pages. There is no server, no account, and nothing is stored.

## How to use it

1. **Person A** opens the site, clicks **I'm starting the chat**, and sends the **invite code** to Person B (email, text, any messenger).
2. **Person B** opens the site, clicks **I received an invite code**, pastes it, clicks **Create my reply code**, and sends the **reply code** back.
3. **Person A** pastes the reply code and clicks **Connect**. The browsers now connect directly to each other.
4. Both people see a **verification code**. Compare it **over a phone call or in person** (not through the channel you used for the codes). If it matches on both screens, click **The codes match**. If not, click **They don't match** and stop.
5. Chat. Click **End and wipe** or let the timer run out. Closing the tab also destroys everything.

## How it works

- **Transport:** a WebRTC data channel. The two codes are the WebRTC offer and answer, so no signalling server is needed.
- **Key exchange:** each side generates an ephemeral ECDH P-256 key pair in memory (the private key is non-extractable).
- **Verification:** both sides derive a 100-bit short authentication string from the whole handshake (both public keys, both DTLS fingerprints, and the shared secret). If anyone swapped keys or fingerprints while the codes were in transit, the two screens will differ.
- **Messages:** AES-256-GCM. Every message uses a fresh key from a one-way HMAC-SHA-256 ratchet, and old keys are zeroed, so a key captured later can't decrypt earlier messages. Messages are padded to 256-byte blocks, numbered, and replays or reordering end the session.
- **Hardening:** a strict Content-Security-Policy (no inline scripts, no third-party loads), messages are only ever written with `textContent`, and codes asking for audio/video or extra channels are rejected.
- **Temporary:** nothing is written to localStorage, IndexedDB, or cookies. Keys and messages exist only in memory.

## Limits (please read)

- **Both IP addresses are visible** to each other (that is how WebRTC works). With "Use public STUN servers" ticked, Google and Cloudflare also see your IP. Untick it for same-network chats.
- **No relay server.** Strict corporate firewalls and some mobile or symmetric NATs block direct connections, and the chat will fail to connect. A TURN relay would fix that but can't be hosted on GitHub Pages.
- **You must trust the code you load.** The JavaScript comes from this repo via GitHub Pages. If the repo or the GitHub account were compromised, the code could be altered. Protect the account with 2FA, review changes, and consider hosting your own copy.
- **Verification is essential.** Without comparing the verification code out-of-band, encryption only stops passive eavesdroppers.
- **Endpoints:** nothing protects you from malware or screen capture on either device, or from the other person saving the messages.
- Both people must be online at the same time. There is no offline delivery and no history.

## Deploy on GitHub Pages

1. Repo **Settings → Pages**.
2. **Build and deployment → Source: Deploy from a branch**.
3. Branch **main**, folder **/ (root)**, then **Save**.
4. After a minute the site is at `https://<your-username>.github.io/whisper-link/`.

## Files

| File | Purpose |
|---|---|
| `index.html` | Page structure and Content-Security-Policy |
| `app.js` | WebRTC, cryptography and UI logic |
| `style.css` | Styling (light and dark mode) |

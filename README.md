# whisper-link

Temporary, end-to-end encrypted chat for **two people**. It runs entirely in the browser and is hosted on GitHub Pages. There is no server, no account, and nothing is stored.

## How to use it

1. **Person A** opens the site, clicks **I'm starting the chat**, and sends the **invite code** to Person B (email, text, any messenger).
2. **Person B** opens the site, clicks **I received an invite code**, pastes it, clicks **Create my reply code**, and sends the **reply code** back.
3. **Person A** pastes the reply code and clicks **Connect**. The browsers now connect directly to each other.
4. Both people see a **verification code**. Compare the **whole** code **over a phone call or in person** (not through the channel you used for the codes). If it matches on both screens, click **The codes match**. If not, click **They don't match** and stop.
5. Chat. Click **End and wipe** or let the timer run out. Closing the tab also destroys everything.

## How it works

- **Transport:** a WebRTC data channel. The two codes are the WebRTC offer and answer, so no signalling server is needed.
- **Key exchange:** each side generates an ephemeral ECDH P-256 key pair in memory (the private key is non-extractable and is dropped as soon as the shared secret is derived).
- **Verification:** both sides derive a 100-bit short authentication string from the whole handshake (both public keys, both DTLS fingerprints, and the shared secret). If anyone swapped keys or fingerprints while the codes were in transit, the two screens will differ. Your end-to-end keys do not depend on the WebRTC connection being trustworthy: even if someone interfered with the connection itself, they still could not read messages unless the verification code was also fooled.
- **Messages:** AES-256-GCM. Every message uses a fresh key from a one-way HMAC-SHA-256 ratchet, and old keys are zeroed, so a key captured later can't decrypt earlier messages. Messages are padded to 256-byte blocks, numbered, and replays or reordering end the session.
- **Hardening:**
  - Strict Content-Security-Policy (no inline scripts, no third-party loads), and messages are only ever written with `textContent`.
  - The page refuses to run inside another page (clickjacking) and drops any link to the page that opened it.
  - Codes are size-limited and checked. Codes that ask for audio/video are rejected. The other side's network addresses are filtered (no loopback, link-local, multicast, TCP, hostnames, or low ports) and capped at 12, and an unsafe data-channel configuration is refused.
  - Flooding is capped: the queue of messages that arrive before you verify, the on-screen message list, and the message rate.
  - Error messages are fixed text, never echoes of what the other side sent. Bidirectional-text override characters are removed from displayed messages.
  - The message box turns off spellcheck and autocorrect, so a browser's cloud spellcheck is not sent your drafts.
- **Temporary:** nothing is written to localStorage, IndexedDB, or cookies. Keys and messages exist only in memory.

## Limits (please read)

- **Your IP address is in the codes.** The invite and reply codes contain network addresses (your local and, with STUN on, public IP). Whoever carries the code (your messenger, email provider) can read them. The other person sees your IP address too.
- **Pasting an invite makes your browser contact the addresses in it.** Only use invites from people you trust. Unsafe address types are filtered, but addresses on your own network are still tried, because that is how chats on the same network connect. At most 12 are used.
- **With "Use public STUN servers" ticked,** Google and Cloudflare also see your IP address. Untick it for same-network chats.
- **No relay server.** Strict firewalls and some mobile or symmetric NATs block direct connections, and the chat will fail to connect. A TURN relay would fix that but can't be hosted on GitHub Pages.
- **You must trust the code you load.** The JavaScript comes from this repo via GitHub Pages. If the repo or the GitHub account were compromised, the code could be altered. GitHub Pages serves every project site under one account from the same web origin, so another site under the same account could script this one. Protect the account with 2FA, review changes, don't host untrusted content under the same account, and consider hosting your own copy on its own domain.
- **GitHub Pages can't send security headers.** The Content-Security-Policy is applied via a `<meta>` tag, which cannot set `frame-ancestors`. Framing is blocked by the page's own script instead, which is weaker than a header.
- **Verification is essential.** Without comparing the verification code out-of-band, encryption only stops passive eavesdroppers. Compare the whole code; the longer you compare, the harder it is to fake.
- **"The other person says they confirmed the code"** is a claim made by the other side. It proves nothing.
- **Endpoints:** nothing protects you from malware, a malicious browser extension, or screen capture on either device, or from the other person saving the messages. Wiping is best-effort: browsers and operating systems can leave traces in memory that a web page can't erase. "Copy" puts a code on the clipboard, where clipboard-history tools may keep it.
- **No deniability.** The chat is authenticated with keys both sides hold, so the other person can prove to themselves who wrote what, but this app makes no promise to protect you from the other person sharing what you wrote.
- Both people must be online at the same time. There is no offline delivery and no history.
- This is a small, custom, un-audited protocol. Don't rely on it where a failure would be dangerous.

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
| `style.css` | Styling (dark cyber theme) |

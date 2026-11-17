# Codebase Map: where to find what

| I want to... | Look in |
|---|---|
| Page structure and the Content-Security-Policy | `index.html` (CSP in the `<meta>` tag) |
| WebRTC setup, invite/reply codes, ICE wait | `app.js` (ICE timer near `ICE_WAIT_MS`) |
| Key agreement, verification code | `app.js` (ECDH and HKDF functions) |
| Message encryption, ratchet, padding, framing | `app.js` (ratchet, pad and frame functions, `MAX_FRAME`) |
| Session expiry and the timer | `app.js` (expiry handling, `S.expiresAt`) |
| Styling, light and dark mode | `style.css` |
| GitHub Pages | `.nojekyll` |

There is no build step and no automated test suite in the repository.

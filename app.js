'use strict';

/*
 * whisper-link: temporary, end-to-end encrypted chat for two people.
 *
 * - Transport: a WebRTC data channel, set up by copy-pasting two codes (no signalling server).
 * - Key exchange: ephemeral ECDH P-256 keys that live only in memory.
 * - Authentication: both sides derive a short verification code (SAS) from the whole handshake
 *   (both public keys, both DTLS fingerprints, the shared secret). The users compare it by voice.
 * - Messages: AES-256-GCM with a fresh key per message from a one-way HMAC ratchet (forward secrecy).
 */
(() => {
  // Refuse to run inside another page (clickjacking) and cut any link back to an opener (tab-napping).
  try { window.opener = null; } catch (e) { /* ignore */ }
  if (window.top !== window.self) {
    document.body.textContent = 'For your safety this page will not run inside another page. Open it directly in its own browser tab.';
    return;
  }

  const PROTO = 'whisper-link/v1';
  const MAX_TEXT = 4000;
  const MAX_FRAME = 24 * 1024;
  const MAX_CODE_CHARS = 24000;
  const MAX_SDP_CHARS = 16000;
  const MAX_DECOMPRESSED = 64 * 1024;
  const MAX_CANDIDATES = 12;
  const MAX_PENDING = 200;
  const MAX_DOM_ITEMS = 500;
  const FLOOD_WINDOW_MS = 5000;
  const FLOOD_MAX_FRAMES = 300;
  const CONNECT_HINT_MS = 90000;
  const ICE_WAIT_MS = 6000;
  const STUN_SERVERS = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] }];

  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const $ = (id) => document.getElementById(id);
  const delay = (ms) => new Promise((r) => setTimeout(r, ms));

  /* ---------- state ---------- */

  const S = {
    role: null,          // 'host' | 'guest'
    pc: null,
    dc: null,
    keys: null,          // { priv, pub }
    ownPk: '',
    ownFp: '',
    sendChain: null,     // { key: Uint8Array, n: number }
    recvChain: null,
    sas: '',
    opened: false,
    ended: false,
    verifiedMe: false,
    verifiedPeer: false,
    pending: [],         // messages that arrived before this user confirmed the codes
    expiresAt: 0,
    tick: null,
    connectTimer: null,
    statusId: 'host-status',
    sendQ: Promise.resolve(),
    recvQ: Promise.resolve(),
    pendingDropped: 0,
    winStart: 0,
    winCount: 0,
  };

  /* ---------- small helpers ---------- */

  const b64u = {
    enc(bytes) {
      let s = '';
      for (let i = 0; i < bytes.length; i += 0x8000) {
        s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },
    dec(str) {
      let s = str.replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) s += '=';
      const bin = atob(s);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    },
  };

  const SCREENS = ['start', 'host', 'join', 'verify', 'chat', 'ended'];
  function show(name) {
    for (const n of SCREENS) $('screen-' + n).hidden = n !== name;
    const heading = $('screen-' + name).querySelector('h2');
    if (heading) {
      heading.tabIndex = -1;
      heading.focus({ preventScroll: true });
    }
  }

  function setStatus(id, msg, kind) {
    const el = $(id);
    el.textContent = msg || '';
    if (kind) el.dataset.kind = kind;
    else delete el.dataset.kind;
  }

  // Only our own fixed messages are ever shown. Browser errors can echo attacker-controlled text.
  class UserError extends Error {}
  const errText = (e) => (e instanceof UserError ? e.message : 'Something went wrong. Please try again, or reload the page.');

  // Remove characters that can reorder or hide text (bidi overrides and isolates).
  const stripBidi = (t) => t.replace(/[\u202A-\u202E\u2066-\u2069]/g, '');

  /* ---------- code (blob) packing ---------- */

  async function pipeBytes(bytes, transform, maxOut) {
    const reader = new Blob([bytes]).stream().pipeThrough(transform).getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxOut) {
        reader.cancel();
        throw new UserError('That code is too large.');
      }
      chunks.push(value);
    }
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) { out.set(c, o); o += c.length; }
    return out;
  }

  async function packBlob(obj) {
    const raw = enc.encode(JSON.stringify(obj));
    if (typeof CompressionStream === 'function') {
      return 'WL1.' + b64u.enc(await pipeBytes(raw, new CompressionStream('deflate-raw'), MAX_DECOMPRESSED));
    }
    return 'WL0.' + b64u.enc(raw);
  }

  async function unpackBlob(text, expectedRole) {
    const t = String(text || '').replace(/\s+/g, '');
    if (t.length > MAX_CODE_CHARS) throw new UserError('That code is too long to be a whisper-link code.');
    const m = /^WL([01])\.([A-Za-z0-9_-]+)$/.exec(t);
    if (!m) throw new UserError("That doesn't look like a whisper-link code. Copy the whole thing, starting with WL.");
    let bytes;
    try {
      bytes = b64u.dec(m[2]);
      if (m[1] === '1') {
        if (typeof DecompressionStream !== 'function') throw new UserError('This browser cannot read compressed codes.');
        bytes = await pipeBytes(bytes, new DecompressionStream('deflate-raw'), MAX_DECOMPRESSED);
      }
    } catch (e) {
      throw new UserError(e instanceof UserError ? e.message : 'The code is damaged or incomplete. Copy it again in full.');
    }
    let obj;
    try {
      obj = JSON.parse(dec.decode(bytes));
    } catch (e) {
      throw new UserError('The code is damaged or incomplete. Copy it again in full.');
    }
    if (!obj || obj.v !== 1) throw new UserError('Unsupported code version.');
    if (obj.r !== expectedRole) {
      throw new UserError(expectedRole === 'answer'
        ? 'That is an invite code. Paste the reply code the other person sent you.'
        : 'That is a reply code. Paste the invite code instead.');
    }
    if (typeof obj.s !== 'string' || obj.s.length > MAX_SDP_CHARS || typeof obj.k !== 'string') {
      throw new UserError('Malformed code.');
    }
    return obj;
  }

  /* ---------- SDP / key validation ---------- */

  // Returns the DTLS fingerprint of a data-channel-only SDP, or throws.
  function inspectSdp(sdp) {
    if (!/^v=0\r?\n/.test(sdp)) throw new UserError('Malformed connection data.');
    const mLines = sdp.match(/^m=.*$/gm) || [];
    if (mLines.length !== 1 || !/^m=application /.test(mLines[0])) {
      throw new UserError('This code asks for more than a text chat (audio or video). Refusing it.');
    }
    const fps = new Set();
    for (const m of sdp.matchAll(/^a=fingerprint:(\S+) ([0-9A-Fa-f:]+)\s*$/gm)) {
      if (m[1].toLowerCase() !== 'sha-256') throw new UserError('Unsupported fingerprint type.');
      fps.add(m[2].toUpperCase());
    }
    if (fps.size !== 1) throw new UserError('The code has no usable security fingerprint.');
    return [...fps][0];
  }

  function parsePk(b64) {
    let bytes;
    try { bytes = b64u.dec(b64); } catch (e) { throw new UserError('Malformed key in code.'); }
    if (bytes.length !== 65 || bytes[0] !== 4 || b64u.enc(bytes) !== b64) throw new UserError('Malformed key in code.');
    return bytes;
  }

  // Which network addresses from someone else's code are we willing to let the browser contact?
  function addressIsSafe(addr) {
    if (/^[0-9a-f-]{36}\.local$/i.test(addr)) return true; // browser-generated mDNS name
    const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
    if (v4) {
      const o = v4.slice(1).map(Number);
      if (o.some((x) => x > 255)) return false;
      if (o[0] === 0 || o[0] === 127 || o[0] >= 224) return false; // unspecified, loopback, multicast, reserved
      if (o[0] === 169 && o[1] === 254) return false;             // link-local
      return true;
    }
    if (/^[0-9a-f:]{2,45}$/i.test(addr) && addr.includes(':')) {
      const a = addr.toLowerCase();
      return !(a === '::' || a === '::1' || a.startsWith('fe80') || a.startsWith('ff'));
    }
    return false; // hostnames would trigger DNS lookups
  }

  function candidateIsSafe(line) {
    const p = line.slice('a=candidate:'.length).trim().split(/\s+/);
    if (p.length < 8 || p[6] !== 'typ') return false;
    const port = Number(p[5]);
    return p[2].toLowerCase() === 'udp'
      && ['host', 'srflx', 'prflx'].includes(p[7])
      && Number.isInteger(port) && port >= 1024 && port <= 65535
      && addressIsSafe(p[4]);
  }

  // Rebuild the other side's SDP keeping only what we need. Their candidate list decides which addresses
  // our browser will probe, so it is filtered and capped. Default address/port lines are neutralised.
  function sanitizeRemoteSdp(sdp) {
    const out = [];
    let kept = 0;
    for (const line of sdp.split(/\r?\n/)) {
      if (line === '') continue;
      if (line.startsWith('a=candidate:')) {
        if (kept < MAX_CANDIDATES && candidateIsSafe(line)) { out.push(line); kept++; }
        continue;
      }
      if (line.startsWith('c=')) { out.push('c=IN IP4 0.0.0.0'); continue; }
      if (line.startsWith('m=application ')) {
        if (!/^m=application \d+ UDP\/DTLS\/SCTP webrtc-datachannel$/.test(line)) throw new UserError('Unsupported connection type in this code.');
        out.push('m=application 9 UDP/DTLS/SCTP webrtc-datachannel');
        continue;
      }
      if (line.startsWith('a=remote-candidates') || line.startsWith('a=rtcp:')) continue;
      out.push(line);
    }
    if (!kept) throw new UserError('This code has no usable network address. Ask for a fresh one.');
    return out.join('\r\n') + '\r\n';
  }

  async function applyRemote(type, sdp) {
    try {
      await S.pc.setRemoteDescription({ type, sdp });
    } catch (e) {
      throw new UserError("Your browser rejected the other side's connection data. Ask them to create a fresh code.");
    }
  }

  /* ---------- crypto ---------- */

  async function genKeys() {
    const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    return { priv: kp.privateKey, pub };
  }

  const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32: no I, L, O, U

  function sasString(bytes) {
    let bits = 0;
    let val = 0;
    let out = '';
    for (const b of bytes) {
      val = (val << 8) | b;
      bits += 8;
      while (bits >= 5) {
        out += ALPHABET[(val >>> (bits - 5)) & 31];
        bits -= 5;
      }
      val &= (1 << bits) - 1;
    }
    return out.slice(0, 20).match(/.{5}/g).join(' ');
  }

  async function deriveSession(peerPkB64, peerFp) {
    const isHost = S.role === 'host';
    const peerPub = parsePk(peerPkB64);
    const peerKey = await crypto.subtle.importKey('raw', peerPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, S.keys.priv, 256);

    const offerFp = isHost ? S.ownFp : peerFp;
    const answerFp = isHost ? peerFp : S.ownFp;
    const offerPk = isHost ? S.ownPk : peerPkB64;
    const answerPk = isHost ? peerPkB64 : S.ownPk;
    const transcript = enc.encode([PROTO, offerFp, answerFp, offerPk, answerPk].join('\n'));
    const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', transcript));

    const hk = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
    const expand = async (label, bytes) => new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(PROTO + ' ' + label) }, hk, bytes * 8));
    const [sas, h2g, g2h] = await Promise.all([expand('sas', 13), expand('host-to-guest', 32), expand('guest-to-host', 32)]);

    return {
      sas: sasString(sas),
      sendChain: { key: isHost ? h2g : g2h, n: 0 },
      recvChain: { key: isHost ? g2h : h2g, n: 0 },
    };
  }

  function commitSession(sess) {
    S.sas = sess.sas;
    S.sendChain = sess.sendChain;
    S.recvChain = sess.recvChain;
    S.keys.priv = null; // the ECDH private key is no longer needed; drop it for forward secrecy
  }

  async function hmac(keyBytes, byte) {
    const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', k, Uint8Array.of(byte)));
  }

  // One-way ratchet: message key = HMAC(chain, 1); next chain = HMAC(chain, 2). The old chain key is zeroed.
  async function ratchet(chain) {
    const mk = await hmac(chain.key, 1);
    const next = await hmac(chain.key, 2);
    chain.key.fill(0);
    chain.key = next;
    return { mk, n: chain.n++ };
  }

  function counterBytes(n) {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(n));
    return b;
  }

  function ivFor(n) {
    const iv = new Uint8Array(12);
    new DataView(iv.buffer).setBigUint64(4, BigInt(n));
    return iv;
  }

  // Pad plaintext to a multiple of 256 bytes so message length leaks less.
  function pad(bytes) {
    const total = Math.ceil((4 + bytes.length) / 256) * 256;
    const out = new Uint8Array(total);
    new DataView(out.buffer).setUint32(0, bytes.length);
    out.set(bytes, 4);
    return out;
  }

  function unpad(buf) {
    if (buf.length < 4) throw new UserError('bad padding');
    const len = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(0);
    if (len > buf.length - 4) throw new UserError('bad padding');
    return buf.subarray(4, 4 + len);
  }

  async function seal(obj) {
    const { mk, n } = await ratchet(S.sendChain);
    const key = await crypto.subtle.importKey('raw', mk, 'AES-GCM', false, ['encrypt']);
    mk.fill(0);
    const aad = counterBytes(n);
    const pt = pad(enc.encode(JSON.stringify(obj)));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivFor(n), additionalData: aad }, key, pt));
    const frame = new Uint8Array(8 + ct.length);
    frame.set(aad, 0);
    frame.set(ct, 8);
    return frame;
  }

  async function open(frame) {
    if (frame.length < 8 + 16 + 256 || frame.length > MAX_FRAME) throw new UserError('bad frame size');
    const aad = frame.subarray(0, 8);
    const n = Number(new DataView(frame.buffer, frame.byteOffset, 8).getBigUint64(0));
    if (n !== S.recvChain.n) throw new UserError('out-of-order or replayed message');
    const { mk } = await ratchet(S.recvChain);
    const key = await crypto.subtle.importKey('raw', mk, 'AES-GCM', false, ['decrypt']);
    mk.fill(0);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivFor(n), additionalData: aad }, key, frame.subarray(8)));
    return JSON.parse(dec.decode(unpad(pt)));
  }

  /* ---------- WebRTC ---------- */

  function makePc() {
    const pc = new RTCPeerConnection({ iceServers: $('use-stun').checked ? STUN_SERVERS : [] });
    pc.onconnectionstatechange = () => {
      if (S.ended || pc !== S.pc) return;
      if (pc.connectionState === 'failed') {
        if (S.opened) endSession('The connection was lost.', false);
        else setStatus(S.statusId, "Couldn't connect. You may be behind a strict firewall or NAT that blocks direct connections, and whisper-link has no relay server. Try again on another network, or turn STUN on.", 'error');
      }
    };
    return pc;
  }

  function waitForIce(pc) {
    return new Promise((resolve) => {
      if (pc.iceGatheringState === 'complete') return resolve();
      const timer = setTimeout(done, ICE_WAIT_MS);
      function done() {
        clearTimeout(timer);
        pc.removeEventListener('icegatheringstatechange', onChange);
        resolve();
      }
      function onChange() {
        if (pc.iceGatheringState === 'complete') done();
      }
      pc.addEventListener('icegatheringstatechange', onChange);
    });
  }

  function wireChannel(ch) {
    ch.binaryType = 'arraybuffer';
    ch.onopen = onOpen;
    ch.onclose = () => {
      if (S.opened && !S.ended) endSession('The other person disconnected.', false);
    };
    ch.onmessage = (ev) => {
      if (!(ev.data instanceof ArrayBuffer)) return;
      const now = Date.now();
      if (now - S.winStart > FLOOD_WINDOW_MS) { S.winStart = now; S.winCount = 0; }
      if (++S.winCount > FLOOD_MAX_FRAMES) {
        endSession('The other side was sending data far too fast, so the chat was ended.', false);
        return;
      }
      const frame = new Uint8Array(ev.data);
      S.recvQ = S.recvQ.then(() => handleFrame(frame)).catch(() => {
        endSession('A message failed its security check, so the chat was ended. The connection may have been tampered with.', false);
      });
    };
  }

  function resetConnection() {
    clearTimeout(S.connectTimer);
    try { if (S.dc) S.dc.close(); } catch (e) { /* ignore */ }
    try { if (S.pc) S.pc.close(); } catch (e) { /* ignore */ }
    S.pc = null;
    S.dc = null;
    S.keys = null;
    if (S.sendChain) S.sendChain.key.fill(0);
    if (S.recvChain) S.recvChain.key.fill(0);
    S.sendChain = null;
    S.recvChain = null;
    S.sas = '';
  }

  function armConnectTimer() {
    clearTimeout(S.connectTimer);
    S.connectTimer = setTimeout(() => {
      if (!S.opened && !S.ended) {
        setStatus(S.statusId, "Still not connected. Check that both people pasted the codes from the same attempt. If you're on different networks, make sure STUN is ticked on both sides.", 'error');
      }
    }, CONNECT_HINT_MS);
  }

  /* ---------- host flow ---------- */

  async function startHost() {
    S.role = 'host';
    S.statusId = 'host-status';
    resetConnection();
    show('host');
    $('btn-connect').disabled = true;
    setStatus('host-status', 'Creating your invite code…');
    try {
      S.keys = await genKeys();
      S.ownPk = b64u.enc(S.keys.pub);
      S.pc = makePc();
      S.pc.ondatachannel = (ev) => ev.channel.close(); // we never expect the other side to open channels
      S.dc = S.pc.createDataChannel('chat');
      wireChannel(S.dc);
      await S.pc.setLocalDescription(await S.pc.createOffer());
      await waitForIce(S.pc);
      const sdp = S.pc.localDescription.sdp;
      S.ownFp = inspectSdp(sdp);
      $('invite-out').value = await packBlob({ v: 1, r: 'offer', s: sdp, k: S.ownPk });
      $('btn-connect').disabled = false;
      setStatus('host-status', 'Invite code ready. Send it to the other person, then paste their reply below.', 'ok');
    } catch (e) {
      setStatus('host-status', 'Could not create the invite: ' + errText(e), 'error');
    }
  }

  async function acceptReply() {
    $('btn-connect').disabled = true;
    try {
      setStatus('host-status', 'Checking the reply…');
      const msg = await unpackBlob($('reply-in').value, 'answer');
      const peerFp = inspectSdp(msg.s);
      parsePk(msg.k);
      const safeSdp = sanitizeRemoteSdp(msg.s);
      const sess = await deriveSession(msg.k, peerFp);
      await applyRemote('answer', safeSdp);
      commitSession(sess);
      setStatus('host-status', 'Connecting…');
      armConnectTimer();
    } catch (e) {
      $('btn-connect').disabled = false;
      setStatus('host-status', errText(e), 'error');
    }
  }

  /* ---------- guest flow ---------- */

  async function createReply() {
    S.role = 'guest';
    S.statusId = 'join-status';
    $('btn-reply').disabled = true;
    $('reply-box').hidden = true;
    try {
      setStatus('join-status', 'Checking the invite…');
      const msg = await unpackBlob($('invite-in').value, 'offer');
      const peerFp = inspectSdp(msg.s);
      parsePk(msg.k);
      const safeSdp = sanitizeRemoteSdp(msg.s);

      resetConnection();
      S.keys = await genKeys();
      S.ownPk = b64u.enc(S.keys.pub);
      S.pc = makePc();
      S.pc.ondatachannel = (ev) => {
        const ch = ev.channel;
        const safe = ch.label === 'chat' && ch.ordered && ch.maxRetransmits === null
          && ch.maxPacketLifeTime === null && !ch.negotiated;
        if (S.dc || !safe) {
          ch.close();
          if (!S.dc && !safe) setStatus('join-status', 'The other side tried to open an unsafe data channel, so it was refused.', 'error');
          return;
        }
        S.dc = ch;
        wireChannel(S.dc);
        if (S.dc.readyState === 'open') onOpen();
      };
      await applyRemote('offer', safeSdp);
      await S.pc.setLocalDescription(await S.pc.createAnswer());
      await waitForIce(S.pc);
      const sdp = S.pc.localDescription.sdp;
      S.ownFp = inspectSdp(sdp);
      commitSession(await deriveSession(msg.k, peerFp));
      $('reply-out').value = await packBlob({ v: 1, r: 'answer', s: sdp, k: S.ownPk });
      $('reply-box').hidden = false;
      setStatus('join-status', 'Reply code ready. Send it back and keep this page open.', 'ok');
      armConnectTimer();
    } catch (e) {
      setStatus('join-status', errText(e), 'error');
    } finally {
      $('btn-reply').disabled = false;
    }
  }

  /* ---------- connected ---------- */

  function onOpen() {
    if (S.opened || S.ended || !S.sendChain) return;
    S.opened = true;
    clearTimeout(S.connectTimer);
    startTimer();
    $('sas').textContent = S.sas;
    $('sas').setAttribute('aria-label', 'Verification code: ' + S.sas.replace(/ /g, ', ').split('').join(' '));
    show('verify');
  }

  function sendCtl(obj) {
    const p = S.sendQ.then(async () => {
      if (!S.dc || S.dc.readyState !== 'open' || !S.sendChain) throw new UserError('Not connected.');
      S.dc.send(await seal(obj));
    });
    S.sendQ = p.catch(() => {});
    return p;
  }

  async function handleFrame(frame) {
    if (S.ended || !S.recvChain) return;
    const m = await open(frame);
    if (!m || typeof m.t !== 'string') throw new UserError('bad message');
    if (m.t === 'msg') {
      if (typeof m.text !== 'string' || m.text.length > MAX_TEXT) throw new UserError('bad text');
      if (S.verifiedMe) addMessage('them', m.text);
      else if (S.pending.length < MAX_PENDING) S.pending.push({ text: m.text, at: new Date() });
      else S.pendingDropped++;
    } else if (m.t === 'verified') {
      S.verifiedPeer = true;
      updatePeerState();
    } else if (m.t === 'bye') {
      endSession('The other person ended the chat.', false);
    }
  }

  function updatePeerState() {
    const el = $('peer-state');
    if (S.verifiedPeer) {
      el.textContent = 'The other person says they confirmed the code';
      delete el.dataset.kind;
    } else {
      el.textContent = 'Waiting for the other person to confirm the codes…';
      delete el.dataset.kind;
    }
  }

  function fmtTime(d) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function addMessage(who, text, at) {
    const list = $('messages');
    const wrap = document.createElement('div');
    wrap.className = 'msg ' + who;
    const bubble = document.createElement('div');
    bubble.className = 'bubble';
    bubble.textContent = stripBidi(text);
    const time = document.createElement('time');
    time.textContent = fmtTime(at || new Date());
    wrap.append(bubble, time);
    list.append(wrap);
    trimMessages();
    list.scrollTop = list.scrollHeight;
  }

  function trimMessages() {
    const list = $('messages');
    while (list.childElementCount > MAX_DOM_ITEMS) list.firstElementChild.remove();
  }

  function addSystem(text) {
    const el = document.createElement('div');
    el.className = 'sys';
    el.textContent = text;
    $('messages').append(el);
    trimMessages();
  }

  function confirmMatch() {
    S.verifiedMe = true;
    show('chat');
    updatePeerState();
    addSystem('Codes confirmed on your side. Messages are end-to-end encrypted.');
    for (const p of S.pending) addMessage('them', p.text, p.at);
    if (S.pendingDropped) addSystem(S.pendingDropped + ' message(s) sent before you confirmed the code were discarded because there were too many.');
    S.pending = [];
    S.pendingDropped = 0;
    sendCtl({ t: 'verified' }).catch(() => {});
    $('msg-input').focus();
  }

  async function sendMessage() {
    const input = $('msg-input');
    const text = input.value.replace(/\s+$/, '');
    if (!text) return;
    if (text.length > MAX_TEXT) {
      setStatus('chat-status', 'Message is too long (max ' + MAX_TEXT + ' characters).', 'error');
      return;
    }
    input.value = '';
    try {
      await sendCtl({ t: 'msg', text });
      addMessage('me', text);
      setStatus('chat-status', '');
    } catch (e) {
      input.value = text;
      setStatus('chat-status', 'Could not send: ' + errText(e), 'error');
    }
  }

  /* ---------- timer / teardown ---------- */

  function startTimer() {
    const minutes = Number($('expiry').value);
    if (!minutes) {
      $('countdown').textContent = 'No time limit';
      return;
    }
    S.expiresAt = Date.now() + minutes * 60000;
    S.tick = setInterval(updateTimer, 1000);
    updateTimer();
  }

  function updateTimer() {
    const left = S.expiresAt - Date.now();
    if (left <= 0) {
      endSession('The time limit was reached, so the chat was ended and wiped.');
      return;
    }
    const m = Math.floor(left / 60000);
    const s = Math.floor((left % 60000) / 1000);
    $('countdown').textContent = m + ':' + String(s).padStart(2, '0') + ' left';
  }

  async function endSession(reason, notifyPeer = true) {
    if (S.ended) return;
    S.ended = true;
    if (notifyPeer && S.dc && S.dc.readyState === 'open' && S.sendChain) {
      try {
        await Promise.race([sendCtl({ t: 'bye' }), delay(500)]);
        await delay(150);
      } catch (e) { /* peer will notice the close */ }
    }
    clearInterval(S.tick);
    resetConnection();
    S.pending = [];
    $('messages').textContent = '';
    for (const id of ['msg-input', 'invite-in', 'invite-out', 'reply-in', 'reply-out']) $(id).value = '';
    $('sas').textContent = '';
    $('ended-reason').textContent = reason;
    show('ended');
  }

  /* ---------- clipboard ---------- */

  async function copyFrom(id, statusId) {
    const el = $(id);
    el.focus();
    el.select();
    try {
      await navigator.clipboard.writeText(el.value);
      setStatus(statusId, 'Copied to clipboard.', 'ok');
    } catch (e) {
      setStatus(statusId, 'Select the text and press Ctrl+C (or Cmd+C) to copy it.');
    }
  }

  async function pasteInto(id, statusId) {
    try {
      $(id).value = await navigator.clipboard.readText();
    } catch (e) {
      setStatus(statusId, 'Your browser blocked automatic paste. Click in the box and press Ctrl+V (or Cmd+V).');
      $(id).focus();
    }
  }

  /* ---------- wiring ---------- */

  function init() {
    const supported = !!(window.RTCPeerConnection && window.crypto && crypto.subtle && window.isSecureContext);
    if (!supported) {
      $('unsupported').hidden = false;
      $('btn-host').disabled = true;
      $('btn-join').disabled = true;
      return;
    }

    $('btn-host').addEventListener('click', startHost);
    $('btn-join').addEventListener('click', () => {
      S.role = 'guest';
      S.statusId = 'join-status';
      show('join');
      $('invite-in').focus();
    });
    $('btn-connect').addEventListener('click', acceptReply);
    $('btn-reply').addEventListener('click', createReply);
    $('copy-invite').addEventListener('click', () => copyFrom('invite-out', 'host-status'));
    $('copy-reply').addEventListener('click', () => copyFrom('reply-out', 'join-status'));
    $('paste-reply').addEventListener('click', () => pasteInto('reply-in', 'host-status'));
    $('paste-invite').addEventListener('click', () => pasteInto('invite-in', 'join-status'));
    for (const b of document.querySelectorAll('button.cancel')) {
      b.addEventListener('click', () => location.reload());
    }
    $('btn-match').addEventListener('click', confirmMatch);
    $('btn-nomatch').addEventListener('click', () => {
      endSession("You reported that the codes don't match. Someone may have been intercepting the connection, so the chat was cancelled.");
    });
    $('btn-end').addEventListener('click', () => endSession('You ended the chat.'));
    $('btn-restart').addEventListener('click', () => location.reload());

    $('composer').addEventListener('submit', (e) => {
      e.preventDefault();
      sendMessage();
    });
    $('msg-input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
        e.preventDefault();
        sendMessage();
      }
    });

    for (const id of ['invite-out', 'reply-out']) {
      $(id).addEventListener('focus', (e) => e.target.select());
    }

    window.addEventListener('beforeunload', (e) => {
      if (S.opened && !S.ended) e.preventDefault();
    });
  }

  init();
})();

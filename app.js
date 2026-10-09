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
  const PROTO = 'whisper-link/v1';
  const MAX_TEXT = 4000;
  const MAX_FRAME = 24 * 1024;
  const MAX_CODE_CHARS = 24000;
  const MAX_SDP_CHARS = 16000;
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

  const errText = (e) => (e && e.message) || String(e);

  /* ---------- code (blob) packing ---------- */

  async function pipeBytes(bytes, transform) {
    const stream = new Blob([bytes]).stream().pipeThrough(transform);
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  async function packBlob(obj) {
    const raw = enc.encode(JSON.stringify(obj));
    if (typeof CompressionStream === 'function') {
      return 'WL1.' + b64u.enc(await pipeBytes(raw, new CompressionStream('deflate-raw')));
    }
    return 'WL0.' + b64u.enc(raw);
  }

  async function unpackBlob(text, expectedRole) {
    const t = String(text || '').replace(/\s+/g, '');
    if (t.length > MAX_CODE_CHARS) throw new Error('That code is too long to be a whisper-link code.');
    const m = /^WL([01])\.([A-Za-z0-9_-]+)$/.exec(t);
    if (!m) throw new Error("That doesn't look like a whisper-link code. Copy the whole thing, starting with WL.");
    let bytes;
    try {
      bytes = b64u.dec(m[2]);
      if (m[1] === '1') {
        if (typeof DecompressionStream !== 'function') throw new Error('This browser cannot read compressed codes.');
        bytes = await pipeBytes(bytes, new DecompressionStream('deflate-raw'));
      }
    } catch (e) {
      throw new Error('The code is damaged or incomplete. Copy it again in full.');
    }
    let obj;
    try {
      obj = JSON.parse(dec.decode(bytes));
    } catch (e) {
      throw new Error('The code is damaged or incomplete. Copy it again in full.');
    }
    if (!obj || obj.v !== 1) throw new Error('Unsupported code version.');
    if (obj.r !== expectedRole) {
      throw new Error(expectedRole === 'answer'
        ? 'That is an invite code. Paste the reply code the other person sent you.'
        : 'That is a reply code. Paste the invite code instead.');
    }
    if (typeof obj.s !== 'string' || obj.s.length > MAX_SDP_CHARS || typeof obj.k !== 'string') {
      throw new Error('Malformed code.');
    }
    return obj;
  }

  /* ---------- SDP / key validation ---------- */

  // Returns the DTLS fingerprint of a data-channel-only SDP, or throws.
  function inspectSdp(sdp) {
    if (!/^v=0\r?\n/.test(sdp)) throw new Error('Malformed connection data.');
    const mLines = sdp.match(/^m=.*$/gm) || [];
    if (mLines.length !== 1 || !/^m=application /.test(mLines[0])) {
      throw new Error('This code asks for more than a text chat (audio or video). Refusing it.');
    }
    const fps = new Set();
    for (const m of sdp.matchAll(/^a=fingerprint:(\S+) ([0-9A-Fa-f:]+)\s*$/gm)) {
      if (m[1].toLowerCase() !== 'sha-256') throw new Error('Unsupported fingerprint type.');
      fps.add(m[2].toUpperCase());
    }
    if (fps.size !== 1) throw new Error('The code has no usable security fingerprint.');
    return [...fps][0];
  }

  function parsePk(b64) {
    let bytes;
    try { bytes = b64u.dec(b64); } catch (e) { throw new Error('Malformed key in code.'); }
    if (bytes.length !== 65 || bytes[0] !== 4) throw new Error('Malformed key in code.');
    return bytes;
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

  async function establishKeys(peerPkB64, peerFp) {
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

    S.sas = sasString(sas);
    S.sendChain = { key: isHost ? h2g : g2h, n: 0 };
    S.recvChain = { key: isHost ? g2h : h2g, n: 0 };
    S.keys.priv = null;
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
    if (buf.length < 4) throw new Error('bad padding');
    const len = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(0);
    if (len > buf.length - 4) throw new Error('bad padding');
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
    if (frame.length < 8 + 16 + 256 || frame.length > MAX_FRAME) throw new Error('bad frame size');
    const aad = frame.subarray(0, 8);
    const n = Number(new DataView(frame.buffer, frame.byteOffset, 8).getBigUint64(0));
    if (n !== S.recvChain.n) throw new Error('out-of-order or replayed message');
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
      await establishKeys(msg.k, peerFp);
      await S.pc.setRemoteDescription({ type: 'answer', sdp: msg.s });
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

      resetConnection();
      S.keys = await genKeys();
      S.ownPk = b64u.enc(S.keys.pub);
      S.pc = makePc();
      S.pc.ondatachannel = (ev) => {
        if (S.dc || ev.channel.label !== 'chat') {
          ev.channel.close();
          return;
        }
        S.dc = ev.channel;
        wireChannel(S.dc);
        if (S.dc.readyState === 'open') onOpen();
      };
      await S.pc.setRemoteDescription({ type: 'offer', sdp: msg.s });
      await S.pc.setLocalDescription(await S.pc.createAnswer());
      await waitForIce(S.pc);
      const sdp = S.pc.localDescription.sdp;
      S.ownFp = inspectSdp(sdp);
      await establishKeys(msg.k, peerFp);
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
      if (!S.dc || S.dc.readyState !== 'open' || !S.sendChain) throw new Error('Not connected.');
      S.dc.send(await seal(obj));
    });
    S.sendQ = p.catch(() => {});
    return p;
  }

  async function handleFrame(frame) {
    if (S.ended || !S.recvChain) return;
    const m = await open(frame);
    if (!m || typeof m.t !== 'string') throw new Error('bad message');
    if (m.t === 'msg') {
      if (typeof m.text !== 'string' || m.text.length > MAX_TEXT) throw new Error('bad text');
      if (S.verifiedMe) addMessage('them', m.text);
      else S.pending.push({ text: m.text, at: new Date() });
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
      el.textContent = 'Both sides verified';
      el.dataset.kind = 'ok';
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
    bubble.textContent = text;
    const time = document.createElement('time');
    time.textContent = fmtTime(at || new Date());
    wrap.append(bubble, time);
    list.append(wrap);
    list.scrollTop = list.scrollHeight;
  }

  function addSystem(text) {
    const el = document.createElement('div');
    el.className = 'sys';
    el.textContent = text;
    $('messages').append(el);
  }

  function confirmMatch() {
    S.verifiedMe = true;
    show('chat');
    updatePeerState();
    addSystem('Codes confirmed on your side. Messages are end-to-end encrypted.');
    for (const p of S.pending) addMessage('them', p.text, p.at);
    S.pending = [];
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

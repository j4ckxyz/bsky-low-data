// app.js
// Bluesky Low Data – minimal posting client

// ------------------------
// Utilities
// ------------------------
const textEncoder = new TextEncoder();
const b64 = {
  urlencode(bytes) {
    let str = typeof bytes === 'string' ? bytes : btoa(String.fromCharCode(...new Uint8Array(bytes)));
    if (bytes instanceof ArrayBuffer || ArrayBuffer.isView(bytes)) {
      str = btoa(String.fromCharCode(...new Uint8Array(bytes)));
    }
    return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  },
  urldecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = str.length % 4 ? '='.repeat(4 - (str.length % 4)) : '';
    return atob(str + pad);
  }
};
function randomString(len = 64) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return b64.urlencode(bytes);
}
async function sha256(input) {
  const data = typeof input === 'string' ? textEncoder.encode(input) : input;
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}
function qs(params) {
  return new URLSearchParams(params).toString();
}

function coerceLocalRedirect(urlString) {
  try {
    const u = new URL(urlString);
    if (u.hostname === 'localhost') {
      u.hostname = '127.0.0.1';
      return u.toString();
    }
    return urlString;
  } catch {
    return urlString;
  }
}

// ------------------------
// Storage
// ------------------------
const storage = {
  get(key, fallback = null) {
    try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; }
  },
  set(key, value) { localStorage.setItem(key, JSON.stringify(value)); },
  del(key) { localStorage.removeItem(key); }
};

// ------------------------
// AT Protocol helpers
// ------------------------
async function resolveDidFromHandle(handle) {
  const url = `https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?${qs({ handle })}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to resolve handle');
  const data = await res.json();
  return data.did; // did:plc:...
}

async function discoverPdsFromDid(did) {
  // Fetch DID doc from PLC directory
  const res = await fetch(`https://plc.directory/${did}`);
  if (!res.ok) throw new Error('Failed to fetch DID document');
  const doc = await res.json();
  const services = doc?.service || [];
  let endpoint = null;
  for (const s of services) {
    const id = s?.id || '';
    const typ = s?.type || '';
    if (id === 'atproto_pds' || /Atproto.*PDS|PersonalDataServer/i.test(typ)) {
      endpoint = s.serviceEndpoint || s.endpoint || s.url || null;
      break;
    }
  }
  if (!endpoint) throw new Error('PDS endpoint not found in DID doc');
  return endpoint.replace(/\/$/, '');
}

function ensureTrailing(path, ch = '/') {
  return path.endsWith(ch) ? path : path + ch;
}

// ------------------------
// Session and auth state
// ------------------------
const session = {
  state: {
    accessJwt: null,
    refreshJwt: null,
    did: null,
    handle: null,
    pds: null,
    authType: null, // 'apppw' | 'oauth'
    oauth: {
      codeVerifier: null,
      clientId: null,
      redirectUri: null,
      metadata: null,
      dpopKeyId: null,
    }
  },
  load() {
    const saved = storage.get('bsky.session');
    if (saved) this.state = saved;
    return this.state;
  },
  save() { storage.set('bsky.session', this.state); },
  clear() { storage.del('bsky.session'); this.state = { oauth: {} }; }
};

// ------------------------
// HTTP helpers
// ------------------------
async function apiFetch(path, { method = 'GET', headers = {}, body } = {}) {
  const { pds, accessJwt, authType } = session.state;
  if (!pds) throw new Error('No PDS configured');
  const url = `${ensureTrailing(pds)}xrpc/${path}`;
  const h = new Headers(headers);
  if (accessJwt) {
    // For app password we use Bearer; for OAuth we likely need DPoP Authorization
    if (authType === 'oauth') {
      h.set('Authorization', `DPoP ${accessJwt}`);
      const proof = await makeDpopProof(url, method);
      h.set('DPoP', proof);
    } else {
      h.set('Authorization', `Bearer ${accessJwt}`);
    }
  }
  const res = await fetch(url, { method, headers: h, body });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`API ${method} ${path} failed: ${res.status} ${text}`);
  }
  const ctype = res.headers.get('content-type') || '';
  if (ctype.includes('application/json')) return res.json();
  return res;
}

// ------------------------
// App password login
// ------------------------
async function loginWithAppPassword(identifier, password) {
  const inputId = (identifier || '').trim();
  const normalizedId = inputId.startsWith('did:') ? inputId : inputId.replace(/^@/, '');
  let did = normalizedId;
  if (!normalizedId.startsWith('did:')) {
    did = await resolveDidFromHandle(normalizedId);
  }
  const pds = await discoverPdsFromDid(did);
  const res = await fetch(`${ensureTrailing(pds)}xrpc/com.atproto.server.createSession`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ identifier: normalizedId, password })
  });
  if (!res.ok) {
    let msg = `${res.status}`;
    try {
      const j = await res.json();
      msg += ` ${j?.error || ''} ${j?.message || ''}`.trim();
    } catch {
      try { msg += ` ${await res.text()}`; } catch {}
    }
    throw new Error(`Login failed. ${msg}. Check your handle and app password.`);
  }
  const data = await res.json();
  session.state = {
    ...session.state,
    accessJwt: data.accessJwt,
    refreshJwt: data.refreshJwt,
    did: data.did,
    handle: data.handle,
    pds,
    authType: 'apppw'
  };
  session.save();
  return session.state;
}

// ------------------------
// OAuth (Experimental): PKCE + PAR + DPoP
// ------------------------
async function getOAuthMetadata(pdsOrigin) {
  const url = new URL('/.well-known/oauth-authorization-server', pdsOrigin).toString();
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) throw new Error('Failed to load OAuth metadata');
  return res.json();
}

async function startOAuth(handle, redirectUri) {
  const normalized = handle.replace(/^@/, '');
  const did = await resolveDidFromHandle(normalized);
  const pds = await discoverPdsFromDid(did);
  let metadata;
  try {
    metadata = await getOAuthMetadata(pds);
  } catch (e) {
    throw new Error(`Failed to load OAuth metadata from your PDS (${pds}). This PDS may not support OAuth yet, or it may block metadata discovery. ${e?.message || ''}`);
  }

  const codeVerifier = randomString(64);
  const codeChallenge = b64.urlencode(await sha256(codeVerifier));

  // Public client: client_id is our site origin (recommended), or our redirect URI
  const clientId = new URL(redirectUri, location.href).origin;

  // Push the authorization request (PAR)
  const parParams = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    scope: 'atproto',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    // Provide login hint to streamline account selection
    login_hint: handle,
  });

  // DPoP setup for token and later resource calls
  await ensureDpopKey();

  const parRes = await fetch(metadata.pushed_authorization_request_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: parParams.toString()
  });
  if (!parRes.ok) {
    const txt = await parRes.text().catch(()=> '');
    throw new Error(`PAR request failed: ${parRes.status} ${txt}`);
  }
  const par = await parRes.json(); // { request_uri, expires_in }

  session.state = {
    ...session.state,
    did,
    handle,
    pds,
    authType: 'oauth',
    oauth: { codeVerifier, clientId, redirectUri, metadata }
  };
  session.save();

  // Redirect to authorization endpoint with request_uri
  const authUrl = new URL(metadata.authorization_endpoint);
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('request_uri', par.request_uri);
  window.location.href = authUrl.toString();
}

async function handleOAuthCallback() {
  session.load();
  const { oauth, pds } = session.state;
  if (!oauth?.codeVerifier) throw new Error('Missing PKCE state');
  const url = new URL(window.location.href);
  const code = url.searchParams.get('code');
  const iss = url.searchParams.get('iss');
  if (!code) throw new Error('Missing authorization code');

  const tokenUrl = oauth.metadata?.token_endpoint;
  if (!tokenUrl) throw new Error('Missing token endpoint');

  // Compute DPoP JKT thumbprint
  const { jkt } = await getDpopThumbprint();

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: oauth.clientId,
    redirect_uri: oauth.redirectUri,
    code,
    code_verifier: oauth.codeVerifier,
    dpop_jkt: jkt,
  });

  // DPoP proof for token endpoint
  const proof = await makeDpopProof(tokenUrl, 'POST');
  const res = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'DPoP': proof
    },
    body: body.toString()
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    throw new Error(`Token exchange failed: ${res.status} ${txt}`);
  }
  const tok = await res.json(); // { access_token, refresh_token?, token_type: 'DPoP' }

  session.state = {
    ...session.state,
    accessJwt: tok.access_token,
    refreshJwt: tok.refresh_token || null,
    authType: 'oauth'
  };
  session.save();
}

// ------------------------
// DPoP key and proof
// ------------------------
async function ensureDpopKey() {
  let kid = storage.get('bsky.dpop.kid');
  if (kid) return kid;
  const key = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const jwk = await crypto.subtle.exportKey('jwk', key.publicKey);
  const priv = await crypto.subtle.exportKey('jwk', key.privateKey);
  // Persist in IndexedDB would be better; use localStorage for simplicity
  storage.set('bsky.dpop.key', { publicJwk: jwk, privateJwk: priv });
  kid = randomString(24);
  storage.set('bsky.dpop.kid', kid);
  return kid;
}
async function loadDpopKey() {
  const { publicJwk, privateJwk } = storage.get('bsky.dpop.key') || {};
  if (!publicJwk || !privateJwk) throw new Error('DPoP key missing');
  const publicKey = await crypto.subtle.importKey('jwk', publicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  const privateKey = await crypto.subtle.importKey('jwk', privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  return { publicJwk, publicKey, privateKey };
}
async function getDpopThumbprint() {
  const { publicJwk } = await loadDpopKey();
  // JWK thumbprint (RFC 7638) over ordered members crv, kty, x, y
  const ordered = { crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y };
  const json = JSON.stringify(ordered);
  const digest = await sha256(textEncoder.encode(json));
  return { jkt: b64.urlencode(digest) };
}
async function makeDpopProof(htu, htm = 'GET', nonce) {
  const { publicJwk, privateKey } = await loadDpopKey();
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk };
  const payload = { htu, htm, iat: Math.floor(Date.now() / 1000), jti: crypto.randomUUID?.() || randomString(16) };
  if (nonce) payload.nonce = nonce;
  const encHeader = b64.urlencode(textEncoder.encode(JSON.stringify(header)));
  const encPayload = b64.urlencode(textEncoder.encode(JSON.stringify(payload)));
  const toSign = `${encHeader}.${encPayload}`;
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, textEncoder.encode(toSign));
  const encSig = b64.urlencode(sig);
  return `${encHeader}.${encPayload}.${encSig}`;
}

// ------------------------
// Facets (links and hashtags)
// ------------------------
const urlRegex = /https?:\/\/[\w.-]+(?:\/[\w\-._~:/?#[\]@!$&'()*+,;=%]*)?/gi;
const hashRegex = /(^|\s)#([\p{L}\p{N}_]+)\b/giu;
function utf8ByteOffsets(text, startChar, endChar) {
  const pre = text.slice(0, startChar);
  const mid = text.slice(startChar, endChar);
  const byteStart = textEncoder.encode(pre).length;
  const byteEnd = byteStart + textEncoder.encode(mid).length;
  return { byteStart, byteEnd };
}
function buildFacets(text) {
  const facets = [];
  // Links
  for (const match of text.matchAll(urlRegex)) {
    const start = match.index ?? 0;
    const end = start + match[0].length;
    const { byteStart, byteEnd } = utf8ByteOffsets(text, start, end);
    facets.push({
      index: { byteStart, byteEnd },
      features: [{ $type: 'app.bsky.richtext.facet#link', uri: match[0] }]
    });
  }
  // Hashtags
  for (const match of text.matchAll(hashRegex)) {
    const tag = match[2];
    if (!tag) continue;
    const start = (match.index ?? 0) + (match[1]?.length || 0);
    const end = start + 1 + tag.length; // include '#'
    const { byteStart, byteEnd } = utf8ByteOffsets(text, start, end);
    facets.push({
      index: { byteStart, byteEnd },
      features: [{ $type: 'app.bsky.richtext.facet#tag', tag }]
    });
  }
  return facets.length ? facets : undefined;
}

// ------------------------
// Image processing
// ------------------------
async function compressImage(file, { maxDim = 1600, quality = 0.85 } = {}) {
  const img = await (async () => {
    if (window.createImageBitmap) {
      try { return await createImageBitmap(file); } catch {}
    }
    // Fallback via HTMLImageElement
    const url = URL.createObjectURL(file);
    try {
      await new Promise((resolve, reject) => {
        const i = new Image();
        i.onload = () => { resolve(); };
        i.onerror = reject;
        i.src = url;
      });
      const i2 = new Image(); i2.src = url; return i2;
    } finally {
      // do not revoke immediately; keep until drawImage finishes
      setTimeout(() => URL.revokeObjectURL(url), 3000);
    }
  })();

  let width = img.width, height = img.height;
  const scale = Math.min(1, maxDim / Math.max(width, height));
  const targetW = Math.round(width * scale);
  const targetH = Math.round(height * scale);

  // Use OffscreenCanvas when available, else fallback to regular canvas
  let blob;
  if (typeof OffscreenCanvas !== 'undefined') {
    const canvas = new OffscreenCanvas(targetW, targetH);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0, targetW, targetH);
    blob = await canvas.convertToBlob({ type: 'image/jpeg', quality });
  } else {
    const canvas = document.createElement('canvas');
    canvas.width = targetW; canvas.height = targetH;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0, targetW, targetH);
    blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', quality));
  }
  return new File([blob], file.name.replace(/\.[^.]+$/, '.jpg'), { type: 'image/jpeg' });
}

async function uploadBlob(file) {
  const res = await apiFetch('com.atproto.repo.uploadBlob', {
    method: 'POST',
    headers: { 'content-type': file.type },
    body: file
  });
  return res.blob; // { $type:"blob", ref:{ $link: CID }, mimeType, size }
}

// ------------------------
// Posting
// ------------------------
async function createPost({ text, images, alts, reply }) {
  const record = {
    $type: 'app.bsky.feed.post',
    text,
    createdAt: new Date().toISOString()
  };
  const facets = buildFacets(text);
  if (facets) record.facets = facets;

  if (images && images.length) {
    const imgs = [];
    for (let i = 0; i < images.length; i++) {
      const file = images[i];
      const uploaded = await uploadBlob(file);
      imgs.push({
        image: uploaded,
        alt: alts?.[i] || ''
      });
    }
    record.embed = { $type: 'app.bsky.embed.images', images: imgs };
  }

  if (reply?.parentUri && reply?.parentCid) {
    const rootUri = reply.rootUri || reply.parentUri;
    const rootCid = reply.rootCid || reply.parentCid;
    record.reply = {
      root: { uri: rootUri, cid: rootCid },
      parent: { uri: reply.parentUri, cid: reply.parentCid }
    };
  }

  const { did } = session.state;
  const res = await apiFetch('com.atproto.repo.createRecord', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      repo: did,
      collection: 'app.bsky.feed.post',
      record
    })
  });
  return res; // { uri, cid, ... }
}

// ------------------------
// UI wiring
// ------------------------
function $(sel) { return document.querySelector(sel); }
function setHidden(el, hidden) { el.hidden = !!hidden; }

function initTabs() {
  const tabs = document.querySelectorAll('.tab');
  tabs.forEach(btn => btn.addEventListener('click', () => {
    tabs.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const which = btn.dataset.tab;
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    if (which === 'oauth') $('#tab-oauth').classList.add('active');
    if (which === 'apppw') $('#tab-apppw').classList.add('active');
  }));
}

function updateSessionUI() {
  const s = session.state;
  const loggedIn = !!(s?.accessJwt && s?.did);
  setHidden($('#login-section'), loggedIn);
  setHidden($('#session-section'), !loggedIn);
  setHidden($('#composer'), !loggedIn);
  setHidden($('#btn-logout'), !loggedIn);
  if (loggedIn) {
    $('#session-identity').textContent = `${s.handle || s.did}`;
    try { $('#pds-host').textContent = new URL(s.pds).host; } catch { $('#pds-host').textContent = s.pds || '—'; }
  }
}

function initInstallPrompt() {
  let deferred;
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferred = e;
    const btn = $('#btn-install');
    setHidden(btn, false);
    btn.onclick = async () => { deferred?.prompt(); };
  });
}

function countBytesAndUpdate() {
  const text = $('#post-text').value || '';
  const bytes = textEncoder.encode(text).length;
  $('#byte-count').textContent = String(bytes);
  if (bytes > 300) $('#byte-count').style.color = 'var(--danger)'; else $('#byte-count').style.color = 'var(--muted)';
}

function updateImageList(files) {
  const list = $('#image-list');
  list.innerHTML = '';
  const max = Math.min(files.length, 4);
  for (let i = 0; i < max; i++) {
    const file = files[i];
    const url = URL.createObjectURL(file);
    const item = document.createElement('div');
    item.className = 'image-item';
    item.innerHTML = `
      <img src="${url}" alt="preview"/>
      <label class="full small"><span>Alt text</span>
        <input data-alt-for="${i}" type="text" maxlength="1000" placeholder="Describe the image" />
      </label>
    `;
    list.appendChild(item);
  }
}

function collectAlts(max) {
  const alts = [];
  for (let i = 0; i < max; i++) {
    const el = document.querySelector(`input[data-alt-for="${i}"]`);
    alts.push(el?.value || '');
  }
  return alts;
}

function initUI() {
  initTabs();
  initInstallPrompt();

  // Default redirect URI
  const defaultRedirect = coerceLocalRedirect(new URL('oauth-callback.html', location.href).toString());
  const redirectEl = $('#oauth-redirect');
  redirectEl.value = defaultRedirect;

  // Byte counter
  $('#post-text').addEventListener('input', countBytesAndUpdate);
  countBytesAndUpdate();

  // Image input
  $('#image-input').addEventListener('change', (e) => {
    updateImageList(e.target.files || []);
  });

  // Logout
  $('#btn-logout').addEventListener('click', () => {
    session.clear();
    updateSessionUI();
  });

  // OAuth form
  $('#form-oauth').addEventListener('submit', async (e) => {
    e.preventDefault();
    const handle = $('#oauth-handle').value.trim();
    let redirect = $('#oauth-redirect').value.trim();
    // Replace localhost with 127.0.0.1 to satisfy RFC 8252 loopback rule
    const coerced = coerceLocalRedirect(redirect);
    if (coerced !== redirect) {
      redirect = coerced;
      $('#oauth-redirect').value = redirect;
    }
    if (!handle || !redirect) return;
    try {
      $('#btn-oauth-start').disabled = true;
      await startOAuth(handle, redirect);
    } catch (err) {
      alert(err.message || 'OAuth failed');
    } finally {
      $('#btn-oauth-start').disabled = false;
    }
  });

  // App password form
  $('#form-apppw').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = $('#apppw-identifier').value.trim();
    const pw = $('#apppw-password').value;
    try {
      $('#btn-apppw-login').disabled = true;
      await loginWithAppPassword(id, pw);
      updateSessionUI();
    } catch (err) {
      alert(err.message || 'Login failed');
    } finally {
      $('#btn-apppw-login').disabled = false;
    }
  });

  // Compose form
  $('#form-compose').addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = $('#post-text').value.trim();
    const files = Array.from($('#image-input').files || []).slice(0, 4);
    const compress = $('#compress-toggle').checked;
    const maxDim = parseInt($('#max-dim').value || '1600', 10);
    const quality = parseFloat($('#quality').value || '0.85');

    const reply = {
      parentUri: $('#reply-parent-uri').value.trim() || null,
      parentCid: $('#reply-parent-cid').value.trim() || null,
      rootUri: $('#reply-root-uri').value.trim() || null,
      rootCid: $('#reply-root-cid').value.trim() || null,
    };
    if (!reply.parentUri || !reply.parentCid) delete reply.parentUri, delete reply.parentCid, delete reply.rootUri, delete reply.rootCid;

    const byteLen = textEncoder.encode(text).length;
    if (byteLen > 300) { alert('Post exceeds 300-byte limit'); return; }

    try {
      $('#btn-post').disabled = true;
      let processedFiles = files;
      if (compress && files.length) {
        processedFiles = [];
        for (const f of files) {
          try { processedFiles.push(await compressImage(f, { maxDim, quality })); }
          catch { processedFiles.push(f); }
        }
      }
      const alts = collectAlts(processedFiles.length);
      const res = await createPost({ text, images: processedFiles, alts, reply });
      $('#post-result').value = `Posted: ${res.uri}`;
      // Reset form
      $('#post-text').value = '';
      $('#image-input').value = '';
      $('#image-list').innerHTML = '';
      countBytesAndUpdate();
    } catch (err) {
      alert(err.message || 'Post failed');
    } finally {
      $('#btn-post').disabled = false;
    }
  });
}

// ------------------------
// Boot
// ------------------------
(function boot() {
  session.load();
  if (document.getElementById('oauth-redirect')) {
    // main page
    updateSessionUI();
    initUI();
  }
})();

export { handleOAuthCallback };

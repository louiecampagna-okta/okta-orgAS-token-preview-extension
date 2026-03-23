// Okta Token Preview — Content Script
// Runs on Okta admin app detail pages. Injects the Token Preview button and
// proxies Okta Management API calls (using the admin's browser session cookies).

(function () {
  'use strict';

  // ─── URL Parsing ─────────────────────────────────────────────────────────────

  function parseOktaAppUrl() {
    const { hostname, pathname } = window.location;
    // Okta admin URL format: /admin/app/{appType}/instance/{appId}[/...]
    const match = pathname.match(/\/admin\/app\/([^/]+)\/instance\/([^/]+)/);
    if (!match) return null;
    return {
      domain: hostname,
      appType: match[1],  // e.g. "oidc_client"
      appId: match[2],    // e.g. "0oajqa3bf5o9CCAxR696"
    };
  }

  const ctx = parseOktaAppUrl();
  if (!ctx) return;

  // ─── Okta API Helpers ────────────────────────────────────────────────────────
  //
  // Approach derived from the Rockstar extension (gabrielsroka.github.io/rockstar):
  //  • Use location.origin (same domain as admin console) — no cross-origin issues
  //  • Rely on the session cookie (credentials: 'include') — no bearer token needed
  //  • Read #_xsrfToken from the page DOM and send as X-Okta-XsrfToken for
  //    state-mutating requests — this is how the admin console protects PUT/POST
  //  • Bearer tokens from okta-token-storage don't have okta.apps.manage write
  //    scope and were causing the 403 errors on PUT requests

  function getXsrfToken() {
    // Okta embeds the CSRF token in a hidden span with id="_xsrfToken"
    return document.querySelector('#_xsrfToken')?.textContent?.trim() || null;
  }

  const UA_HEADER = { 'X-Okta-User-Agent-Extended': 'okta-token-preview' };

  async function oktaGet(path) {
    const res = await fetch(`https://${ctx.domain}${path}`, {
      credentials: 'include',
      headers: { Accept: 'application/json', ...UA_HEADER },
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.errorSummary || `API error ${res.status}`);
    }
    return res.json();
  }

  async function oktaPut(path, payload) {
    const xsrf = getXsrfToken();
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...UA_HEADER,
    };
    if (xsrf) headers['X-Okta-XsrfToken'] = xsrf;

    const res = await fetch(`https://${ctx.domain}${path}`, {
      method: 'PUT',
      credentials: 'include',
      headers,
      body: JSON.stringify(deepClean(payload)),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.errorSummary || `API error ${res.status}`);
    }
    return res.json();
  }

  // ─── Message Handler ─────────────────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    switch (message.action) {
      case 'GET_CONTEXT':
        sendResponse({ success: true, context: ctx });
        break;

      case 'GET_APP_DETAILS': {
        const appId = message.appId || ctx.appId;
        oktaGet(`/api/v1/apps/${appId}`)
          .then(app => sendResponse({ success: true, app }))
          .catch(err => sendResponse({ success: false, error: err.message }));
        return true;
      }

      case 'SEARCH_USERS': {
        const q = encodeURIComponent(message.query || '');
        const limit = message.limit || 10;
        oktaGet(`/api/v1/users?q=${q}&limit=${limit}`)
          .then(users => sendResponse({ success: true, users }))
          .catch(err => sendResponse({ success: false, error: err.message }));
        return true;
      }

      case 'ADD_REDIRECT_URI': {
        const { appId, redirectUri } = message;
        oktaGet(`/api/v1/apps/${appId}`)
          .then(app => {
            const current = app.settings?.oauthClient?.redirect_uris || [];
            if (current.includes(redirectUri)) {
              return sendResponse({ success: true, alreadyPresent: true, app });
            }
            // Deep-copy via JSON so we don't mutate the fetched object
            const updated = JSON.parse(JSON.stringify(app));
            updated.settings.oauthClient.redirect_uris = [...current, redirectUri];
            return oktaPut(`/api/v1/apps/${appId}`, updated)
              .then(updatedApp => sendResponse({ success: true, app: updatedApp }));
          })
          .catch(err => sendResponse({ success: false, error: err.message }));
        return true;
      }

      case 'REMOVE_REDIRECT_URI': {
        const { appId, redirectUri } = message;
        oktaGet(`/api/v1/apps/${appId}`)
          .then(app => {
            const current = app.settings?.oauthClient?.redirect_uris || [];
            const filtered = current.filter(uri => uri !== redirectUri);
            if (filtered.length === current.length) {
              return sendResponse({ success: true, noop: true });
            }
            const updated = JSON.parse(JSON.stringify(app));
            updated.settings.oauthClient.redirect_uris = filtered;
            return oktaPut(`/api/v1/apps/${appId}`, updated)
              .then(updatedApp => sendResponse({ success: true, app: updatedApp }));
          })
          .catch(err => sendResponse({ success: false, error: err.message }));
        return true;
      }

      case 'SHOW_TOKEN_OVERLAY':
        // Route into the panel if it's open, otherwise fall back to the overlay
        if (isPanelOpen()) {
          updatePanelWithResult(message.result);
        } else {
          showTokenOverlay(message.result);
        }
        sendResponse({ success: true });
        break;

      default:
        break;
    }
  });

  // ─── Token Overlay ────────────────────────────────────────────────────────────

  const OVERLAY_HOST_ID = 'okta-token-preview-overlay-host';

  const CLAIM_META = {
    iss: 'Issuer', sub: 'Subject', aud: 'Audience',
    exp: 'Expiration', iat: 'Issued At', nbf: 'Not Before', jti: 'JWT ID',
    nonce: 'Nonce', auth_time: 'Auth Time', acr: 'Auth Context Class',
    amr: 'Auth Methods', azp: 'Authorized Party', at_hash: 'Access Token Hash',
    name: 'Full Name', given_name: 'Given Name', family_name: 'Family Name',
    email: 'Email', email_verified: 'Email Verified',
    preferred_username: 'Username', locale: 'Locale', zoneinfo: 'Timezone',
    phone_number: 'Phone', updated_at: 'Updated At',
    scp: 'Scopes', ver: 'Version', uid: 'User ID', cid: 'Client ID',
    groups: 'Groups',
  };
  const TIME_CLAIMS = new Set(['exp', 'iat', 'nbf', 'auth_time', 'updated_at']);

  function esc(str) {
    return String(str)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function decodeJWT(token) {
    try {
      const [h, p] = token.split('.');
      const parse = b64 => JSON.parse(atob(b64.replace(/-/g, '+').replace(/_/g, '/')));
      return { header: parse(h), payload: parse(p) };
    } catch { return null; }
  }

  function fmtValue(key, val) {
    if (TIME_CLAIMS.has(key) && typeof val === 'number') {
      const d = new Date(val * 1000);
      const diff = val * 1000 - Date.now();
      const abs = Math.abs(diff);
      const rel = abs < 60000 ? 'just now'
        : abs < 3600000 ? `${Math.round(abs / 60000)}m ${diff > 0 ? 'remaining' : 'ago'}`
        : `${Math.round(abs / 3600000)}h ${diff > 0 ? 'remaining' : 'ago'}`;
      return `<span class="time-val">${esc(d.toLocaleString())}</span> <span class="time-rel">${esc(rel)}</span>`;
    }
    if (Array.isArray(val)) {
      return val.map(v => `<span class="tag">${esc(String(v))}</span>`).join(' ');
    }
    if (typeof val === 'boolean') {
      return `<span class="bool bool--${val}">${val}</span>`;
    }
    if (typeof val === 'object' && val !== null) {
      return `<code class="json-val">${esc(JSON.stringify(val))}</code>`;
    }
    return `<span class="scalar">${esc(String(val))}</span>`;
  }

  function buildClaimsTable(obj) {
    return '<table class="claims">' +
      Object.entries(obj).map(([k, v]) => {
        const label = CLAIM_META[k] || '';
        return `<tr>
          <td class="ck">
            <code>${esc(k)}</code>
            ${label ? `<span class="cl">${esc(label)}</span>` : ''}
          </td>
          <td class="cv">${fmtValue(k, v)}</td>
        </tr>`;
      }).join('') +
      '</table>';
  }

  function buildJWTPanel(jwt) {
    if (!jwt) return '<p class="absent">Not present in this response.</p>';
    const d = decodeJWT(jwt);
    if (!d) return '<p class="absent">Could not decode token.</p>';
    const parts = jwt.split('.');
    return `
      <div class="section">
        <div class="section-title">Payload</div>
        ${buildClaimsTable(d.payload)}
      </div>
      <div class="section">
        <div class="section-title">
          Raw JWT
          <button class="copy-jwt-btn" data-jwt="${esc(jwt)}">Copy</button>
        </div>
        <div class="raw-jwt">
          <span class="jh">${esc(parts[0])}</span
          >.<span class="jp">${esc(parts[1])}</span
          >.<span class="js">${esc(parts[2])}</span>
        </div>
      </div>`;
  }

  const OVERLAY_CSS = `
    *{box-sizing:border-box;margin:0;padding:0}
    :host{all:initial}
    .overlay{
      position:fixed;top:0;right:0;width:460px;height:100vh;
      background:#fff;border-left:1px solid #dde1e7;
      display:flex;flex-direction:column;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      font-size:13px;color:#1d1d21;z-index:2147483647;
      box-shadow:-8px 0 32px rgba(0,0,0,.12);
      animation:slide-in .22s ease;
    }
    @keyframes slide-in{from{transform:translateX(100%)}to{transform:translateX(0)}}
    .hdr{
      display:flex;align-items:center;gap:10px;
      padding:12px 16px;background:#f4f4f6;
      border-bottom:1px solid #dde1e7;flex-shrink:0;
    }
    .hdr-icon{
      width:28px;height:28px;background:#007dc1;border-radius:7px;
      display:flex;align-items:center;justify-content:center;flex-shrink:0;
    }
    .hdr-title{flex:1;font-weight:700;font-size:14px;color:#1d1d21}
    .hdr-sub{font-size:11px;color:#6e6e78;font-family:'SF Mono','Fira Code',monospace}
    .close-btn{
      background:none;border:none;color:#6e6e78;cursor:pointer;
      font-size:18px;line-height:1;padding:4px;border-radius:4px;
    }
    .close-btn:hover{color:#1d1d21;background:rgba(0,0,0,.06)}
    .tabs{
      display:flex;border-bottom:1px solid #dde1e7;
      background:#f4f4f6;flex-shrink:0;
    }
    .tab{
      background:none;border:none;border-bottom:2px solid transparent;
      color:#6e6e78;cursor:pointer;font-size:12px;font-weight:600;
      padding:8px 16px 9px;font-family:inherit;transition:color .15s,border-color .15s;
    }
    .tab:hover{color:#1d1d21}
    .tab.active{color:#007dc1;border-bottom-color:#007dc1}
    .panels{flex:1;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#dde1e7 transparent}
    .panels::-webkit-scrollbar{width:4px}
    .panels::-webkit-scrollbar-thumb{background:#dde1e7;border-radius:2px}
    .panel{padding:14px;display:flex;flex-direction:column;gap:14px}
    .panel.hidden{display:none}
    .section{display:flex;flex-direction:column;gap:8px}
    .section-title{
      font-size:11px;font-weight:700;text-transform:uppercase;
      letter-spacing:.07em;color:#6e6e78;
      padding-bottom:6px;border-bottom:1px solid #dde1e7;
      display:flex;align-items:center;justify-content:space-between;
    }
    .claims{width:100%;border-collapse:collapse;font-size:12px}
    .claims tr{border-bottom:1px solid #f0f0f4}
    .claims tr:hover{background:#fafafa}
    .ck{padding:6px 8px 6px 0;vertical-align:top;width:38%;white-space:nowrap}
    .ck code{
      font-family:'SF Mono','Fira Code',monospace;font-size:11px;
      color:#005f99;background:#e8f3fb;
      padding:1px 5px;border-radius:3px;
    }
    .cl{display:block;font-size:10px;color:#9898a6;font-style:italic;margin-top:2px}
    .cv{padding:6px 0;vertical-align:top;word-break:break-all}
    .scalar{color:#1d1d21;font-family:'SF Mono','Fira Code',monospace;font-size:11px}
    .time-val{color:#8b5e00;font-size:11px}
    .time-rel{color:#9898a6;font-size:10px}
    .tag{
      display:inline-block;background:#e8f3fb;color:#005f99;
      border:1px solid #c2dff2;border-radius:4px;
      padding:1px 6px;font-size:11px;margin:1px 2px 1px 0;
      font-family:'SF Mono','Fira Code',monospace;
    }
    .bool--true{color:#00856f;font-weight:600}
    .bool--false{color:#b52f2f;font-weight:600}
    .json-val{font-family:'SF Mono','Fira Code',monospace;font-size:10px;color:#6e6e78}
    .raw-jwt{
      background:#f4f4f6;border:1px solid #dde1e7;border-radius:6px;
      padding:10px;font-family:'SF Mono','Fira Code',monospace;
      font-size:10px;word-break:break-all;line-height:1.6;
    }
    .jh{color:#c0392b}.jp{color:#27ae60}.js{color:#d97706}
    .copy-jwt-btn{
      background:#fff;border:1px solid #dde1e7;color:#6e6e78;
      border-radius:4px;padding:3px 8px;font-size:11px;cursor:pointer;
      font-family:inherit;font-weight:500;
    }
    .copy-jwt-btn:hover{border-color:#007dc1;color:#005f99}
    .absent{color:#9898a6;font-style:italic;padding:8px 0}
    .error-wrap{
      margin:20px 16px;padding:16px;
      background:#fef2f2;border:1px solid #fca5a5;
      border-radius:8px;color:#b52f2f;font-size:13px;line-height:1.5;
      display:flex;gap:10px;align-items:flex-start;
    }
  `;

  function showTokenOverlay(result) {
    // Remove any existing overlay
    document.getElementById(OVERLAY_HOST_ID)?.remove();

    const host = document.createElement('div');
    host.id = OVERLAY_HOST_ID;
    const shadow = host.attachShadow({ mode: 'open' });

    const appLabel = ctx ? `${ctx.appType} / ${ctx.appId}` : '';

    let body;
    if (result.error) {
      body = `
        <div class="error-wrap">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0;margin-top:1px">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          ${esc(result.error)}
        </div>`;
    } else {
      const { accessToken, idToken } = result.tokens || {};
      body = `
        <div class="tabs">
          <button class="tab active" data-panel="at">Access Token</button>
          <button class="tab" data-panel="it">ID Token</button>
        </div>
        <div class="panels">
          <div class="panel" id="panel-at">${buildJWTPanel(accessToken)}</div>
          <div class="panel hidden" id="panel-it">${buildJWTPanel(idToken)}</div>
        </div>`;
    }

    shadow.innerHTML = `
      <style>${OVERLAY_CSS}</style>
      <div class="overlay">
        <div class="hdr">
          <div class="hdr-icon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M9 12l2 2 4-4"/>
            </svg>
          </div>
          <div>
            <div class="hdr-title">Token Preview</div>
            ${appLabel ? `<div class="hdr-sub">${esc(appLabel)}</div>` : ''}
          </div>
          <button class="close-btn" id="close-btn" title="Close">✕</button>
        </div>
        ${body}
      </div>`;

    // Wire up close button
    shadow.getElementById('close-btn').addEventListener('click', hideTokenOverlay);

    // Wire up tabs
    shadow.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', () => {
        shadow.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        shadow.querySelectorAll('.panel').forEach(p => p.classList.add('hidden'));
        tab.classList.add('active');
        shadow.getElementById(`panel-${tab.dataset.panel}`)?.classList.remove('hidden');
      });
    });

    // Wire up copy buttons
    shadow.querySelectorAll('.copy-jwt-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        navigator.clipboard.writeText(btn.dataset.jwt).catch(() => {});
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = orig; }, 1500);
      });
    });

    document.body.appendChild(host);
  }

  function hideTokenOverlay() {
    document.getElementById(OVERLAY_HOST_ID)?.remove();
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────────

  // The admin console lives on {org}-admin.okta.com; OAuth endpoints are on {org}.okta.com
  function getOAuthDomain() {
    return ctx.domain.replace(
      /^(.+?)-admin(\.(okta\.com|okta-emea\.com|oktapreview\.com))$/,
      '$1$2'
    );
  }

  // Deep-strip all underscore-prefixed keys (e.g. _links, _embedded) at every
  // level of the object. Okta adds these to GET responses but rejects them on PUT.
  function deepClean(obj) {
    if (Array.isArray(obj)) return obj.map(deepClean);
    if (obj && typeof obj === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(obj)) {
        if (!k.startsWith('_')) out[k] = deepClean(v);
      }
      return out;
    }
    return obj;
  }

  function bgSend(message) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, res => {
        if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
        else resolve(res);
      });
    });
  }

  // ─── Token Preview Panel ──────────────────────────────────────────────────────

  const PANEL_HOST_ID = 'okta-token-preview-panel-host';
  const PANEL_SCOPES = [
    { v: 'openid',       req: true  },
    { v: 'profile',      req: false },
    { v: 'email',        req: false },
    { v: 'groups',       req: false },
    { v: 'offline_access', req: false },
    { v: 'phone',        req: false },
    { v: 'address',      req: false },
  ];

  let panelShadow = null;
  let panelApp = null;
  let panelRedirectUri = null;
  let panelSelectedScopes = new Set(['openid', 'profile', 'email']);

  function isPanelOpen() {
    return !!document.getElementById(PANEL_HOST_ID);
  }

  function closePanel() {
    stopPolling();
    document.getElementById(PANEL_HOST_ID)?.remove();
    panelShadow = null;
  }

  const PANEL_CSS = `
    *{box-sizing:border-box;margin:0;padding:0}
    :host{all:initial}
    .hidden{display:none!important}
    .panel{
      position:fixed;top:0;right:0;width:460px;height:100vh;
      background:#fff;border-left:1px solid #dde1e7;
      display:flex;flex-direction:column;overflow:hidden;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      font-size:13px;color:#1d1d21;z-index:2147483647;
      box-shadow:-8px 0 32px rgba(0,0,0,.12);
      animation:slide-in .22s ease;
    }
    @keyframes slide-in{from{transform:translateX(100%)}to{transform:translateX(0)}}
    .hdr{
      display:flex;align-items:center;gap:10px;
      padding:12px 16px;background:#f4f4f6;
      border-bottom:1px solid #dde1e7;flex-shrink:0;
    }
    .hdr-icon{
      width:28px;height:28px;background:#007dc1;border-radius:7px;
      display:flex;align-items:center;justify-content:center;flex-shrink:0;
    }
    .hdr-info{flex:1;min-width:0}
    .hdr-title{font-weight:700;font-size:14px;color:#1d1d21;
               white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .hdr-sub{font-size:11px;color:#6e6e78;font-family:'SF Mono','Fira Code',monospace;
             white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px}
    .close-btn{background:none;border:none;color:#6e6e78;cursor:pointer;
               font-size:18px;line-height:1;padding:4px;border-radius:4px;flex-shrink:0}
    .close-btn:hover{color:#1d1d21;background:rgba(0,0,0,.06)}
    .body{flex:1;overflow-y:auto;padding:14px;display:flex;flex-direction:column;gap:14px;
          scrollbar-width:thin;scrollbar-color:#dde1e7 transparent}
    .body::-webkit-scrollbar{width:4px}
    .body::-webkit-scrollbar-thumb{background:#dde1e7;border-radius:2px}
    .section{display:flex;flex-direction:column;gap:8px}
    .section-title{
      font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;
      color:#6e6e78;padding-bottom:6px;border-bottom:1px solid #dde1e7;
      display:flex;align-items:center;gap:6px;
    }
    .badge{padding:2px 7px;border-radius:10px;font-size:10px;font-weight:700;
           text-transform:none;letter-spacing:0;margin-left:auto}
    .badge-ok{background:rgba(0,133,111,.1);color:#00856f;border:1px solid rgba(0,133,111,.25)}
    .badge-warn{background:rgba(188,100,0,.08);color:#bc6400;border:1px solid rgba(188,100,0,.2)}
    .uri-row{
      display:flex;align-items:center;gap:8px;
      background:#f4f4f6;border:1px solid #dde1e7;border-radius:6px;padding:8px 10px;
    }
    .uri-code{
      font-family:'SF Mono','Fira Code',monospace;font-size:11px;color:#005f99;
      flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
    }
    .scope-grid{display:flex;flex-wrap:wrap;gap:6px}
    .scope-chip{
      padding:4px 10px;border-radius:20px;font-size:12px;
      font-family:'SF Mono','Fira Code',monospace;
      border:1px solid #dde1e7;background:#fff;color:#6e6e78;
      cursor:pointer;transition:all .15s;
    }
    .scope-chip:hover{border-color:#007dc1;color:#005f99}
    .scope-chip.selected{background:#e8f3fb;border-color:#007dc1;color:#005f99;font-weight:600}
    .scope-chip.required{cursor:default;opacity:.85}
    button.btn{
      display:inline-flex;align-items:center;justify-content:center;gap:6px;
      border:none;border-radius:6px;font-size:13px;font-family:inherit;
      font-weight:600;cursor:pointer;transition:all .15s;white-space:nowrap;
    }
    button.btn:disabled{opacity:.45;cursor:not-allowed}
    .btn-primary{background:#007dc1;color:#fff;padding:10px 18px}
    .btn-primary:hover:not(:disabled){background:#0069a4}
    .btn-full{width:100%}
    .btn-sm{padding:6px 12px;font-size:12px}
    .btn-secondary{
      background:#fff;color:#1d1d21;border:1px solid #dde1e7;
      padding:6px 12px;font-size:12px;
    }
    .btn-secondary:hover:not(:disabled){border-color:#007dc1;color:#005f99}
    .btn-icon{
      background:none;border:none;color:#6e6e78;cursor:pointer;
      padding:2px 4px;border-radius:3px;display:inline-flex;align-items:center;
    }
    .btn-icon:hover{color:#1d1d21}
    .generate-note{font-size:11px;color:#9898a6;text-align:center;line-height:1.5;margin-top:6px}
    .generate-note code{
      font-family:'SF Mono','Fira Code',monospace;
      background:#f4f4f6;padding:1px 4px;border-radius:3px;font-size:10px;
    }
    .status-line{
      display:flex;align-items:center;gap:8px;padding:10px 12px;
      background:#f4f4f6;border:1px solid #dde1e7;border-radius:6px;
      font-size:12px;color:#6e6e78;
    }
    .spinner{
      width:14px;height:14px;border:2px solid #dde1e7;border-top-color:#007dc1;
      border-radius:50%;animation:spin .7s linear infinite;flex-shrink:0;
    }
    @keyframes spin{to{transform:rotate(360deg)}}
    .token-tabs{display:flex;border-bottom:1px solid #dde1e7;margin:0 -14px;padding:0 14px}
    .token-tab{
      background:none;border:none;border-bottom:2px solid transparent;
      color:#6e6e78;cursor:pointer;font-size:12px;font-weight:600;
      padding:7px 14px 8px;font-family:inherit;transition:color .15s,border-color .15s;
    }
    .token-tab:hover{color:#1d1d21}
    .token-tab.active{color:#007dc1;border-bottom-color:#007dc1}
    .token-panel{display:flex;flex-direction:column;gap:12px;padding-top:12px}
    .token-panel.hidden{display:none}
    .sub-section{display:flex;flex-direction:column;gap:6px}
    .sub-title{
      font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
      color:#6e6e78;padding-bottom:5px;border-bottom:1px solid #dde1e7;
      display:flex;align-items:center;justify-content:space-between;
    }
    .claims{width:100%;border-collapse:collapse;font-size:12px}
    .claims tr{border-bottom:1px solid #f0f0f4}
    .claims tr:hover{background:#fafafa}
    .ck{padding:6px 8px 6px 0;vertical-align:top;width:38%;white-space:nowrap}
    .ck code{font-family:'SF Mono','Fira Code',monospace;font-size:11px;
             color:#005f99;background:#e8f3fb;padding:1px 5px;border-radius:3px}
    .cl{display:block;font-size:10px;color:#9898a6;font-style:italic;margin-top:2px}
    .cv{padding:6px 0;vertical-align:top;word-break:break-all}
    .scalar{color:#1d1d21;font-family:'SF Mono','Fira Code',monospace;font-size:11px}
    .time-val{color:#8b5e00;font-size:11px}
    .time-rel{color:#9898a6;font-size:10px}
    .tag{display:inline-block;background:#e8f3fb;color:#005f99;
         border:1px solid #c2dff2;border-radius:4px;
         padding:1px 6px;font-size:11px;margin:1px 2px 1px 0;
         font-family:'SF Mono','Fira Code',monospace}
    .bool--true{color:#00856f;font-weight:600}
    .bool--false{color:#b52f2f;font-weight:600}
    .json-val{font-family:'SF Mono','Fira Code',monospace;font-size:10px;color:#6e6e78}
    .raw-jwt{
      background:#f4f4f6;border:1px solid #dde1e7;border-radius:6px;
      padding:10px;font-family:'SF Mono','Fira Code',monospace;
      font-size:10px;word-break:break-all;line-height:1.6;
    }
    .jh{color:#c0392b}.jp{color:#27ae60}.js{color:#d97706}
    .copy-jwt-btn{
      background:#fff;border:1px solid #dde1e7;color:#6e6e78;
      border-radius:4px;padding:3px 8px;font-size:11px;cursor:pointer;
      font-family:inherit;font-weight:500;
    }
    .copy-jwt-btn:hover{border-color:#007dc1;color:#005f99}
    .absent{color:#9898a6;font-style:italic;padding:8px 0;font-size:12px}
    .error-banner{
      display:flex;align-items:flex-start;gap:8px;padding:10px 12px;
      background:#fef2f2;border:1px solid #fca5a5;
      border-radius:6px;color:#b52f2f;font-size:12px;line-height:1.5;
    }
    .loading-wrap{
      display:flex;align-items:center;gap:10px;justify-content:center;
      padding:40px 20px;color:#9898a6;
    }
    .reg-added{color:#00856f;font-size:12px;font-weight:600}
    .uri-instruction{
      font-size:12px;color:#6e6e78;line-height:1.5;
      padding:8px 10px;background:#fafafa;border-radius:6px;
      border:1px solid #e6e6ea;
    }
    .uri-instruction strong{color:#1d1d21}
  `;

  function openTokenPreviewPanel() {
    hideTokenOverlay();
    if (isPanelOpen()) { closePanel(); return; }

    const host = document.createElement('div');
    host.id = PANEL_HOST_ID;
    const shadow = host.attachShadow({ mode: 'open' });
    panelShadow = shadow;

    shadow.innerHTML = `<style>${PANEL_CSS}</style>
      <div class="panel">
        <div class="hdr">
          <div class="hdr-icon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M9 12l2 2 4-4"/>
            </svg>
          </div>
          <div class="hdr-info">
            <div class="hdr-title">Token Preview</div>
          </div>
          <button class="close-btn" id="panel-close">✕</button>
        </div>
        <div class="body">
          <div class="loading-wrap">
            <div class="spinner"></div>
            <span>Loading app details…</span>
          </div>
        </div>
      </div>`;

    shadow.getElementById('panel-close').addEventListener('click', closePanel);
    document.body.appendChild(host);

    Promise.all([
      oktaGet(`/api/v1/apps/${ctx.appId}`),
      bgSend({ action: 'GET_REDIRECT_URI' }),
    ]).then(([app, uriRes]) => {
      panelApp = app;
      panelRedirectUri = uriRes.redirectUri;
      renderPanel();
    }).catch(err => {
      if (!panelShadow) return;
      panelShadow.querySelector('.body').innerHTML = `
        <div class="error-banner">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0;margin-top:1px">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          ${esc(err.message)}
        </div>`;
    });
  }

  function renderPanel() {
    const shadow = panelShadow;
    if (!shadow || !panelApp) return;

    const app = panelApp;
    const appName = app.label || app.name || '(app)';
    const clientId = app.credentials?.oauthClient?.client_id || '—';
    const currentUris = app.settings?.oauthClient?.redirect_uris || [];
    const isRegistered = currentUris.includes(panelRedirectUri);
    const oauthDomain = getOAuthDomain();

    const hdrInfo = shadow.querySelector('.hdr-info');
    hdrInfo.innerHTML = `
      <div class="hdr-title">${esc(appName)}</div>
      <div class="hdr-sub">${esc(clientId)}</div>`;

    shadow.querySelector('.body').innerHTML = `
      <!-- Redirect URI -->
      <div class="section">
        <div class="section-title">
          Redirect URI
          <span class="badge ${isRegistered ? 'badge-ok' : 'badge-warn'}" id="uri-badge">
            ${isRegistered ? 'registered' : 'not registered'}
          </span>
        </div>
        <div class="uri-row">
          <code class="uri-code">${esc(panelRedirectUri)}</code>
          <button class="btn-icon" id="copy-uri-btn" title="Copy">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <rect x="9" y="9" width="13" height="13" rx="2"/>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
            </svg>
          </button>
        </div>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          ${!isRegistered ? `<button class="btn btn-primary btn-sm" id="auto-add-btn">Auto-add to App</button>` : ''}
          <button class="btn btn-secondary btn-sm" id="check-uri-btn">
            ${isRegistered ? '↻ Re-check' : 'Check'}
          </button>
          <span class="reg-added ${isRegistered ? '' : 'hidden'}" id="reg-note">✓ Registered</span>
        </div>
        ${!isRegistered ? `
          <p class="uri-instruction">
            Or add manually in this app's <strong>General</strong> tab under
            <strong>Login redirect URIs</strong>, then click Check.
          </p>
        ` : ''}
        <div class="error-banner hidden" id="uri-error"></div>
      </div>

      <!-- Scopes -->
      <div class="section">
        <div class="section-title">Scopes</div>
        <div class="scope-grid" id="scope-grid">
          ${PANEL_SCOPES.map(s => `
            <button class="scope-chip ${panelSelectedScopes.has(s.v) ? 'selected' : ''} ${s.req ? 'required' : ''}"
                    data-scope="${s.v}">${esc(s.v)}</button>
          `).join('')}
        </div>
      </div>

      <!-- Generate -->
      <div class="section">
        <button class="btn btn-primary btn-full" id="generate-btn"
                ${!isRegistered ? 'disabled' : ''}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <polygon points="5 3 19 12 5 21 5 3"/>
          </svg>
          Generate Token Preview
        </button>
        <p class="generate-note">Org AS · Auth Code + PKCE · <code>${esc(oauthDomain)}</code></p>
      </div>

      <!-- Status (shown during generation) -->
      <div class="status-line hidden" id="panel-status">
        <div class="spinner"></div>
        <span id="panel-status-msg">Opening browser tab…</span>
      </div>

      <!-- Token results -->
      <div id="panel-token-results" class="hidden"></div>

      <!-- Error -->
      <div class="error-banner hidden" id="panel-error">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0;margin-top:1px">
          <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <span id="panel-error-msg"></span>
      </div>
    `;

    // Copy URI
    shadow.getElementById('copy-uri-btn').addEventListener('click', () => {
      navigator.clipboard.writeText(panelRedirectUri).catch(() => {});
      const btn = shadow.getElementById('copy-uri-btn');
      btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#4caf7d" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>';
      setTimeout(() => { btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`; }, 1500);
    });

    // Auto-add and check URI registration
    shadow.getElementById('auto-add-btn')?.addEventListener('click', () => handleAutoAdd(shadow));
    shadow.getElementById('check-uri-btn')?.addEventListener('click', () => handleCheckUri(shadow));

    // Scope chips
    shadow.querySelectorAll('.scope-chip:not(.required)').forEach(chip => {
      chip.addEventListener('click', () => {
        const s = chip.dataset.scope;
        if (panelSelectedScopes.has(s)) { panelSelectedScopes.delete(s); chip.classList.remove('selected'); }
        else { panelSelectedScopes.add(s); chip.classList.add('selected'); }
      });
    });

    // Generate
    shadow.getElementById('generate-btn')?.addEventListener('click', () => handleGenerate(shadow));
  }

  async function handleAutoAdd(shadow) {
    const btn = shadow.getElementById('auto-add-btn');
    const errDiv = shadow.getElementById('uri-error');
    if (btn) { btn.disabled = true; btn.textContent = 'Adding…'; }
    errDiv?.classList.add('hidden');

    try {
      const fresh = await oktaGet(`/api/v1/apps/${ctx.appId}`);
      const current = fresh.settings?.oauthClient?.redirect_uris || [];

      if (!current.includes(panelRedirectUri)) {
        const updated = deepClean(fresh);
        if (!updated.settings) updated.settings = {};
        if (!updated.settings.oauthClient) updated.settings.oauthClient = {};
        updated.settings.oauthClient.redirect_uris = [...current, panelRedirectUri];
        panelApp = await oktaPut(`/api/v1/apps/${ctx.appId}`, updated);
      } else {
        panelApp = fresh;
      }

      // Flip to registered state
      shadow.getElementById('uri-badge')?.setAttribute('class', 'badge badge-ok');
      const badge = shadow.getElementById('uri-badge');
      if (badge) badge.textContent = 'registered';
      shadow.getElementById('reg-note')?.classList.remove('hidden');
      shadow.querySelector('.uri-instruction')?.classList.add('hidden');
      btn?.remove();
      const genBtn = shadow.getElementById('generate-btn');
      if (genBtn) genBtn.disabled = false;
    } catch (err) {
      if (errDiv) {
        errDiv.textContent = err.message;
        errDiv.classList.remove('hidden');
      }
      if (btn) { btn.disabled = false; btn.textContent = 'Auto-add to App'; }
    }
  }

  async function handleCheckUri(shadow) {
    const btn = shadow.getElementById('check-uri-btn');
    const errDiv = shadow.getElementById('uri-error');
    if (btn) { btn.disabled = true; btn.textContent = 'Checking…'; }
    errDiv?.classList.add('hidden');

    try {
      const fresh = await oktaGet(`/api/v1/apps/${ctx.appId}`);
      panelApp = fresh;
      const isNowRegistered = (fresh.settings?.oauthClient?.redirect_uris || [])
        .includes(panelRedirectUri);

      const badge = shadow.getElementById('uri-badge');
      if (badge) {
        badge.textContent = isNowRegistered ? 'registered' : 'not registered';
        badge.className = `badge ${isNowRegistered ? 'badge-ok' : 'badge-warn'}`;
      }

      const note = shadow.getElementById('reg-note');
      note?.classList.toggle('hidden', !isNowRegistered);

      const instruction = shadow.querySelector('.uri-instruction');
      if (instruction) instruction.classList.toggle('hidden', isNowRegistered);

      const genBtn = shadow.getElementById('generate-btn');
      if (genBtn) genBtn.disabled = !isNowRegistered;

      if (btn) { btn.disabled = false; btn.textContent = isNowRegistered ? '↻ Re-check' : 'Check Registration'; }
    } catch (err) {
      if (errDiv) {
        errDiv.textContent = err.message;
        errDiv.classList.remove('hidden');
      }
      if (btn) { btn.disabled = false; btn.textContent = 'Check Registration'; }
    }
  }

  let _pollTimer = null;

  function stopPolling() {
    clearInterval(_pollTimer);
    _pollTimer = null;
  }

  function startPolling() {
    stopPolling();
    let ticks = 0;
    _pollTimer = setInterval(async () => {
      ticks++;
      if (ticks > 180) { // 3-minute hard timeout
        stopPolling();
        const s = panelShadow;
        if (s) {
          s.getElementById('panel-status')?.classList.add('hidden');
          const b = s.getElementById('generate-btn');
          if (b) b.disabled = false;
          showPanelError(s, 'Authentication timed out. Try again.');
        }
        return;
      }
      try {
        const { tokenPreviewResult: r } = await chrome.storage.session.get('tokenPreviewResult');
        if (!r) return;
        // Result is ready — stop polling and display it
        stopPolling();
        await chrome.storage.session.remove('tokenPreviewResult');
        if (panelShadow) updatePanelWithResult(r);
      } catch {}
    }, 1000);
  }

  function handleGenerate(shadow) {
    const genBtn = shadow.getElementById('generate-btn');
    const statusDiv = shadow.getElementById('panel-status');
    const statusMsg = shadow.getElementById('panel-status-msg');
    const errDiv = shadow.getElementById('panel-error');

    shadow.getElementById('panel-token-results')?.classList.add('hidden');
    errDiv?.classList.add('hidden');
    if (genBtn) genBtn.disabled = true;

    const clientId = panelApp?.credentials?.oauthClient?.client_id;
    if (!clientId) {
      showPanelError(shadow, 'Could not determine the app\'s Client ID.');
      if (genBtn) genBtn.disabled = false;
      return;
    }

    statusDiv?.classList.remove('hidden');
    if (statusMsg) statusMsg.textContent = 'Opening auth tab…';

    bgSend({
      action: 'RUN_OAUTH_FLOW',
      payload: {
        domain: getOAuthDomain(),
        clientId,
        scopes: Array.from(panelSelectedScopes),
        loginHint: null,
      },
    }).then(() => {
      // Tab opened — switch status and start polling session storage for result.
      // We don't rely solely on SHOW_TOKEN_OVERLAY message delivery since tab
      // focus changes can make that unreliable.
      if (statusMsg) statusMsg.textContent = 'Auth tab opened — it will close automatically…';
      startPolling();
    }).catch(err => {
      statusDiv?.classList.add('hidden');
      if (genBtn) genBtn.disabled = false;
      showPanelError(shadow, err.message);
    });
  }

  function showPanelError(shadow, msg) {
    const errDiv = shadow?.getElementById('panel-error');
    const errMsg = shadow?.getElementById('panel-error-msg');
    if (errMsg) errMsg.textContent = msg;
    errDiv?.classList.remove('hidden');
  }

  function updatePanelWithResult(result) {
    const shadow = panelShadow;
    if (!shadow) return;

    stopPolling();
    shadow.getElementById('panel-status')?.classList.add('hidden');
    const genBtn = shadow.getElementById('generate-btn');
    if (genBtn) genBtn.disabled = false;

    if (result.error) {
      showPanelError(shadow, result.error);
      return;
    }

    const resultsDiv = shadow.getElementById('panel-token-results');
    if (!resultsDiv) return;

    const { accessToken, idToken } = result.tokens || {};

    resultsDiv.innerHTML = `
      <div class="section">
        <div class="token-tabs">
          <button class="token-tab active" data-panel="at">Access Token</button>
          <button class="token-tab" data-panel="it">ID Token</button>
        </div>
        <div class="token-panel" id="tp-at">${buildPanelJWT(accessToken)}</div>
        <div class="token-panel hidden" id="tp-it">${buildPanelJWT(idToken)}</div>
      </div>`;
    resultsDiv.classList.remove('hidden');

    // Tab switching
    resultsDiv.querySelectorAll('.token-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        resultsDiv.querySelectorAll('.token-tab').forEach(t => t.classList.remove('active'));
        resultsDiv.querySelectorAll('.token-panel').forEach(p => p.classList.add('hidden'));
        tab.classList.add('active');
        resultsDiv.querySelector(`#tp-${tab.dataset.panel}`)?.classList.remove('hidden');
      });
    });

    // Copy JWT buttons
    resultsDiv.querySelectorAll('.copy-jwt-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        navigator.clipboard.writeText(btn.dataset.jwt).catch(() => {});
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = orig; }, 1500);
      });
    });

    resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function buildPanelJWT(jwt) {
    if (!jwt) return '<p class="absent">Not present in this response.</p>';
    const d = decodeJWT(jwt);
    if (!d) return '<p class="absent">Could not decode token.</p>';
    const parts = jwt.split('.');
    return `
      <div class="sub-section">
        <div class="sub-title">Payload</div>
        ${buildClaimsTable(d.payload)}
      </div>
      <div class="sub-section">
        <div class="sub-title">
          Raw JWT
          <button class="copy-jwt-btn" data-jwt="${esc(jwt)}">Copy</button>
        </div>
        <div class="raw-jwt">
          <span class="jh">${esc(parts[0])}</span
          >.<span class="jp">${esc(parts[1])}</span
          >.<span class="js">${esc(parts[2])}</span>
        </div>
      </div>`;
  }

  // ─── Inject Token Preview Button ─────────────────────────────────────────────

  function injectButton() {
    if (document.getElementById('okta-token-preview-btn')) return;

    const btn = document.createElement('button');
    btn.id = 'okta-token-preview-btn';
    btn.className = 'okta-token-preview-inject-btn';
    btn.title = 'Open Okta Token Preview';
    btn.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="M9 12l2 2 4-4"/>
      </svg>
      Token Preview
    `;
    btn.addEventListener('click', openTokenPreviewPanel);

    const candidates = [
      '.o-form-button-bar',
      '[data-se="page-header"]',
      '.okta-header-with-actions',
      '.edit-mode-link-wrap',
      'header.paged-header',
      '.app-details-header',
    ];

    let mounted = false;
    for (const sel of candidates) {
      const el = document.querySelector(sel);
      if (el) { el.appendChild(btn); mounted = true; break; }
    }
    if (!mounted) {
      btn.classList.add('okta-token-preview-float');
      document.body.appendChild(btn);
    }
  }

  // Wait for the SPA to finish rendering before injecting
  function waitAndInject() {
    const observer = new MutationObserver(() => { injectButton(); });
    observer.observe(document.body, { childList: true, subtree: true });
    injectButton();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', waitAndInject);
  } else {
    waitAndInject();
  }
})();

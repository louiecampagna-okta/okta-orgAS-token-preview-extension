// Okta Token Preview — Popup Logic

'use strict';

// ─── State ────────────────────────────────────────────────────────────────────

const state = {
  tab: null,
  context: null,     // { domain, appType, appId }
  app: null,         // full Okta app object from /api/v1/apps/{id}
  redirectUri: null,
  redirectRegistered: false,
  selectedUser: null,
  selectedScopes: new Set(['openid', 'profile', 'email']),
  lastTokenResponse: null,
};

// ─── DOM refs ─────────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);
const views = {
  loading: $('view-loading'),
  notApp: $('view-not-app'),
  main: $('view-main'),
};

// ─── Standard OIDC scopes supported by the Okta org authorization server ──────

const ORG_AS_SCOPES = [
  { value: 'openid',          label: 'openid',          required: true,  desc: 'Required for OIDC' },
  { value: 'profile',         label: 'profile',         required: false, desc: 'Name, locale, etc.' },
  { value: 'email',           label: 'email',           required: false, desc: 'Email address' },
  { value: 'address',         label: 'address',         required: false, desc: 'Physical address' },
  { value: 'phone',           label: 'phone',           required: false, desc: 'Phone number' },
  { value: 'groups',          label: 'groups',          required: false, desc: 'Group memberships' },
  { value: 'offline_access',  label: 'offline_access',  required: false, desc: 'Refresh token' },
  { value: 'device_sso',      label: 'device_sso',      required: false, desc: 'Device SSO' },
];

// ─── JWT Claim Descriptions ───────────────────────────────────────────────────

const CLAIM_DOCS = {
  // Core JWT (RFC 7519)
  iss:    { label: 'Issuer',              desc: 'The authorization server that issued this token.' },
  sub:    { label: 'Subject',             desc: 'Unique identifier for the principal (user).' },
  aud:    { label: 'Audience',            desc: 'Intended recipient(s). Must include the client_id for ID tokens.' },
  exp:    { label: 'Expiration',          desc: 'Unix timestamp after which this token MUST NOT be accepted.', isTime: true },
  iat:    { label: 'Issued At',           desc: 'Unix timestamp when the token was issued.', isTime: true },
  nbf:    { label: 'Not Before',          desc: 'Token not valid before this Unix timestamp.', isTime: true },
  jti:    { label: 'JWT ID',              desc: 'Unique identifier for this token — useful for revocation.' },

  // OIDC Core (OpenID Connect Core 1.0)
  nonce:       { label: 'Nonce',               desc: 'Client-supplied value to bind the ID token to the session and prevent replay attacks.' },
  auth_time:   { label: 'Auth Time',           desc: 'When the end-user last authenticated.', isTime: true },
  acr:         { label: 'Auth Context Class',  desc: 'Authentication Context Class Reference — the level of assurance.' },
  amr:         { label: 'Auth Methods',        desc: 'Authentication Methods References — list of auth methods used (e.g. "pwd", "mfa").' },
  azp:         { label: 'Authorized Party',    desc: 'The OAuth 2.0 client to which the token was issued.' },
  at_hash:     { label: 'Access Token Hash',   desc: 'Hash of the access token — used to bind the ID token to an access token.' },
  c_hash:      { label: 'Code Hash',           desc: 'Hash of the authorization code.' },

  // Standard OIDC profile claims
  name:                { label: 'Full Name',        desc: 'End-user full name.' },
  given_name:          { label: 'Given Name',        desc: 'End-user first/given name.' },
  family_name:         { label: 'Family Name',       desc: 'End-user last/family name.' },
  middle_name:         { label: 'Middle Name',       desc: 'End-user middle name.' },
  nickname:            { label: 'Nickname',          desc: 'Casual name for the end-user.' },
  preferred_username:  { label: 'Preferred Username',desc: 'Shorthand name by which the user wishes to be referred.' },
  profile:             { label: 'Profile URL',       desc: 'URL of the end-user\'s profile page.' },
  picture:             { label: 'Picture URL',       desc: 'URL of the end-user\'s profile picture.' },
  website:             { label: 'Website',           desc: 'URL of the end-user\'s website.' },
  email:               { label: 'Email',             desc: 'End-user\'s preferred email address.' },
  email_verified:      { label: 'Email Verified',    desc: 'True if the email address has been verified by the OP.' },
  gender:              { label: 'Gender',            desc: 'End-user\'s gender.' },
  birthdate:           { label: 'Birthdate',         desc: 'End-user\'s birthday (YYYY-MM-DD or YYYY).' },
  zoneinfo:            { label: 'Timezone',          desc: 'End-user\'s time zone (tz database format, e.g. "America/Los_Angeles").' },
  locale:              { label: 'Locale',            desc: 'End-user\'s locale (e.g. "en-US").' },
  phone_number:        { label: 'Phone Number',      desc: 'End-user\'s preferred telephone number.' },
  phone_number_verified: { label: 'Phone Verified',  desc: 'True if the phone number has been verified.' },
  address:             { label: 'Address',           desc: 'End-user\'s preferred postal address.' },
  updated_at:          { label: 'Updated At',        desc: 'Time the user\'s information was last updated.', isTime: true },

  // OAuth 2.0 Access Token claims (Okta-specific)
  scp:     { label: 'Scopes',           desc: 'OAuth 2.0 scopes granted to this access token.' },
  ver:     { label: 'Version',          desc: 'Okta token version number.' },
  uid:     { label: 'User ID',          desc: 'Okta internal unique identifier for the user.' },
  cid:     { label: 'Client ID',        desc: 'The OAuth 2.0 client that requested the token.' },
  groups:  { label: 'Groups',           desc: 'Okta groups the user belongs to (if the groups scope was requested).' },
};

// ─── Utilities ────────────────────────────────────────────────────────────────

function showView(name) {
  Object.values(views).forEach(v => v.classList.add('hidden'));
  views[name].classList.remove('hidden');
}

function showError(msg) {
  const banner = $('error-banner');
  $('error-message').textContent = msg;
  banner.classList.remove('hidden');
}

function clearError() {
  $('error-banner').classList.add('hidden');
}

function decodeJWT(token) {
  try {
    const [rawHeader, rawPayload, signature] = token.split('.');
    const decode = b64 => {
      const padded = b64.replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(atob(padded));
    };
    return {
      header: decode(rawHeader),
      payload: decode(rawPayload),
      signature,
      raw: token,
    };
  } catch {
    return null;
  }
}

function formatTimestamp(unix) {
  if (!unix) return '—';
  const d = new Date(unix * 1000);
  const now = Date.now();
  const diff = unix * 1000 - now;
  const abs = Math.abs(diff);
  let relative;
  if (abs < 60000) relative = 'just now';
  else if (abs < 3600000) relative = `${Math.round(abs / 60000)}m ${diff > 0 ? 'from now' : 'ago'}`;
  else relative = `${Math.round(abs / 3600000)}h ${diff > 0 ? 'from now' : 'ago'}`;

  return `${d.toLocaleString()} (${relative})`;
}

function copyText(text) {
  navigator.clipboard.writeText(text).catch(() => {
    const el = document.createElement('textarea');
    el.value = text;
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    el.remove();
  });
}

// ─── Content Script Messaging ─────────────────────────────────────────────────

function sendToContent(message) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(state.tab.id, message, response => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else if (response?.success === false) {
        reject(new Error(response.error || 'Unknown error'));
      } else {
        resolve(response);
      }
    });
  });
}

function sendToBackground(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, response => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else if (response?.success === false) {
        reject(new Error(response.error || 'Unknown error'));
      } else {
        resolve(response);
      }
    });
  });
}

// ─── App Info Rendering ───────────────────────────────────────────────────────

function renderAppInfo(app) {
  const oauthClient = app.settings?.oauthClient || {};
  const name = app.label || app.name || '(unnamed app)';
  const clientId = app.credentials?.oauthClient?.client_id || '—';
  const grantTypes = (oauthClient.grant_types || []).join(', ') || '—';
  const issuer = `https://${state.context.domain}`;

  $('app-name').textContent = name;
  $('app-client-id').textContent = clientId;
  $('app-grant-types').textContent = grantTypes;
  $('app-issuer').textContent = issuer;
  $('header-domain').textContent = state.context.domain;

  // Render scope grid — combine app-configured scopes with standard scopes
  const appScopes = oauthClient.response_types?.includes('token')
    ? (oauthClient.scopes || [])
    : [];

  const allScopes = [
    ...ORG_AS_SCOPES,
    ...appScopes
      .filter(s => !ORG_AS_SCOPES.some(o => o.value === s))
      .map(s => ({ value: s, label: s, required: false, desc: 'Configured on app' })),
  ];

  const grid = $('scope-grid');
  grid.innerHTML = '';
  allScopes.forEach(scope => {
    const chip = document.createElement('button');
    chip.type = 'button';
    chip.className = 'scope-chip';
    chip.dataset.scope = scope.value;
    chip.title = scope.desc;
    if (state.selectedScopes.has(scope.value)) chip.classList.add('selected');
    if (scope.required) chip.classList.add('required');
    chip.textContent = scope.label;
    chip.addEventListener('click', () => toggleScope(scope.value, scope.required, chip));
    grid.appendChild(chip);
  });
}

function toggleScope(value, required, el) {
  if (required) return;
  if (state.selectedScopes.has(value)) {
    state.selectedScopes.delete(value);
    el.classList.remove('selected');
  } else {
    state.selectedScopes.add(value);
    el.classList.add('selected');
  }
}

// ─── Redirect URI Handling ────────────────────────────────────────────────────

async function checkRedirectUriRegistration() {
  if (!state.app || !state.redirectUri) return;

  const registered = (state.app.settings?.oauthClient?.redirect_uris || [])
    .includes(state.redirectUri);

  state.redirectRegistered = registered;
  updateRedirectBadge(registered);
}

function updateRedirectBadge(registered) {
  const badge = $('redirect-status-badge');
  const note = $('redirect-added-note');
  const addBtn = $('btn-auto-add-uri');
  const removeBtn = $('btn-remove-uri');

  badge.textContent = registered ? 'registered' : 'not registered';
  badge.className = `status-badge ${registered ? 'badge-ok' : 'badge-warn'}`;
  note.classList.toggle('hidden', !registered);
  addBtn.style.display = registered ? 'none' : '';
  removeBtn.style.display = registered ? '' : 'none';
}

// ─── Token Rendering ─────────────────────────────────────────────────────────

function renderJWT(jwt, containerId) {
  const container = $(containerId);
  if (!jwt) {
    container.innerHTML = '<p class="no-token">Not present in this response.</p>';
    return;
  }

  const decoded = decodeJWT(jwt);
  if (!decoded) {
    container.innerHTML = '<p class="no-token">Could not decode token.</p>';
    return;
  }

  container.innerHTML = `
    <div class="jwt-section">
      <div class="jwt-section-title">Header</div>
      ${renderClaimsTable(decoded.header)}
    </div>
    <div class="jwt-section">
      <div class="jwt-section-title">Payload</div>
      ${renderClaimsTable(decoded.payload)}
    </div>
    <div class="jwt-section">
      <div class="jwt-section-title">Raw JWT</div>
      <div class="raw-jwt-wrap">
        <div class="raw-jwt">
          <span class="jwt-part jwt-header">${jwt.split('.')[0]}</span
          >.<span class="jwt-part jwt-payload">${jwt.split('.')[1]}</span
          >.<span class="jwt-part jwt-sig">${jwt.split('.')[2]}</span>
        </div>
        <button class="copy-raw-btn" data-jwt="${escapeAttr(jwt)}">Copy JWT</button>
      </div>
    </div>
  `;

  // Bind copy button
  container.querySelector('.copy-raw-btn')?.addEventListener('click', e => {
    copyText(e.target.dataset.jwt);
    e.target.textContent = 'Copied!';
    setTimeout(() => { e.target.textContent = 'Copy JWT'; }, 1500);
  });
}

function renderClaimsTable(claims) {
  const rows = Object.entries(claims).map(([key, value]) => {
    const doc = CLAIM_DOCS[key];
    const label = doc?.label || key;
    const desc = doc?.desc || '';
    const isTime = doc?.isTime && typeof value === 'number';
    let displayValue;
    if (isTime) {
      displayValue = `<span class="claim-time">${formatTimestamp(value)}</span>`;
    } else if (Array.isArray(value)) {
      displayValue = value.map(v => `<span class="claim-tag">${escapeHtml(String(v))}</span>`).join(' ');
    } else if (typeof value === 'object' && value !== null) {
      displayValue = `<code class="claim-json">${escapeHtml(JSON.stringify(value, null, 2))}</code>`;
    } else if (typeof value === 'boolean') {
      displayValue = `<span class="claim-bool claim-bool--${value}">${value}</span>`;
    } else {
      displayValue = `<span class="claim-val">${escapeHtml(String(value))}</span>`;
    }

    return `
      <tr class="claim-row" title="${escapeAttr(desc)}">
        <td class="claim-key">
          <code>${escapeHtml(key)}</code>
          ${doc ? `<span class="claim-label-text">${escapeHtml(label)}</span>` : ''}
        </td>
        <td class="claim-value">${displayValue}</td>
        ${desc ? `<td class="claim-desc">${escapeHtml(desc)}</td>` : '<td></td>'}
      </tr>
    `;
  }).join('');

  return `<table class="claims-table"><tbody>${rows}</tbody></table>`;
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function escapeAttr(str) {
  return escapeHtml(str).replace(/\n/g, '&#10;');
}

// ─── User Search ──────────────────────────────────────────────────────────────

let searchDebounce;

$('user-search').addEventListener('input', e => {
  clearTimeout(searchDebounce);
  const q = e.target.value.trim();
  if (!q) {
    $('user-search-results').classList.add('hidden');
    return;
  }
  searchDebounce = setTimeout(() => searchUsers(q), 350);
});

async function searchUsers(query) {
  try {
    const { users } = await sendToContent({ action: 'SEARCH_USERS', query, limit: 8 });
    renderUserResults(users);
  } catch (err) {
    console.warn('User search failed:', err);
  }
}

function renderUserResults(users) {
  const container = $('user-search-results');
  if (!users?.length) {
    container.innerHTML = '<div class="search-empty">No users found.</div>';
    container.classList.remove('hidden');
    return;
  }
  container.innerHTML = users.map(u => {
    const profile = u.profile || {};
    const name = [profile.firstName, profile.lastName].filter(Boolean).join(' ') || '(no name)';
    const login = profile.login || profile.email || u.id;
    return `<button class="search-result-item" data-login="${escapeAttr(login)}" data-name="${escapeAttr(name)}">
      <span class="search-result-name">${escapeHtml(name)}</span>
      <span class="search-result-login">${escapeHtml(login)}</span>
    </button>`;
  }).join('');
  container.classList.remove('hidden');

  container.querySelectorAll('.search-result-item').forEach(btn => {
    btn.addEventListener('click', () => {
      selectUser(btn.dataset.login, btn.dataset.name);
      container.classList.add('hidden');
      $('user-search').value = '';
    });
  });
}

function selectUser(login, name) {
  state.selectedUser = login;
  const wrap = $('selected-user');
  $('selected-user-label').textContent = `${name} (${login})`;
  wrap.classList.remove('hidden');
}

$('clear-user').addEventListener('click', () => {
  state.selectedUser = null;
  $('selected-user').classList.add('hidden');
});

// ─── Initialization ───────────────────────────────────────────────────────────

// Inject content script on-demand if it wasn't already loaded by the browser
// (this happens when the user navigated to the app page via SPA routing without a full reload)
async function ensureContentScript(tabId) {
  try {
    // Ping: if content script is already there, this resolves quickly
    await new Promise((resolve, reject) => {
      chrome.tabs.sendMessage(tabId, { action: 'GET_CONTEXT' }, res => {
        if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
        else resolve(res);
      });
    });
  } catch {
    // Not there — inject programmatically
    await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
    await chrome.scripting.insertCSS({ target: { tabId }, files: ['content.css'] });
    // Brief pause so the listener registers before we send the next message
    await new Promise(r => setTimeout(r, 50));
  }
}

// If a token flow completed while the popup was closed, retrieve the result
// from session storage and display it. Clears storage after reading so the
// result only auto-shows once.
async function restoreTokensFromSession() {
  const { tokenPreviewResult } = await chrome.storage.session.get('tokenPreviewResult');
  if (!tokenPreviewResult) return;

  // Discard stale results (older than 2 minutes)
  if (Date.now() - tokenPreviewResult.timestamp > 2 * 60 * 1000) {
    await chrome.storage.session.remove('tokenPreviewResult');
    return;
  }

  await chrome.storage.session.remove('tokenPreviewResult');

  if (tokenPreviewResult.error) {
    showError(tokenPreviewResult.error);
  } else {
    state.lastTokenResponse = tokenPreviewResult.tokens;
    renderTokenResults(tokenPreviewResult.tokens);
    $('tokens-card').classList.remove('hidden');
  }
}

function setNotAppHint(msg) {
  const el = document.querySelector('#view-not-app .hint');
  if (el) el.textContent = msg;
}

async function init() {
  showView('loading');

  try {
    // Get active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    state.tab = tab;

    const currentUrl = tab.url || '';

    // Always show the detected URL so issues are immediately visible
    setNotAppHint(`Detected URL: ${currentUrl || '(empty — try reloading the page)'}`);

    if (!currentUrl) {
      showView('notApp');
      return;
    }

    // Parse the app URL.
    // Okta admin URLs follow the pattern: /admin/app/{appType}/instance/{appId}
    // The literal "instance" segment sits between appType and the actual app ID.
    const appMatch = currentUrl.match(/\/admin\/app\/([^/?#]+)\/instance\/([^/?#]+)/);
    if (!appMatch) {
      showView('notApp');
      const hint = currentUrl.includes('/admin/')
        ? `You're in the Admin Console but not on an app detail page.\n\nExpected path: /admin/app/{type}/instance/{id}\nDetected: ${currentUrl}`
        : `Detected: ${currentUrl}`;
      setNotAppHint(hint);
      return;
    }

    const adminDomain = new URL(currentUrl).hostname;
    // The admin console lives on {org}-admin.okta.com, but all OAuth and
    // Management API endpoints are on {org}.okta.com — strip the -admin infix.
    const oauthDomain = adminDomain.replace(
      /^(.+?)-admin(\.(okta\.com|okta-emea\.com|oktapreview\.com))$/,
      '$1$2'
    );
    state.context = { domain: oauthDomain, appType: appMatch[1], appId: appMatch[2] };

    // Ensure the content script is injected (handles SPA navigation without a page reload)
    await ensureContentScript(tab.id);

    // Load data in parallel
    const [appResponse, redirectData] = await Promise.all([
      sendToContent({ action: 'GET_APP_DETAILS', appId: state.context.appId }),
      sendToBackground({ action: 'GET_REDIRECT_URI' }),
    ]);

    state.app = appResponse.app;
    state.redirectUri = redirectData.redirectUri;

    renderAppInfo(state.app);
    $('redirect-uri-value').textContent = state.redirectUri;
    await checkRedirectUriRegistration();

    showView('main');

    // The popup closes when the auth tab takes focus. Check whether a flow
    // completed while the popup was closed and show the tokens immediately.
    await restoreTokensFromSession();
  } catch (err) {
    showView('notApp');
    showError(`Detection failed: ${err.message}`);
  }
}

// ─── Event Listeners ──────────────────────────────────────────────────────────

// Auto-add redirect URI
$('btn-auto-add-uri').addEventListener('click', async () => {
  const btn = $('btn-auto-add-uri');
  btn.disabled = true;
  btn.textContent = 'Adding…';
  clearError();
  try {
    const res = await sendToContent({
      action: 'ADD_REDIRECT_URI',
      appId: state.context.appId,
      redirectUri: state.redirectUri,
    });
    state.app = res.app;
    state.redirectRegistered = true;
    updateRedirectBadge(true);
  } catch (err) {
    showError(`Could not add redirect URI: ${err.message}`);
    btn.disabled = false;
    btn.textContent = 'Auto-add to App';
  }
});

// Remove redirect URI
$('btn-remove-uri').addEventListener('click', async () => {
  const btn = $('btn-remove-uri');
  btn.disabled = true;
  btn.textContent = 'Removing…';
  clearError();
  try {
    const res = await sendToContent({
      action: 'REMOVE_REDIRECT_URI',
      appId: state.context.appId,
      redirectUri: state.redirectUri,
    });
    state.app = res.app;
    state.redirectRegistered = false;
    updateRedirectBadge(false);
  } catch (err) {
    showError(`Could not remove redirect URI: ${err.message}`);
    btn.disabled = false;
    btn.textContent = 'Remove from App';
  }
});

// Custom scope
$('btn-add-custom-scope').addEventListener('click', () => {
  const input = $('custom-scope-input');
  const val = input.value.trim();
  if (!val) return;

  const existing = document.querySelector(`[data-scope="${CSS.escape(val)}"]`);
  if (existing) {
    existing.classList.add('scope-chip-highlight');
    setTimeout(() => existing.classList.remove('scope-chip-highlight'), 800);
    input.value = '';
    return;
  }

  const chip = document.createElement('button');
  chip.type = 'button';
  chip.className = 'scope-chip selected custom-scope';
  chip.dataset.scope = val;
  chip.title = 'Custom scope';
  chip.textContent = val;
  state.selectedScopes.add(val);
  chip.addEventListener('click', () => toggleScope(val, false, chip));
  $('scope-grid').appendChild(chip);

  input.value = '';
});

$('custom-scope-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') $('btn-add-custom-scope').click();
});

// Generate tokens
$('btn-generate').addEventListener('click', async () => {
  clearError();
  if (!state.redirectRegistered) {
    showError('Please register the extension redirect URI in the app first (use "Auto-add to App").');
    return;
  }

  const scopes = Array.from(state.selectedScopes);
  if (!scopes.includes('openid')) {
    showError('The "openid" scope is required for OIDC flows.');
    return;
  }

  const clientId = state.app?.credentials?.oauthClient?.client_id;
  if (!clientId) {
    showError('Could not determine the app\'s Client ID.');
    return;
  }

  const btn = $('btn-generate');
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-inline"></span> Generating…`;

  // The background opens an auth tab (active: true) which closes this popup.
  // Tokens are written to chrome.storage.session by the background's top-level
  // webNavigation listener and retrieved by restoreTokensFromSession() the next
  // time the popup opens. Just kick off the flow and let the popup close.
  sendToBackground({
    action: 'RUN_OAUTH_FLOW',
    payload: {
      domain: state.context.domain,
      clientId,
      scopes,
      loginHint: state.selectedUser || null,
      adminTabId: state.tab.id,
    },
  }).catch(err => {
    // Only reachable if startAuthFlow itself fails (e.g. tabs.create error)
    showError(err.message);
    btn.disabled = false;
    btn.innerHTML = `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <polygon points="5 3 19 12 5 21 5 3"/>
      </svg>
      Generate Token Preview`;
  });
});

// Token tabs
document.querySelectorAll('.token-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.token-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.token-panel').forEach(p => p.classList.add('hidden'));
    tab.classList.add('active');
    $(`tab-${tab.dataset.tab}`)?.classList.remove('hidden');
  });
});

// Clear tokens
$('btn-clear-tokens').addEventListener('click', () => {
  $('tokens-card').classList.add('hidden');
  state.lastTokenResponse = null;
});

// Copy buttons
document.addEventListener('click', e => {
  const btn = e.target.closest('[data-copy-id]');
  if (!btn) return;
  const target = $(btn.dataset.copyId);
  if (target) {
    copyText(target.textContent.trim());
    const orig = btn.innerHTML;
    btn.innerHTML = '✓';
    setTimeout(() => { btn.innerHTML = orig; }, 1200);
  }
});

// Close user search results on outside click
document.addEventListener('click', e => {
  if (!e.target.closest('.search-wrap')) {
    $('user-search-results').classList.add('hidden');
  }
});

// ─── Token Results ────────────────────────────────────────────────────────────

function renderTokenResults(tokens) {
  renderJWT(tokens.accessToken, 'access-token-content');
  renderJWT(tokens.idToken, 'id-token-content');

  const rawData = {
    access_token: tokens.accessToken,
    id_token: tokens.idToken,
    token_type: tokens.tokenType,
    expires_in: tokens.expiresIn,
    scope: tokens.scope,
  };
  $('raw-response').textContent = JSON.stringify(rawData, null, 2);
}

// ─── Bootstrap ────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', init);

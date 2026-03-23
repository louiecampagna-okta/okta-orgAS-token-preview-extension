// Okta Token Preview — Background Service Worker

// ─── PKCE Utilities ───────────────────────────────────────────────────────────

async function generateCodeVerifier() {
  const array = new Uint8Array(48);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

async function generateCodeChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(digest));
}

function base64UrlEncode(buffer) {
  return btoa(Array.from(buffer).map(b => String.fromCharCode(b)).join(''))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function generateState() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

// ─── Redirect URI ─────────────────────────────────────────────────────────────
// Use an extension page as the redirect URI so that the token exchange fetch
// (made by callback.js) carries Origin: chrome-extension://{extensionId}.
// Okta extracts that same origin from the registered redirect URI and accepts it.
// chrome.identity.getRedirectURL() (chromiumapp.org) cannot be used here because
// the extension background's fetch origin doesn't match that redirect URI's origin.

function getRedirectUri() {
  return `chrome-extension://${chrome.runtime.id}/callback.html`;
}

// ─── Top-level: auth tab closed by user before Okta redirected ────────────────

chrome.tabs.onRemoved.addListener(async (tabId) => {
  let pending;
  try {
    ({ pendingAuthFlow: pending } = await chrome.storage.session.get('pendingAuthFlow'));
  } catch { return; }

  if (!pending || pending.tabId !== tabId) return;

  await chrome.storage.session.remove('pendingAuthFlow');
  const result = { error: 'Authorization cancelled.', timestamp: Date.now() };
  await chrome.storage.session.set({ tokenPreviewResult: result });
  notifyAdminTab(pending.adminTabId, { error: 'Authorization cancelled.' });
});

// ─── Notify the admin console tab ────────────────────────────────────────────

function notifyAdminTab(tabId, result) {
  if (!tabId) return;
  chrome.tabs.sendMessage(tabId, { action: 'SHOW_TOKEN_OVERLAY', result })
    .catch(() => {});
}

// ─── Token revocation ────────────────────────────────────────────────────────
// These are real, active org AS tokens. Revoke them immediately after we have
// extracted the data we need for display — the decoded claim contents are
// already in session storage at this point so the panel is unaffected.
// ID tokens are stateless JWTs and cannot be revoked; they expire naturally.

function revokeTokens(domain, clientId, tokens) {
  const revoke = (token, hint) =>
    fetch(`https://${domain}/oauth2/v1/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token,
        token_type_hint: hint,
        client_id: clientId,
      }).toString(),
    }).catch(() => {}); // Revocation errors are non-fatal — swallow silently

  if (tokens.accessToken)  revoke(tokens.accessToken,  'access_token');
  if (tokens.refreshToken) revoke(tokens.refreshToken, 'refresh_token');
}

// ─── Start an auth flow ───────────────────────────────────────────────────────

async function startAuthFlow({ domain, clientId, scopes, loginHint, adminTabId }) {
  const redirectUri = getRedirectUri();
  const verifier = await generateCodeVerifier();
  const challenge = await generateCodeChallenge(verifier);
  const state = generateState();

  const authParams = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scopes.join(' '),
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    nonce: generateState(),
  });
  if (loginHint) authParams.set('login_hint', loginHint);

  const authorizeUrl = `https://${domain}/oauth2/v1/authorize?${authParams}`;

  await chrome.storage.session.remove('tokenPreviewResult');

  const tab = await chrome.tabs.create({ url: authorizeUrl, active: true });

  await chrome.storage.session.set({
    pendingAuthFlow: {
      state,
      verifier,
      redirectUri,
      domain,
      clientId,
      tabId: tab.id,
      adminTabId: adminTabId || null,
      timestamp: Date.now(),
    },
  });
}

// ─── Message Handler ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'GET_REDIRECT_URI') {
    sendResponse({ redirectUri: getRedirectUri() });
    return false;
  }

  if (message.action === 'RUN_OAUTH_FLOW') {
    const { domain, clientId, scopes, loginHint, adminTabId } = message.payload;
    // If adminTabId isn't in the payload (e.g. triggered from the content script
    // panel rather than the extension popup), fall back to the sender's tab id.
    const effectiveAdminTabId = adminTabId || sender.tab?.id || null;
    startAuthFlow({ domain, clientId, scopes, loginHint, adminTabId: effectiveAdminTabId })
      .then(() => sendResponse({ success: true, started: true }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  // Sent by callback.js after a successful token exchange
  if (message.action === 'AUTH_CALLBACK_SUCCESS') {
    const { tokens, adminTabId, domain, clientId } = message;
    chrome.tabs.remove(sender.tab.id).catch(() => {});
    chrome.storage.session.remove('pendingAuthFlow');
    // Store and display first — the decoded contents are what we need
    const result = { tokens, timestamp: Date.now() };
    chrome.storage.session.set({ tokenPreviewResult: result });
    notifyAdminTab(adminTabId, { tokens });
    // Revoke immediately after — tokens are real and should not stay active
    revokeTokens(domain, clientId, tokens);
    sendResponse({ success: true });
    return false;
  }

  // Sent by callback.js when the exchange fails or an OAuth error is returned
  if (message.action === 'AUTH_CALLBACK_ERROR') {
    const { error, adminTabId } = message;
    chrome.tabs.remove(sender.tab.id).catch(() => {});
    chrome.storage.session.remove('pendingAuthFlow');
    const result = { error, timestamp: Date.now() };
    chrome.storage.session.set({ tokenPreviewResult: result });
    notifyAdminTab(adminTabId, { error });
    sendResponse({ success: true });
    return false;
  }
});

// Okta Token Preview — Auth Callback Page
//
// Okta redirects here after the user authenticates:
//   chrome-extension://{extensionId}/callback.html?code=...&state=...
//
// This page runs at chrome-extension://{extensionId}, so fetch requests to
// Okta's token endpoint carry Origin: chrome-extension://{extensionId}.
// Okta's CORS check extracts the origin of the registered redirect URI
// (chrome-extension://{extensionId}/callback.html) — the origins match, so
// the token exchange is accepted. This is why we can't do the exchange from
// the background service worker (its origin doesn't match chromiumapp.org).

(async () => {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');
  const oauthError = params.get('error');
  const oauthErrorDesc = params.get('error_description');

  async function finish(action, payload) {
    try {
      await chrome.runtime.sendMessage({ action, ...payload });
    } catch {}
    // Background will close this tab; window.close() is a fallback
    window.close();
  }

  if (oauthError) {
    return finish('AUTH_CALLBACK_ERROR', {
      error: `Authorization error: ${oauthError} — ${oauthErrorDesc || ''}`,
    });
  }

  if (!code) {
    return finish('AUTH_CALLBACK_ERROR', { error: 'No authorization code in callback URL.' });
  }

  // Retrieve the pending flow state (PKCE verifier, client info, etc.)
  let pending;
  try {
    ({ pendingAuthFlow: pending } = await chrome.storage.session.get('pendingAuthFlow'));
  } catch (err) {
    return finish('AUTH_CALLBACK_ERROR', { error: `Could not read flow state: ${err.message}` });
  }

  if (!pending) {
    return finish('AUTH_CALLBACK_ERROR', { error: 'No pending auth flow found. The flow may have expired.' });
  }

  if (pending.state !== state) {
    return finish('AUTH_CALLBACK_ERROR', {
      error: 'State mismatch — possible CSRF attack. Aborting.',
      adminTabId: pending.adminTabId,
    });
  }

  // Exchange the authorization code for tokens.
  // Critically, this fetch comes from chrome-extension://{extensionId} — matching
  // the origin of the registered redirect URI — so Okta's CORS check passes.
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: pending.clientId,
    code,
    code_verifier: pending.verifier,
    redirect_uri: pending.redirectUri,
  });

  let data;
  let ok;
  try {
    const response = await fetch(`https://${pending.domain}/oauth2/v1/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: body.toString(),
    });
    ok = response.ok;
    data = await response.json();
  } catch (err) {
    return finish('AUTH_CALLBACK_ERROR', {
      error: `Network error during token exchange: ${err.message}`,
      adminTabId: pending.adminTabId,
    });
  }

  if (!ok) {
    return finish('AUTH_CALLBACK_ERROR', {
      error: `Token exchange failed (${data.error}): ${data.error_description || ''}`,
      adminTabId: pending.adminTabId,
    });
  }

  finish('AUTH_CALLBACK_SUCCESS', {
    tokens: {
      accessToken: data.access_token || null,
      idToken: data.id_token || null,
      refreshToken: data.refresh_token || null,
      tokenType: data.token_type,
      expiresIn: data.expires_in,
      scope: data.scope,
    },
    adminTabId: pending.adminTabId,
    // Pass through so the background can immediately revoke the tokens
    domain: pending.domain,
    clientId: pending.clientId,
  });
})();

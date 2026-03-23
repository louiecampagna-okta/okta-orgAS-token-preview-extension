# Okta Org AS Token Preview Extension

A Chrome (and Edge) extension that integrates directly into the **Okta Admin Console** to preview OIDC tokens issued by the **Org Authorization Server** for any application — without leaving the admin console or writing a single line of code.

---

## What it does

When you open an OIDC application in the Okta Admin Console, a **Token Preview** button appears. Clicking it opens a side panel where you can:

- Select scopes (`openid`, `profile`, `email`, `groups`, `offline_access`, etc.)
- Optionally target a specific user
- Generate a token preview using **Auth Code + PKCE** against the org AS
- See the fully decoded **Access Token** and **ID Token** — every claim, labelled and explained

Tokens are **immediately revoked** after the decoded contents are captured and displayed. You see the claims; the tokens themselves never remain active.

---

## Features

- **Inline side panel** — slides in from the right inside the admin console, full shadow DOM isolation so Okta's CSS never interferes
- **Auto-registers the redirect URI** — uses the same session-cookie + `X-Okta-XsrfToken` approach as the Rockstar extension to update the app via the Management API, no API token needed
- **Immediate token revocation** — `POST /oauth2/v1/revoke` fires for access and refresh tokens the moment decoded contents are stored
- **Popup fallback** — the extension toolbar popup replicates the full panel experience and picks up token results via `chrome.storage.session` if the panel isn't open
- **Works across org types** — `*.okta.com`, `*.okta-emea.com`, `*.oktapreview.com`
- **Light theme** — matches Okta's Odyssey design system (white background, `#007dc1` blue, `#f4f4f6` header)

---

## Installation

> The extension is not listed on the Chrome Web Store. Load it as an unpacked extension.

1. Clone or download this repository
2. Open **`chrome://extensions`** (or **`edge://extensions`**)
3. Enable **Developer mode**
4. Click **Load unpacked** and select the repository folder
5. Navigate to any OIDC app in the Okta Admin Console — the **Token Preview** button will appear

---

## First-time setup (per app)

The extension needs its callback URI registered as a **Login redirect URI** in each app you want to preview tokens for.

1. Open the Token Preview panel on the app
2. Copy the **Extension Redirect URI** shown (format: `chrome-extension://{extensionId}/callback.html`)
3. Click **Auto-add to App** — the extension registers it automatically using your admin session
4. Or add it manually: **General tab → Login redirect URIs → Add URI**
5. Click **Check Registration** to confirm

> The redirect URI changes if you reinstall the extension (the extension ID is regenerated). Re-register it for each affected app after reinstallation.

---

## Usage

1. Open an OIDC application in the Admin Console
   `Admin Console → Applications → Applications → [select app]`
2. Click **Token Preview** in the page header (or the toolbar icon)
3. Select the scopes you want to evaluate
4. Optionally search for a specific user to use as `login_hint`
5. Click **Generate Token Preview**
6. A browser tab opens briefly, completes the OAuth flow using your existing admin session, and closes automatically
7. The decoded **Access Token** and **ID Token** appear in the panel

---

## How it works

### Auth flow

```
Admin Console page
  → Token Preview panel (content script, shadow DOM)
  → chrome.runtime.sendMessage → background service worker
  → chrome.tabs.create (auth tab, active: true)
  → Okta /oauth2/v1/authorize (picks up existing admin session)
  → Okta redirects to chrome-extension://{id}/callback.html
  → callback.js exchanges code at /oauth2/v1/token
      ↳ Origin: chrome-extension://{id}  (matches redirect URI origin → Okta accepts)
  → AUTH_CALLBACK_SUCCESS → background
  → revokeTokens() → POST /oauth2/v1/revoke (access + refresh)
  → chrome.storage.session → panel polls and renders decoded claims
```

### Why `chrome-extension://` as the redirect URI

The background service worker's `fetch` carries `Origin: chrome-extension://{id}`. Okta validates this against the origin of each registered redirect URI. Using `chrome-extension://{id}/callback.html` as the redirect URI means `chrome-extension://{id}` is its origin — the check passes. Using `chromiumapp.org` (the `chrome.identity` API redirect) would fail this check because the SW's origin doesn't match that domain.

### MV3 service worker persistence

All in-flight OAuth state is stored in `chrome.storage.session`, not in memory. The `chrome.tabs.onRemoved` listener is registered at the module top level so Chrome wakes the service worker on the event even if it was terminated between opening the auth tab and the redirect completing.

### Auto-register approach

Derived from the [Rockstar extension](https://gabrielsroka.github.io/rockstar/): use `credentials: 'include'` (session cookie) and read `#_xsrfToken` from the admin page DOM as the `X-Okta-XsrfToken` CSRF header. No bearer token is needed — and the bearer token from `okta-token-storage` would fail anyway since it lacks `okta.apps.manage` write scope.

---

## Security considerations

| Concern | Mitigation |
|---|---|
| Real tokens issued | Revoked immediately via `/oauth2/v1/revoke` after decoded contents are captured |
| Refresh tokens | Revoked alongside access tokens if `offline_access` scope was requested |
| ID tokens | Cannot be revoked (stateless JWT) — expire naturally per their `exp` claim |
| Token in `chrome.storage.session` | Cleared as soon as the panel reads it; session storage is cleared when the browser session ends |
| Redirect URI persistence | Remains registered in the app after use; remove it via the panel's **Remove from App** option if desired |

---

## Caveats

- **Org AS only** — this extension targets `/oauth2/v1/` (the org authorization server). Custom authorization servers have a built-in Token Preview in the admin console already.
- **Admin session required** — the OAuth flow reuses your existing admin session. If your session has expired the auth tab will show a login page.
- **Extension ID stability** — when loaded as an unpacked extension, the ID is derived from the directory path and stays stable as long as you don't move the folder or reinstall. Packing the extension with a `key` in the manifest would make it permanently stable.
- **Not a "faux" preview** — this issues and immediately revokes a real token. The decoded contents reflect exactly what Okta would include, including any custom attribute mappings. A purely simulated preview (no real token) is technically feasible for the org AS since its claim mappings are deterministic, but is not currently implemented.

---

## Browser support

| Browser | Supported |
|---|---|
| Chrome 102+ | ✅ |
| Edge 102+ (Chromium) | ✅ |
| Firefox | ❌ (uses different extension APIs) |
| Safari | ❌ |

---

## Acknowledgements

- [Rockstar](https://gabrielsroka.github.io/rockstar/) by Gabriel Sroka — session-cookie + `#_xsrfToken` approach for Okta Management API calls

# Browser extension playbook (Chrome/Edge/Firefox, Manifest V3)

## Threats
Over-broad permissions (store rejection, huge blast radius), malicious web pages sending messages to the extension, XSS in extension pages/popup, content scripts trusting page DOM data, remote code (forbidden in MV3), leaking user data to third parties, supply-chain compromise of the published extension, token theft from `chrome.storage`.

## Mandatory controls
1. **Manifest V3**, least privilege (`templates/browser-extension/manifest.json`):
   - Prefer `activeTab` + `scripting` over host permissions; list exact hosts; put optional capabilities in `optional_permissions` / `optional_host_permissions` and request at runtime.
   - No `<all_urls>` unless the core feature truly requires it (justify in store listing).
   - Default CSP (`script-src 'self'; object-src 'self'`); never `unsafe-eval` / remote scripts.
   - `externally_connectable` limited to your domains (or omitted).
   - `web_accessible_resources` minimal with explicit `matches` and `use_dynamic_url: true`.
2. **Messaging** (`templates/browser-extension/messaging.ts`): validate `sender.id === chrome.runtime.id`, and for content-script senders check `sender.origin`/`sender.tab`; validate message shape with a schema; explicit action allow-list; never forward raw page data into privileged APIs.
3. **Content scripts** treat the page as hostile: read DOM with `textContent`, never `innerHTML` from page data into extension UI; use isolated world (default); avoid `window.postMessage` or validate `event.source === window` and `event.origin`.
4. **No remote code**: bundle everything; remote *data* only (JSON), validated.
5. **Storage**: `chrome.storage.session` for tokens (memory, cleared on restart) or `storage.local` with minimal data; never store passwords; set `chrome.storage.session.setAccessLevel` to trusted contexts only.
6. **Network**: HTTPS only; backend validates extension requests (don't trust extension-side auth checks alone).
7. **Privacy**: disclose data use in the store listing and a privacy policy; collect minimum data.
8. **Release security**: 2FA on the developer account, CI builds from tagged source, reproducible zip, version bump discipline.

## Verification
- Load unpacked in a fresh profile; check the permission warning shown on install is minimal.
- Send a crafted `chrome.runtime.sendMessage` from a web page (if externally_connectable) and from the console of an unrelated page → rejected.
- `web-ext lint` (Firefox) / Chrome Web Store pre-review checklist.

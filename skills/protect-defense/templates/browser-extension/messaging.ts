// Validated extension messaging (background service worker side). Types for chrome: npm i -D @types/chrome
// Every message must: come from this extension, match an allow-listed action, and pass schema checks.

const ALLOWED_CONTENT_ORIGINS = new Set(['https://app.example.com']);

type Message =
  | { action: 'getSettings' }
  | { action: 'saveNote'; text: string; url: string };

function parseMessage(raw: unknown): Message | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const m = raw as Record<string, unknown>;
  switch (m.action) {
    case 'getSettings':
      return { action: 'getSettings' };
    case 'saveNote':
      if (typeof m.text !== 'string' || m.text.length > 5000) return null;
      if (typeof m.url !== 'string' || m.url.length > 2048) return null;
      try { if (new URL(m.url).protocol !== 'https:') return null; } catch { return null; }
      return { action: 'saveNote', text: m.text, url: m.url };
    default:
      return null;
  }
}

function isTrustedSender(sender: chrome.runtime.MessageSender): boolean {
  if (sender.id !== chrome.runtime.id) return false;
  // Extension pages (popup/options) have no tab; content scripts must come from allowed origins.
  if (sender.tab) return !!sender.origin && ALLOWED_CONTENT_ORIGINS.has(sender.origin);
  return sender.url?.startsWith(`chrome-extension://${chrome.runtime.id}/`) ?? false;
}

chrome.runtime.onMessage.addListener((raw, sender, sendResponse) => {
  if (!isTrustedSender(sender)) return false;
  const msg = parseMessage(raw);
  if (!msg) { sendResponse({ ok: false, error: 'invalid_message' }); return false; }

  (async () => {
    switch (msg.action) {
      case 'getSettings':
        return chrome.storage.local.get(['theme']);
      case 'saveNote': {
        const { notes = [] } = await chrome.storage.local.get('notes');
        await chrome.storage.local.set({ notes: [...(notes as unknown[]).slice(-499), { text: msg.text, url: msg.url, at: Date.now() }] });
        return { saved: true };
      }
    }
  })()
    .then((data) => sendResponse({ ok: true, data }))
    .catch(() => sendResponse({ ok: false, error: 'internal_error' }));
  return true; // keep the channel open for the async response
});

// Tokens: keep in session storage (memory) and restrict it to trusted contexts.
void chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });

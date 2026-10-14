// Rule corpus (browser extension service worker).
// ruleid: ext.remote-code
importScripts('https://cdn.acme.io/lib.js');
// ok: ext.remote-code
importScripts('lib/bundled.js');

// ruleid: ext.unvalidated-message
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => { run(msg); });


// Safe twin: the handler validates the sender before using the message.
// ok: ext.unvalidated-message
chrome.runtime.onMessage.addListener((msg, sender) => { if (sender.id !== chrome.runtime.id) return; run(msg); });

// ok: doc.pdfjs-eval
const doc = pdfjsLib.getDocument({ url, isEvalSupported: false });

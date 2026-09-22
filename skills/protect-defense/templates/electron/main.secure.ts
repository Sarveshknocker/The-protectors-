// Hardened Electron main process (Electron 30+). Follows the official security checklist.
import { app, BrowserWindow, ipcMain, session, shell, type IpcMainInvokeEvent } from 'electron';
import path from 'node:path';

const APP_ORIGIN = 'file://'; // or 'app://bundle' if you register a custom protocol with protocol.handle
const EXTERNAL_ALLOW = new Set(['https://docs.example.com', 'https://example.com']); // origins you may open in the OS browser

function isTrustedSender(event: IpcMainInvokeEvent): boolean {
  const url = event.senderFrame?.url ?? '';
  return url.startsWith(APP_ORIGIN);
}

function openExternalSafely(raw: string) {
  try {
    const u = new URL(raw);
    if (u.protocol === 'https:' && EXTERNAL_ALLOW.has(u.origin)) void shell.openExternal(u.toString());
  } catch { /* ignore invalid URLs */ }
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: false,
      devTools: !app.isPackaged,
    },
  });

  // Block navigation away from the app; route allowed links to the OS browser.
  win.webContents.on('will-navigate', (e, url) => {
    if (!url.startsWith(APP_ORIGIN)) { e.preventDefault(); openExternalSafely(url); }
  });
  win.webContents.setWindowOpenHandler(({ url }) => { openExternalSafely(url); return { action: 'deny' }; });
  win.webContents.on('will-attach-webview', (e) => e.preventDefault());

  win.once('ready-to-show', () => win.show());
  void win.loadFile(path.join(__dirname, '../renderer/index.html'));
}

app.whenReady().then(() => {
  // CSP for all responses (also add a <meta> CSP in index.html).
  session.defaultSession.webRequest.onHeadersReceived((details, cb) => {
    cb({ responseHeaders: { ...details.responseHeaders, 'Content-Security-Policy': ["default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"] } });
  });
  // Deny permission requests (camera, mic, notifications…) unless explicitly needed.
  session.defaultSession.setPermissionRequestHandler((_wc, _permission, cb) => cb(false));

  // Narrow, validated IPC handlers — one channel per capability.
  ipcMain.handle('settings:get', (event, key: unknown) => {
    if (!isTrustedSender(event)) throw new Error('Untrusted sender');
    if (typeof key !== 'string' || !/^[a-zA-Z0-9_.-]{1,64}$/.test(key)) throw new Error('Invalid key');
    return readSetting(key);
  });

  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

// Placeholder — replace with the app's settings store (use safeStorage for secrets).
function readSetting(key: string): string | null { void key; return null; }

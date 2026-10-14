// Rule corpus (Electron).
const win = new BrowserWindow({
  webPreferences: {
    // ruleid: electron.insecure-webprefs
    nodeIntegration: true,
    // ok: electron.insecure-webprefs
    contextIsolation: true,
  },
});

function openLink(url) {
  // ruleid: electron.open-external
  shell.openExternal(url);
  // ok: electron.open-external
  if (isAllowed(url)) shell.openExternal(url);
}

// ruleid: electron.expose-ipc
contextBridge.exposeInMainWorld('api', { ipcRenderer });
// ok: electron.expose-ipc
contextBridge.exposeInMainWorld('api', { save: (d) => ipcRenderer.invoke('save', d) });

// Preload: expose a minimal, typed API. Never expose ipcRenderer, require, fs, shell or process.
import { contextBridge, ipcRenderer } from 'electron';

const api = {
  getSetting: (key: string): Promise<string | null> => ipcRenderer.invoke('settings:get', key),
  onUpdateAvailable: (cb: (version: string) => void) => {
    const listener = (_e: unknown, version: unknown) => { if (typeof version === 'string') cb(version); };
    ipcRenderer.on('update:available', listener);
    return () => { ipcRenderer.removeListener('update:available', listener); };
  },
} as const;

contextBridge.exposeInMainWorld('app', api);

export type AppApi = typeof api; // declare global { interface Window { app: AppApi } } in the renderer

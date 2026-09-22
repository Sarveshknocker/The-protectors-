# Desktop software playbook (Electron, Tauri, .NET, Python GUI, native)

## Threats
Remote content gaining Node/OS access (Electron RCE), IPC abuse, insecure auto-update (MITM, unsigned updates), DLL/binary planting, secrets on disk, custom protocol handler injection, unsigned binaries triggering SmartScreen/Gatekeeper warnings (looks amateur), local privilege escalation via installers.

## Electron — mandatory (per official security checklist)
1. `BrowserWindow` webPreferences: `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, `webSecurity: true`, `allowRunningInsecureContent: false`, no `enableRemoteModule`. See `templates/electron/main.secure.ts`.
2. **Preload exposes a minimal typed API** via `contextBridge` (`templates/electron/preload.ts`) — never raw `ipcRenderer`, `require`, `fs`, `shell`.
3. **Validate IPC**: every `ipcMain.handle` validates `event.senderFrame.url` (app origin only) and the argument schema.
4. **Navigation lockdown**: `will-navigate` → prevent unless allow-listed; `setWindowOpenHandler` → deny and open allow-listed https links with `shell.openExternal` after URL validation.
5. **CSP** in the renderer (`<meta http-equiv="Content-Security-Policy">` or `session.webRequest.onHeadersReceived`): `default-src 'self'; script-src 'self'; object-src 'none'`.
6. **Load local content** via a custom protocol (`protocol.handle('app', …)`) or `file://` bundled files — never remote URLs in privileged windows.
7. **Fuses** (`@electron/fuses`): disable `RunAsNode`, `EnableNodeCliInspectArguments`, `EnableNodeOptionsEnvironmentVariable`; enable `EnableCookieEncryption`, `OnlyLoadAppFromAsar`, `EnableEmbeddedAsarIntegrityValidation`.
8. **Updates**: `electron-updater` over HTTPS with code-signed builds; verify signatures (default on macOS/Windows with signing).
9. **Secrets**: `safeStorage.encryptString` (OS keychain-backed) — not plain JSON files.
10. Keep Electron within supported major versions (security patches).

## Tauri
- `tauri.conf.json`: strict CSP, `dangerousDisableAssetCspModification: false`, allow-listed capabilities/permissions (v2 capabilities files) — only the commands/plugins used; scope `fs`/`shell`/`http` plugins narrowly.
- Validate all `#[tauri::command]` inputs; no generic shell/exec commands exposed.
- Updater with signature public key configured.

## .NET / native / Python GUI
- Code-sign binaries & installers (Authenticode, Apple Developer ID + notarization); signed auto-updates (Squirrel/Velopack/MSIX, Sparkle with EdDSA).
- Secrets via DPAPI / Windows Credential Manager / macOS Keychain / `keyring` (Python).
- Load DLLs from absolute trusted paths (`SetDefaultDllDirectories`, `LOAD_LIBRARY_SEARCH_SYSTEM32`).
- Obfuscation where IP matters: ConfuserEx/Dotfuscator (.NET), PyArmor/Nuitka (Python) — note it's a speed bump, not security.
- Installers don't grant world-writable install dirs; per-user install when admin isn't needed.

## Verification
- Electron: `npx @doyensec/electronegativity -i .` (if available); check DevTools is disabled in production builds.
- Try opening a remote link in-app → should open externally or be blocked.
- Confirm signed binaries: `signtool verify /pa`, `codesign --verify --deep --strict`, `spctl -a -vv`.

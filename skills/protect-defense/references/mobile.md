# Mobile app playbook (OWASP MASVS 2 / Mobile Top 10 2024)

## Threats
Improper credential usage (keys in the binary), insecure data storage, insecure communication, inadequate supply chain security, insufficient binary protections (reverse engineering, tampering), insecure authentication/authorization (client-side checks), WebView abuse, deep-link hijacking, privacy leaks via logs/backups/screenshots.

## Mandatory controls
1. **No secrets in the app.** Anything in the binary is public. Third-party API calls that need secret keys go through your backend. Only publishable/public keys may ship (Firebase config, Stripe publishable key).
2. **Secure storage**: tokens in Keychain (iOS) / Android Keystore — `expo-secure-store`, `react-native-keychain`, `flutter_secure_storage`, `EncryptedSharedPreferences`/DataStore + Tink. Never AsyncStorage/SharedPreferences/UserDefaults for secrets.
3. **Transport**: HTTPS only. Android: `templates/mobile/network_security_config.xml` (`cleartextTrafficPermitted="false"`), `android:usesCleartextTraffic="false"`. iOS: keep ATS on (no `NSAllowsArbitraryLoads`). **Certificate/public-key pinning** for high-risk apps (banking, health): pin SPKI hashes with a backup pin and an expiry/rollout plan (OkHttp `CertificatePinner`, TrustKit, `react-native-ssl-public-key-pinning`).
4. **Auth**: OAuth2 Authorization Code + PKCE via system browser (AppAuth / expo-auth-session); short-lived tokens; server enforces all authorization — never trust client flags like `isPremium`.
5. **Binary protection / obfuscation**:
   - Android: R8 `minifyEnabled true`, `shrinkResources true`, ProGuard rules; strip logs in release (`-assumenosideeffects class android.util.Log { *; }`).
   - iOS: strip debug symbols in release, bitcode not needed; Swift symbol obfuscation via commercial tools if required.
   - Flutter: `flutter build --obfuscate --split-debug-info=build/symbols`.
   - React Native: Hermes bytecode (default), avoid shipping source maps; JS obfuscation (`javascript-obfuscator` via metro) only for sensitive logic.
   - Integrity/attestation: **Play Integrity API** (Android) and **App Attest / DeviceCheck** (iOS) verified server-side; root/jailbreak detection as a risk signal, not a gate.
6. **Platform config**:
   - Android: `android:allowBackup="false"` (or dataExtractionRules), `debuggable` never set, components `exported="false"` unless required and permission-protected, `FLAG_SECURE` on sensitive screens, `PendingIntent.FLAG_IMMUTABLE`.
   - iOS: Data Protection `NSFileProtectionComplete` for sensitive files, hide sensitive UI in app switcher snapshot, Universal Links over custom schemes.
7. **WebViews**: load only bundled/https allow-listed origins; disable file access; no JS bridges exposed to remote content; `originWhitelist` restricted (RN).
8. **Deep links**: validate every parameter; never perform state-changing actions without user confirmation & auth.
9. **Privacy**: no PII/tokens in logs, crash reports scrubbed, clipboard use minimal, permission prompts just-in-time.

## Verification
- `apktool d app-release.apk` / `strings` on the binary: no secrets, no debug endpoints.
- MobSF static scan (if available) on release builds.
- Proxy test (on the user's own device/emulator): app refuses plain HTTP and, with pinning, refuses a user-installed CA.

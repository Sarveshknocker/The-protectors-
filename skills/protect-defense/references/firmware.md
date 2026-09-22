# Firmware / embedded / IoT playbook

Standards to align with: **ETSI EN 303 645** (consumer IoT), **IEC 62443-4-2** (industrial components), **NIST IR 8259A**, **EU Cyber Resilience Act** (vulnerability handling, SBOM, secure-by-default), PSA Certified / SESIP for MCU platforms.

## Threats
Hard-coded or shared credentials (Wi-Fi, cloud, default admin), firmware extraction via debug ports (JTAG/SWD/UART), unsigned or downgradeable updates, TLS without verification, memory-corruption in protocol parsers (BLE/MQTT/HTTP/Modbus/CAN), secrets readable from flash, insecure provisioning, no way to receive vulnerability reports or ship patches.

## Mandatory controls
1. **No universal secrets in firmware.** Per-device credentials provisioned at manufacturing (X.509 device certs or unique keys), ideally in a secure element (ATECC608, SE050, OPTIGA) or the MCU's key storage (ESP32 eFuse/HMAC/DS peripheral, STM32 SAES/OTP, nRF KMU). Wi-Fi credentials entered by the user at setup (provisioning over BLE/SoftAP with PoP), stored encrypted (ESP-IDF NVS encryption).
2. **Secure boot chain**: ROM → signed bootloader → signed application.
   - ESP32: Secure Boot v2 + flash encryption (Release mode) + disable ROM download/JTAG via eFuses.
   - Zephyr/nRF/STM32: MCUboot with ECDSA-P256 or Ed25519 image signatures, `CONFIG_BOOT_SIGNATURE_TYPE_*` (never NONE), TF-M where available.
   - Linux (Yocto/Buildroot): U-Boot verified boot (FIT signatures), dm-verity for rootfs, signed kernel modules.
3. **Secure updates (OTA)**: HTTPS with server verification → signature verification of the image before activation → **anti-rollback** (security version counter) → A/B slots with automatic revert on failed boot. Never accept images over plain HTTP, never skip signature checks. Tools: MCUboot, ESP-IDF `esp_https_ota` + Secure Boot, SWUpdate/RAUC/Mender (Linux).
4. **TLS done right**: mbedTLS/wolfSSL with `VERIFY_REQUIRED`, pinned CA bundle (`esp_crt_bundle_attach` or a specific root), correct time source (SNTP) before validating, TLS 1.2+ only. Arduino: `client.setCACert(root_ca)` — never `setInsecure()`.
5. **Lock debug interfaces in production**: STM32 RDP Level 1 (Level 2 is permanent — decide deliberately), nRF APPROTECT, ESP32 `JTAG_DISABLE` / `DIS_USB_JTAG` eFuses, disable UART console or require authentication; remove test/diagnostic commands.
6. **Memory safety** in all input parsers (network, BLE, serial, file): bounded copies (`snprintf`, `strlcpy`), explicit length checks before `memcpy`, no VLAs from input, integer-overflow checks on sizes, `-Wall -Wextra -Werror=format-security`, stack canaries (`-fstack-protector-strong`), MPU regions (no-execute RAM, stack guard), watchdog. Prefer Rust (`embassy`, `esp-hal`) for new parser code.
7. **Build hardening**: `templates/firmware/hardening-flags.cmake` for GCC/Clang targets; release builds strip symbols, disable asserts that leak info, enable LTO. Keep production and debug `sdkconfig`/`prj.conf` separate (`templates/firmware/sdkconfig.production`).
8. **Vulnerability handling**: SECURITY.md with a disclosure contact, SBOM (SPDX/CycloneDX from the build — Zephyr `west spdx`, Yocto `create-spdx`), a documented support period for updates.

## Testing
- Static analysis: `cppcheck --enable=warning,portability --inconclusive`, `clang-tidy` (cert-*, bugprone-*), CodeQL `c-cpp` in CI.
- Fuzz every parser on the host with libFuzzer/AFL++ (compile parser code for x86 with `-fsanitize=fuzzer,address,undefined`).
- Unit tests on host (Unity/Ceedling, GoogleTest, Zephyr `ztest`/`twister`).
- Verify fuses/protection settings on a production sample (espefuse.py summary, STM32CubeProgrammer option bytes).

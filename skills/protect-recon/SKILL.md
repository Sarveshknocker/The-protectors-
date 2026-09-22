---
name: protect-recon
description: Identify what a project is (website, API, mobile, desktop, browser extension, CLI, library, cloud/IaC, firmware/embedded, driver/kernel), its languages, frameworks, entry points, and build a per-file risk inventory. First step of any security verification.
---

# Recon

```bash
node <kit>/skills/protect-recon/scripts/recon.mjs . --out .protectors
```
Outputs `.protectors/recon.json` (full per-file inventory with risk tags) and `.protectors/recon.md` (summary).

## Then confirm by reading
1. Build/dependency manifests (package.json, pyproject/requirements, pom/gradle, go.mod, Cargo.toml, *.csproj, pubspec.yaml, composer.json, Gemfile, platformio.ini, CMakeLists.txt, Makefile/Kbuild, sdkconfig, prj.conf, *.inf, *.vcxproj).
2. Every entry point listed in recon.md, and the app bootstrap (server setup, middleware chain, router, main process, service worker, Application class).
3. Deploy/runtime config: Dockerfile, compose, k8s, Terraform, serverless, vercel/netlify, CI workflows.

## Project type → playbook
| `primaryType` / type id | Playbook (`protect-defense/references/`) |
|---|---|
| website | `website.md` (+ `api.md` if it has server routes) |
| api | `api.md` |
| mobile | `mobile.md` |
| desktop | `desktop.md` |
| browser-extension | `browser-extension.md` |
| cli, library, scripts | `cli-library.md` |
| cloud-infra | `cloud-infra.md` |
| firmware | `firmware.md` (PlatformIO, Arduino, ESP-IDF, Zephyr, STM32, FreeRTOS, Yocto/Buildroot, embedded Rust) |
| driver | `driver.md` (Linux kernel modules, Windows KMDF/WDM, macOS DriverKit, libusb/HID tools) |
| baas | `api.md` § BaaS (Supabase RLS / Firebase rules) |

Always apply `common.md` too. The recon type id maps to the playbook file name except `cli`, `library`, `scripts` → `cli-library.md` and `baas` → `api.md`.

## Record
In `.protectors/THREAT_MODEL.md` start with: one-paragraph description of what the project is and does, who uses it, what data it handles (PII, payments, credentials), where it runs, and its trust boundaries (browser ↔ server, app ↔ API, extension ↔ web page, main ↔ renderer, CI ↔ cloud).

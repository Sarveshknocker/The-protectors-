# CLI tool / library / scripts playbook

## Threats
Command injection via arguments/filenames, path traversal when writing files, unsafe temp files, insecure deserialisation of config files, credentials in config files with loose permissions, supply-chain attacks (typosquatting, compromised maintainer, install scripts), publishing secrets inside the package tarball.

## Mandatory controls
1. **Process execution**: no shell (`execFile`/`spawn` with arg arrays, `subprocess.run([...], shell=False)`); quote nothing by hand; validate/allow-list user-provided arguments; use `--` before user-supplied positional args.
2. **Filesystem**: resolve paths against a base dir and verify containment (`safeResolve` in `templates/node/guards.ts` / `guards.py`); use `fs.mkdtemp` / `tempfile.mkstemp`; write credential files with mode `0600`; don't follow symlinks when writing to shared dirs.
3. **Config parsing**: JSON/TOML with schema validation; `yaml.safe_load`; never `pickle`/`eval` config.
4. **Credentials**: read from env or OS keychain (`keytar`/`keyring`); never print them; mask in `--verbose` output.
5. **Network**: TLS verification always on; timeouts on every request; retries with backoff.
6. **Packaging**:
   - npm: `"files"` allow-list in package.json (prevents publishing `.env`, tests, keys); `npm pack --dry-run` check; `npm publish --provenance` from CI; 2FA on the account.
   - Python: `MANIFEST.in`/`[tool.hatch.build]` includes only package code; Trusted Publishing (OIDC) to PyPI.
   - No `preinstall`/`postinstall` scripts unless essential.
7. **Dependencies**: minimal, well-maintained; lockfile for apps/CLIs (libraries: test against lockfile + ranges); Dependabot.
8. **Errors**: helpful messages without stack traces by default (`--debug` to show); non-zero exit codes on failure.
9. **Professional polish**: `--help`/`--version`, semantic versioning, CHANGELOG, typed API (TS types / py.typed), docs for security-relevant options.

## Verification
- `npm pack --dry-run` / `python -m build && tar tf dist/*.tar.gz` → only intended files.
- Fuzz key parsers with odd inputs (`../`, very long strings, unicode, `;`, `$(…)`).

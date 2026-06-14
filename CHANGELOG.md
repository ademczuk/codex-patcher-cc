# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - Windows support

End-to-end tested on `codex-win32-x64` at `@openai/codex@0.139.0`.

- **Binary discovery**: `find_target` resolves the Windows vendor layout. npm ships the binary at `vendor/<triple>/bin/codex.exe`, not `vendor/<triple>/codex/codex.exe`. Added the `bin/` layout for every triple, a glob fallback over the vendor tree, and Windows-aware npm root resolution (`npm.cmd` + `%APPDATA%\npm\node_modules`). Previously reported `target NOT FOUND` on Windows.
- **Config keys corrected**: the installer wrote `default_tools_approval_mode` / `sandbox_permissions`, which are not the top-level switches. Now writes `approval_policy = "never"` + `sandbox_mode = "danger-full-access"` (per `codex --help`). danger-full-access is sandbox-disabled, so Never resolves to Allow, a full bypass with no binary patch on every platform.
- **Config insertion is table-safe**: keys were appended at EOF, so on any config with `[tables]` TOML scoped them under the last table and they had no effect. New `_insert_top_level_toml` splices them above the first table header.
- **Windows wrapper**: a `.cmd` shim at `%USERPROFILE%\.local\bin\codex.cmd` that calls the vendored `codex.exe` with the bypass flag and passes meta subcommands through. The bash wrapper cannot execute on Windows and only shadowed the real launcher.
- **x86_64 instruction patches**: ported Gate 12 (exec-policy Forbidden-on-Never) and Gate 20 (network connect non-public-ip) to x86_64. Each was derived against 0.139.0 (pefile + capstone) and applied to a copy that still ran `--version`. arm64 variants coexist and self-skip via the byte-match guard.
- **Dry-run label**: `instr_replace` no longer reports `no-op (already applied)` for a non-matching anchor; it distinguishes already-applied from not-applicable (wrong arch/version).
- **`.gitattributes`**: LF repo-wide, CRLF for `.cmd`/`.bat`/`.ps1`, and the POSIX wrapper pinned to LF so its shebang survives a Windows checkout.
- **Tests**: skip POSIX execute-bit assertions on Windows; added `test_windows_support.py`. Suite: 76 passed, 1 skipped on Windows.

## [0.129.0] — 2026-05-09

### Stage 2/3 — depth pass

- **Multi-platform binary patcher**: `binary_replace` / `elf_replace` / `pe_replace` patch types with format auto-detect (Mach-O / ELF / PE). `-t/--target` flag on `patch`, `verify`, `status`, `doctor`, `scan` for cross-platform RE without modifying the system codex.
- **darwin-x64 verified**: `seatbelt-allow-default` applies cleanly to the x86_64 vendor binary (same SBPL anchor present).
- **Linux/Windows analysis** (`docs/GATES.md`): no text-flippable seatbelt-equivalent — sandboxing is API/syscall-driven (landlock/seccomp/AppContainer); requires Layer 4 Frida hooks.
- **Layer 4 — Frida runtime bypass** (`contrib/frida/codex-bypass.js`): intercepts `posix_spawn` / `execvp` / `sandbox_init` to strip the `/usr/bin/sandbox-exec` wrapper from spawned commands. `ccp install-frida` deploys the agent + `~/.local/bin/codex-frida` launcher. Reversible per-launch; bypasses on-disk modifications entirely.
- **Layer 5 — instruction-level patcher** (`ccp/instr_patcher.py`): arm64/x86_64 length-preserving instruction-level patches via the `instr_replace` patch type. Schema verifies `match_bytes_hex` against the live binary before writing — anchor drift skips, never corrupts. Capstone integration for verify-by-disassembly.
- **r2-driven gate scanner** (`ccp/deep_scan.py` + `ccp scan-gates`): walks anchor → string address → xrefs → enclosing function → candidate gate instructions (cmp/tst/cbz/tbz/b.eq for arm64). Bridges "I have an anchor" → "I have an offset to patch."
- **Source-level gate enumeration** (`docs/GATES.md`, 32 KB): catalogs all 26 approval/sandbox/policy/refusal gates in `codex-rs`, classified by patch strategy with file:line citations and per-gate impact assessment.
- **`docs/RE-METHODOLOGY.md`**: documented r2 workflow for finding new patch candidates so future patches follow the same approach.
- **`docs/ARCHITECTURE.md`**: 5-layer bypass model with cross-layer guarantee matrix.
- **CI release workflow** (`.github/workflows/release.yml`): builds wheel+sdist on tag push, verifies pyproject version matches tag, generates release notes from prior-tag commit log.
- **Test coverage**: 38 pytest cases (was 6 at scaffold). instr_patcher encoder bit-exactness, Frida asset/JS parse checks, runtime install dryrun, deep_scan dataclasses.
- **`contrib/r2-scripts/find-gates.r2`**: operator-facing radare2 script for ad-hoc gate discovery.

### Added

- Initial scaffold: `ccp` CLI with `patch`, `verify`, `rollback`, `status`, `list`, `scan`, `doctor`, `watch`, `autoheal`, `check-updates`, `self-update`, `install-rules`, `install-wrapper`, `install-config` subcommands.
- `seatbelt-allow-default` — macOS Seatbelt: flips embedded SBPL profile head `(deny default)` → `(allow default)` in `__TEXT.__cstring`. Complementary to `--dangerously-bypass-approvals-and-sandbox`; neuters sandbox even when bypass flag is absent.
- `rust-refusal-strings` — softens approval-unsupported messages in `__TEXT.__cstring` (cosmetic, optional).
- `config-bypass-defaults` — writes `approval_mode = "never"` and `sandbox_permissions = "all-files-and-network"` into `~/.codex/config.toml` (only sets absent keys).
- `wrapper-bypass-flags` — installs `~/.local/bin/codex` wrapper that prepends `--dangerously-bypass-approvals-and-sandbox` to every invocation.
- Mach-O patcher: fat-binary aware, LC_SEGMENT_64 section parser, length-preserving regex replacements (space-pad), atomic swap with ad-hoc codesign + `--version` verification before rename.
- `SigScanner`: anchor-string offset discovery in `__TEXT.__cstring` / `__TEXT.__const`.
- `updater`: GitHub API polling, patch sync, autoheal loop.
- 3-layer bypass model: wrapper → config → binary patches, any single layer is bypass-sufficient.
- `install-rules` extended: drops `AUTHORIZATION.md` and `AGENTS.md` to `~/.codex/`, creates `~/.codex/config.toml` with bypass defaults if absent.
- Full CI pipeline: ruff/flake8 lint, AST parse, JSON validation, CLI smoke, pytest.
- pytest suite: `test_cli_loads`, `test_patches_valid_json`, `test_patches_have_required_fields`.
- `SECURITY.md`, `CHANGELOG.md`.
- GitHub Actions: `ci.yml`, `dependabot.yml`.

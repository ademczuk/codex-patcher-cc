"""Regression tests for the adversarial-review hardening (Findings 1-4).

1. instr_replace multi-site patches are atomic: a partial match writes nothing.
2. instr_replace is arch-gated for real, not only by byte coincidence.
3. config top-level presence ignores same-named keys nested under a [table].
4. binary discovery prefers and validates the host platform binary.
"""
from __future__ import annotations

import struct

import pytest

from ccp.__main__ import (
    _apply_toml_defaults,
    _binary_machine,
    _candidate_matches_host,
    _ordered_platform_pkgs,
    _patch_applies_to_format,
    _toml_top_level_text,
    patch_binary_inplace,
)


def _fake_pe(machine: int, body: bytes = b"") -> bytes:
    """Minimal PE32+ blob with a settable COFF Machine field and an appended body."""
    buf = bytearray(0x200 + len(body))
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)        # e_lfanew
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", buf, 0x84, machine)     # Machine (0x8664 x64, 0xAA64 arm64)
    buf[0x200:0x200 + len(body)] = body
    return bytes(buf)


# ── Finding 4: machine detection + host gating ──────────────────────────────

def test_binary_machine_pe():
    assert _binary_machine(_fake_pe(0x8664)) == "x86_64"
    assert _binary_machine(_fake_pe(0xAA64)) == "arm64"
    assert _binary_machine(b"not a binary") == "unknown"


def test_ordered_platform_pkgs_puts_host_first():
    ordered = _ordered_platform_pkgs()
    # Whatever the host is, its own package must lead the list.
    import sys, platform
    m = platform.machine().lower()
    arch = "arm64" if m in ("arm64", "aarch64") else "x64"
    osmap = {"win32": "win32", "darwin": "darwin", "linux": "linux"}
    osname = osmap.get("linux" if sys.platform.startswith("linux") else sys.platform)
    if osname:
        assert ordered[0] == f"@openai/codex-{osname}-{arch}"


# ── Finding 2: real arch gating ─────────────────────────────────────────────

def test_patch_applies_arch_gate():
    x86 = {"type": "instr_replace", "arch": "x86_64"}
    arm = {"type": "instr_replace", "arch": "arm64"}
    # Machine known and matching -> allowed; mismatched -> rejected.
    assert _patch_applies_to_format(x86, "pe", "x86_64") is True
    assert _patch_applies_to_format(x86, "pe", "arm64") is False
    assert _patch_applies_to_format(arm, "macho", "x86_64") is False
    # Machine unknown / not supplied -> backward compatible (allowed).
    assert _patch_applies_to_format(x86, "pe", None) is True
    assert _patch_applies_to_format(x86, "pe", "unknown") is True


def test_instr_arch_gate_skips_wrong_arch(tmp_path):
    # An arm64 binary with bytes that WOULD match an x86_64 patch must not be
    # written: the arch gate refuses before any byte coincidence matters.
    anchor = b"CCPTESTANCHOR"
    body = bytearray(0x60)
    body[0:len(anchor)] = anchor
    body[0x20:0x22] = bytes.fromhex("7445")  # would match if not arch-gated
    blob = _fake_pe(0xAA64, bytes(body))      # arm64 machine
    f = tmp_path / "codex.exe"
    f.write_bytes(blob)
    patch = {
        "id": "x86-on-arm", "type": "instr_replace", "arch": "x86_64",
        "patches": [{"anchor": "CCPTESTANCHOR", "offset_from_anchor": 0x20,
                     "match_bytes_hex": "7445", "replace_bytes_hex": "eb45",
                     "applied_marker_hex": "eb45"}],
    }
    res = patch_binary_inplace(f, [patch])
    assert res["applied"] == 0
    assert f.read_bytes() == blob   # untouched


# ── Finding 1: atomic multi-site instr patches ──────────────────────────────

def test_instr_partial_match_writes_nothing(tmp_path):
    anchor = b"CCPTESTANCHOR"
    body = bytearray(0x60)
    body[0:len(anchor)] = anchor
    body[0x20:0x22] = bytes.fromhex("7445")  # site 1 matches
    body[0x40:0x42] = bytes.fromhex("0000")  # site 2 does NOT match
    blob = _fake_pe(0x8664, bytes(body))
    f = tmp_path / "codex.exe"
    f.write_bytes(blob)
    patch = {
        "id": "multi", "type": "instr_replace", "arch": "x86_64",
        "patches": [
            {"anchor": "CCPTESTANCHOR", "offset_from_anchor": 0x20,
             "match_bytes_hex": "7445", "replace_bytes_hex": "eb45", "applied_marker_hex": "eb45"},
            {"anchor": "CCPTESTANCHOR", "offset_from_anchor": 0x40,
             "match_bytes_hex": "7445", "replace_bytes_hex": "eb45", "applied_marker_hex": "eb45"},
        ],
    }
    res = patch_binary_inplace(f, [patch])
    assert res["applied"] == 0
    assert f.read_bytes() == blob   # NOT partially written


def test_instr_all_sites_match_applies_all(tmp_path, monkeypatch):
    # When every site matches, all are written. Skip the exec --version verify
    # since this is a synthetic blob, not a runnable codex.
    monkeypatch.setattr("ccp.__main__._can_run_native", lambda *a, **k: False)
    anchor = b"CCPTESTANCHOR"
    body = bytearray(0x60)
    body[0:len(anchor)] = anchor
    body[0x20:0x22] = bytes.fromhex("7445")
    body[0x40:0x42] = bytes.fromhex("7445")
    blob = _fake_pe(0x8664, bytes(body))
    f = tmp_path / "codex.exe"
    f.write_bytes(blob)
    patch = {
        "id": "multi-ok", "type": "instr_replace", "arch": "x86_64",
        "patches": [
            {"anchor": "CCPTESTANCHOR", "offset_from_anchor": 0x20,
             "match_bytes_hex": "7445", "replace_bytes_hex": "eb45", "applied_marker_hex": "eb45"},
            {"anchor": "CCPTESTANCHOR", "offset_from_anchor": 0x40,
             "match_bytes_hex": "7445", "replace_bytes_hex": "eb45", "applied_marker_hex": "eb45"},
        ],
    }
    res = patch_binary_inplace(f, [patch])
    assert res["applied"] == 2
    out = f.read_bytes()
    assert out[0x220:0x222] == bytes.fromhex("eb45")
    assert out[0x240:0x242] == bytes.fromhex("eb45")
    assert len(out) == len(blob)


# ── Finding 3: top-level config detection ───────────────────────────────────

def test_toml_top_level_excludes_nested():
    text = 'model = "x"\n[profiles.work]\napproval_policy = "never"\n'
    top = _toml_top_level_text(text)
    assert "model" in top
    assert "approval_policy" not in top


def test_config_default_added_when_only_nested(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('model = "gpt-5.5"\n[profiles.work]\napproval_policy = "on-request"\n',
                   encoding="utf-8")
    p = {"type": "config_toml", "config_path": str(cfg),
         "defaults": {"approval_policy": '"never"', "sandbox_mode": '"danger-full-access"'}}
    ok, msg = _apply_toml_defaults(p, dry_run=True)
    assert ok
    # approval_policy exists only under [profiles.work], so the top-level default
    # must still be reported as needing to be added.
    assert "approval_policy" in msg and "sandbox_mode" in msg


def test_config_default_noop_when_already_bypass(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('approval_policy = "never"\n[profiles.work]\nx = 1\n', encoding="utf-8")
    p = {"type": "config_toml", "config_path": str(cfg),
         "defaults": {"approval_policy": '"never"'}}
    ok, msg = _apply_toml_defaults(p, dry_run=True)
    assert ok
    assert "no-op" in msg


# ── Workflow round — installer must OVERWRITE a conflicting top-level value ──

def test_config_overwrites_conflicting_top_level(tmp_path):
    # Most real users: a prior Codex run left approval_policy = "on-request".
    # The installer must set it to the bypass value, not report a false success.
    from ccp.__main__ import _apply_toml_defaults
    cfg = tmp_path / "config.toml"
    cfg.write_text('approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n[profiles.work]\nx = 1\n',
                   encoding="utf-8")
    p = {"type": "config_toml", "config_path": str(cfg),
         "defaults": {"approval_policy": '"never"', "sandbox_mode": '"danger-full-access"'}}
    ok, msg = _apply_toml_defaults(p, dry_run=False)
    assert ok
    import tomllib
    d = tomllib.load(open(cfg, "rb"))
    assert d["approval_policy"] == "never"             # overwritten, bypass active
    assert d["sandbox_mode"] == "danger-full-access"
    assert d["profiles"]["work"]["x"] == 1             # nested table untouched


def test_set_top_level_toml_leaves_nested_alone(tmp_path):
    from ccp.__main__ import _set_top_level_toml
    text = 'approval_policy = "on-request"\n[profiles.work]\napproval_policy = "untrusted"\n'
    new, changes = _set_top_level_toml(text, {"approval_policy": '"never"'})
    import tomllib
    d = tomllib.loads(new)
    assert d["approval_policy"] == "never"                       # top-level changed
    assert d["profiles"]["work"]["approval_policy"] == "untrusted"  # nested untouched
    assert any(c["action"] == "changed" for c in changes)


# ── Workflow round — shipped x86_64 patch opcode semantics (coverage) ───────

def test_shipped_x86_64_patch_opcodes():
    import json, glob, os
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for f in glob.glob(os.path.join(repo, "patches", "*x86_64.json")):
        obj = json.load(open(f))
        for sub in obj["patches"]:
            mb = bytes.fromhex(sub["match_bytes_hex"])
            rb = bytes.fromhex(sub["replace_bytes_hex"])
            assert len(mb) == len(rb), f"{f}: length not preserved"
            if len(mb) == 2:  # je rel8 -> jmp rel8, displacement preserved
                assert mb[0] == 0x74 and rb[0] == 0xEB, f"{f}: not je->jmp"
                assert mb[1] == rb[1], f"{f}: displacement byte changed"
            elif len(mb) == 6:  # jne rel32 -> 6-byte NOP
                assert mb[:2] == b"\x0f\x85", f"{f}: not jne rel32"
                assert rb == bytes.fromhex("660f1f440000"), f"{f}: not canonical 6-byte NOP"


# ── Workflow round — wrapper never resolves to itself (recursion guard) ─────

def test_resolve_excludes_wrapper(tmp_path, monkeypatch):
    import ccp.__main__ as m
    wrapper = tmp_path / ".local" / "bin" / "codex.cmd"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("@echo off\nREM ccp-wrapper\n", encoding="utf-8")
    monkeypatch.setattr(m, "find_target", lambda: None)         # force the PATH fallback
    monkeypatch.setattr(m.shutil, "which", lambda n: str(wrapper))  # PATH only has the wrapper
    # With the wrapper excluded, resolution must NOT return the wrapper.
    assert m._resolve_real_codex_invocation(exclude=wrapper) is None


# ── Round 2 — atomic verdict reporting (Finding 3) ──────────────────────────

def test_instr_verdict_mapping():
    from ccp.__main__ import _instr_verdict
    assert _instr_verdict(["apply", "miss"])[0] == "abort"      # partial -> abort
    assert _instr_verdict(["miss", "miss"])[0] == "abort"
    assert _instr_verdict(["already", "already"])[0] == "already"
    assert _instr_verdict(["apply", "already"])[0] == "apply"
    assert _instr_verdict(["optional", "optional"])[0] == "skip"


# ── Round 2 — install-config repairs old marker installs (Finding 1) ────────

def test_install_config_repairs_old_marker_install(tmp_path, monkeypatch):
    from ccp.__main__ import cmd_install_config, _toml_top_level_text
    import types
    # Old/broken install: marker present, but the bypass keys are nested under a
    # [table] (ineffective). Rerunning install-config must still add the top-level
    # keys instead of no-opping on the marker.
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    codex_dir = tmp_path / ".codex"
    codex_dir.mkdir()
    (codex_dir / "config.toml").write_text(
        '# ccp: bypass defaults\n[profiles.work]\napproval_policy = "never"\n'
        'sandbox_mode = "danger-full-access"\n', encoding="utf-8")

    rc = cmd_install_config(types.SimpleNamespace())
    assert rc == 0
    top = _toml_top_level_text((codex_dir / "config.toml").read_text(encoding="utf-8"))
    assert "approval_policy" in top
    assert "sandbox_mode" in top


# ── Round 3 — Windows wrapper refreshes a stale embedded target ─────────────

def test_windows_wrapper_refreshes_stale_target(tmp_path, monkeypatch):
    import ccp.__main__ as m
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    real = tmp_path / "vendor" / "codex.exe"
    real.parent.mkdir(parents=True)
    real.write_bytes(b"\x00" * 16)
    monkeypatch.setattr(m, "_resolve_real_codex_invocation", lambda exclude=None: str(real))

    cmd = tmp_path / ".local" / "bin" / "codex.cmd"
    cmd.parent.mkdir(parents=True)
    # Marker present, but CODEX_REAL points at a path that no longer exists.
    cmd.write_text('@echo off\nREM ccp-wrapper\nset "CODEX_REAL=C:\\gone\\codex.exe"\n',
                   encoding="utf-8")

    ok, msg, dst = m._install_windows_wrapper()
    assert ok and "refresh" in msg.lower()
    assert str(real) in dst.read_text(encoding="utf-8")   # rewritten to the live target

    # Now that the embedded target is valid, a second run is a clean no-op.
    ok2, msg2, _ = m._install_windows_wrapper()
    assert ok2 and "no-op" in msg2

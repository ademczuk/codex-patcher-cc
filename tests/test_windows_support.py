"""Windows-support regression tests (Mach-O/ELF/PE-agnostic; no real binary)."""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

from ccp.__main__ import (
    _insert_top_level_toml,
    _glob_vendor_binary,
    _VENDOR_SUBDIRS,
    load_patches,
)

ROOT = Path(__file__).resolve().parent.parent


def test_insert_top_level_toml_above_first_table():
    existing = 'model = "gpt-5.5"\n\n[projects.foo]\ntrust = "x"\n'
    block = '# ccp\napproval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
    out = _insert_top_level_toml(existing, block)
    d = tomllib.loads(out)
    # keys land top-level, not nested under [projects.foo]
    assert d["approval_policy"] == "never"
    assert d["sandbox_mode"] == "danger-full-access"
    assert "approval_policy" not in d.get("projects", {}).get("foo", {})
    assert d["model"] == "gpt-5.5"
    # block sits before the table header in the text
    assert out.index("approval_policy") < out.index("[projects.foo]")


def test_insert_top_level_toml_no_tables_appends():
    existing = 'model = "x"\n'
    block = 'approval_policy = "never"\n'
    out = _insert_top_level_toml(existing, block)
    d = tomllib.loads(out)
    assert d["approval_policy"] == "never" and d["model"] == "x"


def test_vendor_subdirs_cover_windows_bin_layout():
    assert "vendor/x86_64-pc-windows-msvc/bin/codex.exe" in _VENDOR_SUBDIRS


def test_glob_vendor_binary_finds_bin_layout(tmp_path):
    # Fake the npm bin/ layout with a >1MB file named codex.exe
    p = tmp_path / "vendor" / "x86_64-pc-windows-msvc" / "bin" / "codex.exe"
    p.parent.mkdir(parents=True)
    p.write_bytes(b"\x00" * (1_000_001))
    found = _glob_vendor_binary(tmp_path)
    assert found == p


def test_config_patch_uses_real_codex_keys():
    cfg = json.loads((ROOT / "patches" / "01-config-bypass-defaults.json").read_text())
    keys = cfg["defaults"]
    assert "approval_policy" in keys and "sandbox_mode" in keys
    assert "danger-full-access" in keys["sandbox_mode"]
    assert "never" in keys["approval_policy"]


def test_x86_64_instr_patches_present_and_valid():
    patches = {p["id"]: p for p in load_patches() if p.get("type") == "instr_replace"}
    for pid in (
        "instr-exec-policy-forbidden-on-never-nop-x86_64",
        "instr-network-connect-non-public-ip-allow-x86_64",
    ):
        assert pid in patches, f"missing {pid}"
        p = patches[pid]
        assert p["arch"] == "x86_64"
        for sub in p["patches"]:
            mb = bytes.fromhex(sub["match_bytes_hex"])
            rb = bytes.fromhex(sub["replace_bytes_hex"])
            assert len(mb) == len(rb), "instr patch must be length-preserving"

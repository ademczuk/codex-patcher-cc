"""Smoke tests for the Frida runtime bypass assets."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# Windows has no POSIX execute bit, so st_mode & 0o111 is always 0 there.
_skip_no_exec_bit = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX execute bit not present on Windows"
)

REPO_ROOT = Path(__file__).resolve().parent.parent
FRIDA_DIR = REPO_ROOT / "contrib" / "frida"
AGENT = FRIDA_DIR / "codex-bypass.js"
WRAPPER = FRIDA_DIR / "codex-frida-wrapper.sh"
README = FRIDA_DIR / "README.md"


def test_frida_assets_exist():
    assert AGENT.is_file(), f"missing: {AGENT}"
    assert WRAPPER.is_file(), f"missing: {WRAPPER}"
    assert README.is_file(), f"missing: {README}"


@_skip_no_exec_bit
def test_wrapper_is_executable():
    mode = WRAPPER.stat().st_mode
    assert mode & 0o111, f"wrapper not executable: mode={oct(mode)}"


def test_wrapper_starts_with_shebang():
    head = WRAPPER.read_text().splitlines()[0]
    assert head.startswith("#!"), f"wrapper missing shebang: {head!r}"


def test_agent_advertises_expected_hooks():
    src = AGENT.read_text()
    for fn in ("posix_spawn", "execvp", "sandbox_init"):
        assert fn in src, f"agent does not reference {fn}"


def test_agent_strips_sandbox_exec():
    src = AGENT.read_text()
    assert "/usr/bin/sandbox-exec" in src
    assert "codex-linux-sandbox" in src
    # The dash separator is the bypass marker — confirm logic is present.
    assert 'indexOf("--")' in src


@pytest.mark.skipif(shutil.which("node") is None, reason="node not on PATH")
def test_agent_parses_with_node_check():
    out = subprocess.run(
        ["node", "--check", str(AGENT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, f"node --check failed:\n{out.stderr}"


def test_runtime_module_imports():
    from ccp import runtime

    assert callable(runtime.install_frida)
    assert callable(runtime.uninstall_frida)
    assert runtime.AGENT_SRC == AGENT
    assert runtime.WRAPPER_SRC == WRAPPER


def test_runtime_install_dryrun_to_tmp(tmp_path, monkeypatch):
    """Install with HOME pointed at tmp_path; verify both files copied."""
    from ccp import runtime

    monkeypatch.setenv("HOME", str(tmp_path))
    # Re-resolve module-level paths under the new HOME.
    monkeypatch.setattr(runtime, "AGENT_DST_DIR", tmp_path / ".codex" / "frida")
    monkeypatch.setattr(runtime, "AGENT_DST", tmp_path / ".codex" / "frida" / "codex-bypass.js")
    monkeypatch.setattr(runtime, "WRAPPER_DST_DIR", tmp_path / ".local" / "bin")
    monkeypatch.setattr(runtime, "WRAPPER_DST", tmp_path / ".local" / "bin" / "codex-frida")

    result = runtime.install_frida(force=True, verbose=False)
    assert result["agent_installed"] is True
    assert result["wrapper_installed"] is True
    assert (tmp_path / ".codex" / "frida" / "codex-bypass.js").is_file()
    assert (tmp_path / ".local" / "bin" / "codex-frida").is_file()
    # Wrapper copied with execute bit preserved (POSIX only; Windows has no
    # execute bit, so the chmod is a no-op there).
    if sys.platform != "win32":
        assert (tmp_path / ".local" / "bin" / "codex-frida").stat().st_mode & 0o111

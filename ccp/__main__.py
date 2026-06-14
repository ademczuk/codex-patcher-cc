"""
ccp — Codex CLI Patcher
Rust Mach-O binary patches + wrapper + config installer for OpenAI Codex CLI.
Regex-signature patches survive minor/patch releases.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import shutil
import struct as _struct
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from . import updater as _updater
from . import scanner as _scanner

ROOT       = Path(__file__).resolve().parent.parent
PATCH_DIR  = ROOT / "patches"
BACKUP_DIR = Path.home() / ".ccp" / "backups"

G, Y, R, B, X = "\033[32m", "\033[33m", "\033[31m", "\033[1m", "\033[0m"

# ── console encoding safety ───────────────────────────────────────────────────
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:
    pass

_enc = (getattr(sys.stdout, "encoding", None) or "").lower()
if "utf" not in _enc:
    CHECK, CROSS, WARN_ICON, ARROW, DOT = "[ok]", "[X]", "[!]", "->", "*"
    G = Y = R = B = X = ""
else:
    CHECK, CROSS, WARN_ICON, ARROW, DOT = "✓", "✗", "⚠", "→", "·"

_PKG = "@openai/codex"

# Platform sub-packages — distribution model for Codex CLI Rust binary
_PLATFORM_PKGS = [
    "@openai/codex-linux-x64",
    "@openai/codex-linux-arm64",
    "@openai/codex-darwin-x64",
    "@openai/codex-darwin-arm64",
    "@openai/codex-win32-x64",
    "@openai/codex-win32-arm64",
]

# Vendor path pattern inside each platform package:
# <pkg>/vendor/<triple>/<subdir>/codex  (or codex.exe on Windows)
# The <subdir> moved from "codex/" to "bin/" in current npm builds; every
# Windows build ships the binary under bin/. Both layouts are enumerated so
# detection is layout-agnostic, and find_target() has a glob fallback for any
# layout not listed here.
_VENDOR_SUBDIRS = [
    "vendor/aarch64-apple-darwin/codex/codex",
    "vendor/x86_64-apple-darwin/codex/codex",
    "vendor/aarch64-unknown-linux-gnu/codex/codex",
    "vendor/x86_64-unknown-linux-gnu/codex/codex",
    "vendor/aarch64-pc-windows-msvc/codex/codex.exe",
    "vendor/x86_64-pc-windows-msvc/codex/codex.exe",
    # bin/ layout (current npm distribution, including all Windows builds)
    "vendor/aarch64-apple-darwin/bin/codex",
    "vendor/x86_64-apple-darwin/bin/codex",
    "vendor/aarch64-unknown-linux-gnu/bin/codex",
    "vendor/x86_64-unknown-linux-gnu/bin/codex",
    "vendor/aarch64-pc-windows-msvc/bin/codex.exe",
    "vendor/x86_64-pc-windows-msvc/bin/codex.exe",
]

# Filenames the Rust binary may use, for the glob fallback.
_BINARY_NAMES = ("codex", "codex.exe")


# ── target discovery ──────────────────────────────────────────────────────────

def _npm_global_roots() -> list[Path]:
    roots: list[Path] = []
    # `npm` is npm.cmd on Windows; bare "npm" via subprocess (no shell) fails to
    # resolve there, so try both names.
    npm_cmds = ["npm.cmd", "npm"] if sys.platform == "win32" else ["npm"]
    for npm_cmd in npm_cmds:
        try:
            r = subprocess.run([npm_cmd, "root", "-g"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                roots.insert(0, Path(r.stdout.strip()))
                break
        except Exception:
            continue
    home = Path.home()
    # Windows: npm global modules live under %APPDATA%\npm\node_modules.
    appdata = os.environ.get("APPDATA")
    if appdata:
        roots.append(Path(appdata) / "npm" / "node_modules")
    roots += [
        home / ".npm-global/lib/node_modules",
        home / ".local/lib/node_modules",
        home / "AppData/Roaming/npm/node_modules",
        Path("/opt/homebrew/lib/node_modules"),
        Path("/usr/local/lib/node_modules"),
        Path("/usr/lib/node_modules"),
    ]
    # De-dupe while preserving order.
    seen: set[str] = set()
    uniq: list[Path] = []
    for r in roots:
        k = str(r).lower()
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq


def _glob_vendor_binary(plat_dir: Path) -> Path | None:
    """
    Layout-agnostic fallback: find the Rust binary anywhere under <plat_dir>/vendor.
    Returns the largest matching file over 1 MB (the real binary, not a shim).
    """
    vendor = plat_dir / "vendor"
    if not vendor.is_dir():
        return None
    best: Path | None = None
    best_size = 0
    for name in _BINARY_NAMES:
        for p in vendor.rglob(name):
            try:
                if p.is_file():
                    sz = p.stat().st_size
                    if sz > 1_000_000 and sz > best_size:
                        best, best_size = p, sz
            except OSError:
                continue
    return best


def find_target() -> Path | None:
    """
    Locate the Codex CLI Rust binary. Walks npm global roots looking for:
      <root>/@openai/codex/node_modules/@openai/codex-{platform}/vendor/.../codex
    Returns Path to binary or None.
    """
    for npm_root in _npm_global_roots():
        codex_pkg = npm_root / _PKG
        if not codex_pkg.is_dir():
            continue
        # Walk platform sub-packages nested under main package
        node_mods = codex_pkg / "node_modules"
        for plat_pkg in _PLATFORM_PKGS:
            plat_dir = node_mods / plat_pkg
            if not plat_dir.is_dir():
                continue
            for vendor_suffix in _VENDOR_SUBDIRS:
                p = plat_dir / vendor_suffix
                if p.exists() and p.stat().st_size > 1_000_000:
                    return p
            # Fallback: glob the vendor tree if the layout is not enumerated.
            g = _glob_vendor_binary(plat_dir)
            if g is not None:
                return g
        # Also check vendor directly under codex-{platform} (flat layout)
        for plat_pkg in _PLATFORM_PKGS:
            # Look for platform-named dirs adjacent to node_modules
            pkg_name = plat_pkg.split("/")[-1]  # e.g. codex-darwin-arm64
            plat_dir2 = npm_root / plat_pkg
            if not plat_dir2.is_dir():
                continue
            for vendor_suffix in _VENDOR_SUBDIRS:
                p = plat_dir2 / vendor_suffix
                if p.exists() and p.stat().st_size > 1_000_000:
                    return p
            g = _glob_vendor_binary(plat_dir2)
            if g is not None:
                return g

    # Last resort: resolve `which codex` from PATH and check for sibling binary
    try:
        r = subprocess.run(["which", "codex"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            launcher = Path(r.stdout.strip()).resolve()
            # codex.js is a launcher; look for the Rust binary in adjacent node_modules
            candidate_root = launcher.parent.parent / "lib" / "node_modules"
            if candidate_root.is_dir():
                codex_pkg = candidate_root / _PKG
                node_mods = codex_pkg / "node_modules"
                for plat_pkg in _PLATFORM_PKGS:
                    plat_dir = node_mods / plat_pkg
                    if not plat_dir.is_dir():
                        continue
                    for vendor_suffix in _VENDOR_SUBDIRS:
                        p = plat_dir / vendor_suffix
                        if p.exists() and p.stat().st_size > 1_000_000:
                            return p
    except Exception:
        pass

    return None


def sha256_short(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:12]


# ── Format detection ──────────────────────────────────────────────────────────

def _binary_format(data: bytes | bytearray) -> str:
    """Return 'macho', 'elf', 'pe', or 'unknown' based on magic bytes."""
    if len(data) < 8:
        return "unknown"
    magic4 = bytes(data[:4])
    if magic4 in (b"\xCF\xFA\xED\xFE", b"\xFE\xED\xFA\xCF",
                  b"\xCE\xFA\xED\xFE", b"\xFE\xED\xFA\xCE",
                  b"\xCA\xFE\xBA\xBE", b"\xBE\xBA\xFE\xCA",
                  b"\xCA\xFE\xBA\xBF", b"\xBF\xBA\xFE\xCA"):
        return "macho"
    if magic4 == b"\x7FELF":
        return "elf"
    if magic4[:2] == b"MZ":
        if len(data) < 0x40:
            return "unknown"
        try:
            e_lfanew = _struct.unpack_from("<I", data, 0x3C)[0]
            if 0 <= e_lfanew < len(data) - 4 and bytes(data[e_lfanew:e_lfanew + 4]) == b"PE\x00\x00":
                return "pe"
        except Exception:
            pass
    return "unknown"


# ── Mach-O section helpers ────────────────────────────────────────────────────

def _macho_sections(data: bytes | bytearray) -> list[tuple[str, str, int, int]]:
    """
    Parse a Mach-O binary (arm64 or x86_64, possibly fat) and return a list of
    (segname, sectname, offset, size) for every section.
    Handles fat binaries by picking the first 64-bit slice.
    """
    sections: list[tuple[str, str, int, int]] = []
    if len(data) < 8:
        return sections

    magic = _struct.unpack_from(">I", data, 0)[0]

    # Fat binary — recurse into first arm64 or x86_64 slice
    if magic in (0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA):
        big = magic in (0xCAFEBABE, 0xCAFEBABF)
        fmt = ">I" if big else "<I"
        nfat = _struct.unpack_from(fmt, data, 4)[0]
        entry_size = 20 if magic in (0xCAFEBABE, 0xBEBAFECA) else 32
        for i in range(nfat):
            base = 8 + i * entry_size
            off = _struct.unpack_from(fmt, data, base + 8)[0]
            sub = bytes(data[off:])
            subs = _macho_sections(sub)
            # Return offset-adjusted sections
            for seg, sec, sec_off, sec_size in subs:
                sections.append((seg, sec, off + sec_off, sec_size))
            if sections:
                return sections
        return sections

    if magic not in (0xFEEDFACF, 0xCFFAEDFE, 0xFEEDFACE, 0xCEFAEDFE):
        return sections  # not Mach-O

    is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    end = ">" if magic in (0xFEEDFACF, 0xFEEDFACE) else "<"

    ncmds = _struct.unpack_from(end + "I", data, 16)[0]
    hdr_size = 32 if is_64 else 28
    cur = hdr_size

    LC_SEGMENT_64 = 0x19
    LC_SEGMENT    = 0x01

    for _ in range(ncmds):
        if cur + 8 > len(data):
            break
        cmd, cmdsize = _struct.unpack_from(end + "II", data, cur)
        if cmd == LC_SEGMENT_64:
            segname = bytes(data[cur + 8: cur + 24]).split(b"\x00", 1)[0].decode("ascii", errors="replace")
            nsects  = _struct.unpack_from(end + "I", data, cur + 64)[0]
            sect_base = cur + 72
            for j in range(nsects):
                s = sect_base + j * 80
                if s + 80 > len(data):
                    break
                sectname = bytes(data[s: s + 16]).split(b"\x00", 1)[0].decode("ascii", errors="replace")
                sec_size = _struct.unpack_from(end + "Q", data, s + 40)[0]
                sec_off  = _struct.unpack_from(end + "I", data, s + 48)[0]
                sections.append((segname, sectname, sec_off, sec_size))
        elif cmd == LC_SEGMENT:
            segname = bytes(data[cur + 8: cur + 24]).split(b"\x00", 1)[0].decode("ascii", errors="replace")
            nsects  = _struct.unpack_from(end + "I", data, cur + 48)[0]
            sect_base = cur + 56
            for j in range(nsects):
                s = sect_base + j * 68
                if s + 68 > len(data):
                    break
                sectname = bytes(data[s: s + 16]).split(b"\x00", 1)[0].decode("ascii", errors="replace")
                sec_size = _struct.unpack_from(end + "I", data, s + 36)[0]
                sec_off  = _struct.unpack_from(end + "I", data, s + 40)[0]
                sections.append((segname, sectname, sec_off, sec_size))
        cur += cmdsize if cmdsize >= 8 else 8

    return sections


def _string_section_bounds(data: bytes | bytearray) -> list[tuple[int, int]]:
    """
    Return (offset, end) pairs for __TEXT.__cstring and __TEXT.__const sections
    (the regions that hold string constants in a Rust Mach-O binary).
    Falls back to full file if no sections found.
    """
    sects = _macho_sections(data)
    bounds: list[tuple[int, int]] = []
    for seg, sec, off, size in sects:
        if seg == "__TEXT" and sec in ("__cstring", "__const") and size > 0:
            bounds.append((off, off + size))
    if not bounds:
        # Fallback: patch entire file (length-preserving, safe)
        bounds.append((0, len(data)))
    return bounds


# ── ELF section helpers ───────────────────────────────────────────────────────

def _elf_sections(data: bytes | bytearray) -> list[tuple[str, int, int]]:
    """
    Parse a 64-bit ELF binary and return (section_name, file_offset, size) tuples.
    Returns empty list if not a recognizable ELF.
    """
    sections: list[tuple[str, int, int]] = []
    if len(data) < 64 or bytes(data[:4]) != b"\x7FELF":
        return sections
    ei_class = data[4]   # 1=32, 2=64
    ei_data  = data[5]   # 1=LE, 2=BE
    end = "<" if ei_data == 1 else ">"
    if ei_class != 2:
        return sections  # 32-bit ELF unsupported (codex bins are 64)
    # Elf64_Ehdr: e_shoff @ 0x28 (Q), e_shentsize @ 0x3a (H), e_shnum @ 0x3c (H), e_shstrndx @ 0x3e (H)
    try:
        e_shoff     = _struct.unpack_from(end + "Q", data, 0x28)[0]
        e_shentsize = _struct.unpack_from(end + "H", data, 0x3A)[0]
        e_shnum     = _struct.unpack_from(end + "H", data, 0x3C)[0]
        e_shstrndx  = _struct.unpack_from(end + "H", data, 0x3E)[0]
    except _struct.error:
        return sections
    if e_shoff == 0 or e_shnum == 0 or e_shentsize < 64:
        return sections
    # Read section header string table
    if e_shstrndx >= e_shnum:
        return sections
    shstr_off = e_shoff + e_shstrndx * e_shentsize
    if shstr_off + 64 > len(data):
        return sections
    try:
        shstr_file_off = _struct.unpack_from(end + "Q", data, shstr_off + 0x18)[0]
        shstr_size     = _struct.unpack_from(end + "Q", data, shstr_off + 0x20)[0]
    except _struct.error:
        return sections
    if shstr_file_off + shstr_size > len(data):
        return sections
    shstrtab = bytes(data[shstr_file_off: shstr_file_off + shstr_size])
    # Walk every section header
    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        if sh + 64 > len(data):
            break
        try:
            sh_name      = _struct.unpack_from(end + "I", data, sh + 0x00)[0]
            sh_type      = _struct.unpack_from(end + "I", data, sh + 0x04)[0]
            sh_offset    = _struct.unpack_from(end + "Q", data, sh + 0x18)[0]
            sh_size      = _struct.unpack_from(end + "Q", data, sh + 0x20)[0]
        except _struct.error:
            continue
        if sh_type == 8:  # SHT_NOBITS (.bss) — no file content
            continue
        # Read NUL-terminated name from shstrtab
        end_n = shstrtab.find(b"\x00", sh_name)
        if end_n < 0:
            continue
        name = shstrtab[sh_name:end_n].decode("ascii", errors="replace")
        if sh_offset + sh_size > len(data):
            continue
        sections.append((name, sh_offset, sh_size))
    return sections


def _elf_string_bounds(data: bytes | bytearray) -> list[tuple[int, int]]:
    """
    Return (offset, end) for ELF .rodata, .data.rel.ro, and .data sections — the
    regions that hold Rust string constants in a Linux/musl ELF binary.
    """
    sects = _elf_sections(data)
    bounds: list[tuple[int, int]] = []
    for name, off, size in sects:
        if name in (".rodata", ".data.rel.ro", ".data") and size > 0:
            bounds.append((off, off + size))
    if not bounds:
        bounds.append((0, len(data)))
    return bounds


# ── PE section helpers ────────────────────────────────────────────────────────

def _pe_sections(data: bytes | bytearray) -> list[tuple[str, int, int]]:
    """
    Parse a PE32+ binary and return (section_name, raw_offset, raw_size) tuples.
    """
    sections: list[tuple[str, int, int]] = []
    if len(data) < 0x40 or bytes(data[:2]) != b"MZ":
        return sections
    try:
        e_lfanew = _struct.unpack_from("<I", data, 0x3C)[0]
    except _struct.error:
        return sections
    if e_lfanew + 24 > len(data) or bytes(data[e_lfanew:e_lfanew + 4]) != b"PE\x00\x00":
        return sections
    coff = e_lfanew + 4
    try:
        n_sections      = _struct.unpack_from("<H", data, coff + 0x02)[0]
        opt_header_size = _struct.unpack_from("<H", data, coff + 0x10)[0]
    except _struct.error:
        return sections
    sect_table = coff + 20 + opt_header_size
    for i in range(n_sections):
        s = sect_table + i * 40
        if s + 40 > len(data):
            break
        name = bytes(data[s:s + 8]).rstrip(b"\x00").decode("ascii", errors="replace")
        try:
            raw_size  = _struct.unpack_from("<I", data, s + 0x10)[0]
            raw_off   = _struct.unpack_from("<I", data, s + 0x14)[0]
        except _struct.error:
            continue
        if raw_off + raw_size > len(data):
            continue
        sections.append((name, raw_off, raw_size))
    return sections


def _pe_string_bounds(data: bytes | bytearray) -> list[tuple[int, int]]:
    """
    Return (offset, end) for PE .rdata and .data sections — where Rust string
    constants live in a windows-msvc binary.
    """
    sects = _pe_sections(data)
    bounds: list[tuple[int, int]] = []
    for name, off, size in sects:
        if name in (".rdata", ".data") and size > 0:
            bounds.append((off, off + size))
    if not bounds:
        bounds.append((0, len(data)))
    return bounds


# ── Unified format-aware string bounds ────────────────────────────────────────

def _binary_string_bounds(data: bytes | bytearray) -> list[tuple[int, int]]:
    """Auto-detect format and return string-section bounds."""
    fmt = _binary_format(data)
    if fmt == "macho":
        return _string_section_bounds(data)
    if fmt == "elf":
        return _elf_string_bounds(data)
    if fmt == "pe":
        return _pe_string_bounds(data)
    return [(0, len(data))]


def codesign(path: Path) -> tuple[bool, str]:
    """Ad-hoc re-sign a Mach-O binary. Required on macOS after byte modification."""
    if sys.platform != "darwin":
        return True, "n/a (non-darwin)"
    r = subprocess.run(
        ["codesign", "--force", "--sign", "-", str(path)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return False, (r.stderr or r.stdout or "").strip()
    return True, "ok"


def _can_run_native(fmt: str, data: bytes | bytearray | None = None) -> bool:
    """
    Whether the current OS+arch can execute a binary of the given format directly.
    If `data` is provided, also checks the binary's CPU arch against the host arch.
    On darwin we skip exec-verify when the binary is foreign-arch (Rosetta is slow
    enough that --version timeouts cause false-positive failures during patch).
    """
    if fmt == "macho" and sys.platform == "darwin":
        if data is None:
            return True
        # Match darwin host arch to Mach-O cputype to avoid Rosetta slowness.
        try:
            import platform as _plat
            host_arch = _plat.machine()  # 'arm64' or 'x86_64'
            magic = _struct.unpack_from(">I", data, 0)[0]
            # Skip fat binaries — they will always have a slice that runs natively.
            if magic in (0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA):
                return True
            end = ">" if magic in (0xFEEDFACF, 0xFEEDFACE) else "<"
            cputype = _struct.unpack_from(end + "I", data, 4)[0] & 0x00FFFFFF
            # CPU_TYPE_ARM64 = 0x0100000C & 0xFFFFFF = 0x0C; CPU_TYPE_X86_64 = 0x07
            if cputype == 0x0C and host_arch == "arm64":
                return True
            if cputype == 0x07 and host_arch == "x86_64":
                return True
            return False  # foreign arch (e.g. x86_64 binary on arm64 host)
        except Exception:
            return True
    if fmt == "elf" and sys.platform.startswith("linux"):
        return True
    if fmt == "pe" and sys.platform == "win32":
        return True
    return False


def patch_binary_inplace(binary: Path, patches: list[dict]) -> dict:
    """
    In-place Rust binary byte patcher (format-agnostic).
    - Auto-detects Mach-O / ELF / PE; locates the format's string-constant sections.
    - Applies length-preserving regex/literal replacements (space-pad if shorter).
    - Writes to a .tmp sibling, codesigns (macOS-Mach-O only), runs --version to
      verify when the format matches the host OS, atomic renames.
    Returns dict: {ok, applied, skipped, err?, per_patch}.
    """
    mode = binary.stat().st_mode & 0o7777
    original_size = binary.stat().st_size
    data = bytearray(binary.read_bytes())
    fmt = _binary_format(data)

    bounds = _binary_string_bounds(data)
    applied_total = 0
    skipped_total = 0
    per_patch: list[dict] = []

    for p in patches:
        applied_n = 0
        skipped_n = 0

        # ── instr_replace branch: arm64/x86_64 instruction-level patches.
        # Different schema (anchor + offset_from_anchor + match_bytes_hex)
        # so handled separately from the regex/byte-search loop below.
        if p.get("type") == "instr_replace":
            from .instr_patcher import apply_instr_patch
            arch = p.get("arch", "arm64")
            for sub in p.get("patches", []):
                anchor = sub.get("anchor", "")
                ofs    = int(sub.get("offset_from_anchor", 0))
                mbx    = sub.get("match_bytes_hex", "")
                rbx    = sub.get("replace_bytes_hex", "")
                amk    = sub.get("applied_marker_hex")
                if not (anchor and mbx and rbx):
                    skipped_n += 1
                    continue
                applied, _reason = apply_instr_patch(
                    data, arch=arch, anchor=anchor,
                    offset_from_anchor=ofs, match_bytes_hex=mbx,
                    replace_bytes_hex=rbx, applied_marker_hex=amk,
                )
                if applied:
                    applied_n += 1
                else:
                    skipped_n += 1
            per_patch.append({"id": p.get("id", "?"), "applied": applied_n, "skipped": skipped_n})
            applied_total += applied_n
            skipped_total += skipped_n
            continue

        for sub in p.get("patches", []):
            search_regex = sub.get("search_regex")
            search       = sub.get("search")
            replace      = sub.get("replace", "")
            marker       = sub.get("applied_marker")

            # Idempotency: check marker in any string section
            if marker:
                marker_b = marker.encode("utf-8", "surrogateescape")
                already  = any(
                    data.find(marker_b, lo, hi) >= 0
                    for lo, hi in bounds
                )
                if already:
                    continue

            if search_regex:
                try:
                    pat = re.compile(
                        search_regex.encode("utf-8", "surrogateescape"), re.DOTALL
                    )
                except re.error:
                    skipped_n += 1
                    continue
                for lo, hi in bounds:
                    section_view = bytes(data[lo:hi])
                    for m in pat.finditer(section_view):
                        mb = m.group(0)
                        try:
                            rb = m.expand(replace.encode("utf-8", "surrogateescape"))
                        except Exception:
                            skipped_n += 1
                            continue
                        if len(rb) > len(mb):
                            skipped_n += 1
                            continue
                        if len(rb) < len(mb):
                            rb = rb + b" " * (len(mb) - len(rb))
                        abs_start = lo + m.start()
                        data[abs_start: abs_start + len(mb)] = rb
                        applied_n += 1
            elif search:
                s_b = search.encode("utf-8", "surrogateescape")
                r_b = replace.encode("utf-8", "surrogateescape")
                if len(r_b) > len(s_b):
                    skipped_n += 1
                    continue
                if len(r_b) < len(s_b):
                    r_b = r_b + b" " * (len(s_b) - len(r_b))
                for lo, hi in bounds:
                    pos = lo
                    while True:
                        j = data.find(s_b, pos, hi)
                        if j < 0:
                            break
                        data[j: j + len(s_b)] = r_b
                        applied_n += 1
                        pos = j + len(s_b)

        per_patch.append({"id": p.get("id", "?"), "applied": applied_n, "skipped": skipped_n})
        applied_total += applied_n
        skipped_total += skipped_n

    if len(data) != original_size:
        return {
            "ok": False,
            "err": f"size drift {len(data)} vs {original_size}",
            "applied": 0,
            "skipped": skipped_total,
            "per_patch": per_patch,
        }

    if applied_total == 0:
        return {"ok": True, "noop": True, "applied": 0, "skipped": skipped_total, "per_patch": per_patch}

    # Atomic swap: write tmp -> codesign -> verify -> rename
    tmp_bin = binary.parent / f".{binary.name}.ccptmp-{os.getpid()}"
    try:
        tmp_bin.write_bytes(bytes(data))
        tmp_bin.chmod(mode)

        # macOS Mach-O: must re-sign or hardened runtime will SIGKILL.
        # ELF / PE: no signing step required for ad-hoc patched dev binaries.
        if fmt == "macho":
            ok_sign, sign_msg = codesign(tmp_bin)
            if not ok_sign:
                tmp_bin.unlink(missing_ok=True)
                return {
                    "ok": False,
                    "err": f"codesign failed: {sign_msg}",
                    "applied": applied_total,
                    "skipped": skipped_total,
                    "per_patch": per_patch,
                }

        # Verify only when host can execute this format. Cross-format targets
        # (e.g. patching a Linux ELF on a macOS host via -t) skip exec verify.
        if _can_run_native(fmt, bytes(data[:0x40])):
            r = subprocess.run(
                [str(tmp_bin), "--version"],
                capture_output=True, text=True, timeout=20,
            )
            out = (r.stdout or "") + (r.stderr or "")
            if r.returncode != 0 or not out.strip():
                tmp_bin.unlink(missing_ok=True)
                return {
                    "ok": False,
                    "err": f"verify failed: {out[:120]!r} rc={r.returncode}",
                    "applied": applied_total,
                    "skipped": skipped_total,
                    "per_patch": per_patch,
                }

        binary.unlink()
        tmp_bin.rename(binary)
        binary.chmod(mode)
        # Re-sign the installed binary (Mach-O only)
        if fmt == "macho":
            codesign(binary)

    except Exception as e:
        tmp_bin.unlink(missing_ok=True)
        return {"ok": False, "err": f"write failed: {e}", "applied": 0, "skipped": skipped_total}

    return {"ok": True, "applied": applied_total, "skipped": skipped_total, "per_patch": per_patch, "fmt": fmt}


# Backward-compat alias — older code paths and tests still call this name.
patch_macho_inplace = patch_binary_inplace


# ── patch loading ─────────────────────────────────────────────────────────────

def load_patches() -> list[dict[str, Any]]:
    patches = []
    for f in sorted(PATCH_DIR.glob("*.json")):
        try:
            p = json.loads(f.read_text(encoding="utf-8"))
            if p.get("disabled"):
                continue
            patches.append(p)
        except json.JSONDecodeError as e:
            print(f"{R}{CROSS} {f.name}: invalid JSON — {e}{X}", file=sys.stderr)
    return patches


def backup(target: Path) -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dst   = BACKUP_DIR / f"codex.{stamp}.{sha256_short(target)}.bak"
    shutil.copy2(target, dst)
    # Keep last 10 backups
    for old in sorted(BACKUP_DIR.glob("codex.*.bak"))[:-10]:
        old.unlink(missing_ok=True)
    return dst


# ── config/toml patches ───────────────────────────────────────────────────────

def _insert_top_level_toml(existing_text: str, block: str) -> str:
    """
    Insert `block` of top-level key/value lines into a config.toml so the keys
    stay top-level. TOML scopes bare keys to the most recent [table] header, so
    appending at EOF would silently nest them under the last table. We insert
    the block immediately before the first [table]/[[array]] header instead, or
    append at EOF when the file has no tables.

    `block` is the full text to splice in (caller supplies the leading marker
    comment + newline). Returns the new file text.
    """
    lines = existing_text.splitlines()
    insert_at = None
    for i, line in enumerate(lines):
        if line.lstrip().startswith("["):
            insert_at = i
            break
    if insert_at is None:
        # No tables — safe to append at end.
        return existing_text.rstrip("\n") + "\n\n" + block.strip("\n") + "\n"
    head = "\n".join(lines[:insert_at]).rstrip("\n")
    tail = "\n".join(lines[insert_at:]).strip("\n")
    block = block.strip("\n")
    segments = [s for s in (head, block, tail) if s]
    return "\n\n".join(segments) + "\n"


def _apply_toml_defaults(p: dict, dry_run: bool = False) -> tuple[bool, str]:
    """
    config_toml patch type: write default keys into ~/.codex/config.toml.
    Only sets keys that are absent — never overwrites operator-set values.
    Uses simple line-based TOML writer (no external deps).
    """
    config_path = Path(p.get("config_path", "~/.codex/config.toml")).expanduser()
    defaults: dict[str, str] = p.get("defaults", {})
    if not defaults:
        return True, "no-op (no defaults defined)"

    config_path.parent.mkdir(parents=True, exist_ok=True)
    existing_text = ""
    if config_path.is_file():
        existing_text = config_path.read_text(encoding="utf-8")

    added = []
    for key, val in defaults.items():
        # Simple check: key = ... already present as a top-level entry
        pattern = re.compile(r"^\s*" + re.escape(key) + r"\s*=", re.MULTILINE)
        if pattern.search(existing_text):
            continue
        added.append(f'{key} = {val}')

    if not added:
        return True, "no-op (already applied)"
    if dry_run:
        return True, f"would add {len(added)} key(s): {', '.join(k.split('=')[0].strip() for k in added)}"

    block = "# ccp: bypass defaults\n" + "\n".join(added) + "\n"
    new_text = _insert_top_level_toml(existing_text, block)
    config_path.write_text(new_text, encoding="utf-8")
    return True, f"{len(added)} key(s) added"


# Windows wrapper: a .cmd shim (cmd.exe + PowerShell both execute .cmd, and
# .CMD is in PATHEXT by default, so typing `codex` runs it). It calls the real
# vendored codex.exe directly — the npm `codex` launcher is just `node codex.js`
# that execs this same binary, and ccp already runs it directly for --version.
# A bash wrapper at ~/.local/bin/codex (no extension) cannot run on Windows and
# only shadows/breaks the real launcher, so Windows gets this instead.
_WIN_WRAPPER_TEMPLATE = """@echo off
REM ccp-wrapper (Windows), installed by ccp. Prepends
REM --dangerously-bypass-approvals-and-sandbox to codex, EXCEPT for meta
REM subcommands and when the user already passed a bypass flag or --yolo
REM (codex's alias for the same flag), which would otherwise collide with
REM "cannot be used multiple times". Calls the vendored codex.exe directly.
setlocal
set "CODEX_REAL=__CODEX_REAL__"
set "FIRST=%~1"
if /i "%FIRST%"=="--help"     goto passthrough
if /i "%FIRST%"=="-h"         goto passthrough
if /i "%FIRST%"=="--version"  goto passthrough
if /i "%FIRST%"=="-V"         goto passthrough
if /i "%FIRST%"=="completion" goto passthrough
if /i "%FIRST%"=="login"      goto passthrough
if /i "%FIRST%"=="logout"     goto passthrough
:scan
if "%~1"=="" goto prepend
if /i "%~1"=="--yolo" goto passthrough
if /i "%~1"=="--dangerously-bypass-approvals-and-sandbox" goto passthrough
shift
goto scan
:prepend
"%CODEX_REAL%" --dangerously-bypass-approvals-and-sandbox %*
exit /b %ERRORLEVEL%
:passthrough
"%CODEX_REAL%" %*
exit /b %ERRORLEVEL%
"""

_WIN_WRAPPER_MARKER = "ccp-wrapper"


def _resolve_real_codex_invocation() -> str | None:
    """Absolute path the Windows wrapper should call. Prefers the vendored
    codex binary (what ccp already targets/patches); falls back to the npm
    launcher on PATH."""
    t = find_target()
    if t:
        return str(t)
    return shutil.which("codex.cmd") or shutil.which("codex")


def _install_windows_wrapper() -> tuple[bool, str, Path | None]:
    """Write ~/.local/bin/codex.cmd that prepends the bypass flag. CRLF line
    endings (batch). Returns (ok, message, dst)."""
    real = _resolve_real_codex_invocation()
    if not real:
        return False, "codex binary not found — run 'npm install -g @openai/codex'", None
    dst = Path.home() / ".local" / "bin" / "codex.cmd"
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        try:
            if _WIN_WRAPPER_MARKER in dst.read_text(encoding="utf-8", errors="replace"):
                return True, f"no-op (already installed at {dst})", dst
        except Exception:
            pass
    content = _WIN_WRAPPER_TEMPLATE.replace("__CODEX_REAL__", real)
    crlf = content.replace("\r\n", "\n").replace("\n", "\r\n")
    dst.unlink(missing_ok=True)
    dst.write_bytes(crlf.encode("utf-8"))
    return True, f"installed at {dst}", dst


def _apply_wrapper(p: dict, target: Path | None, dry_run: bool = False) -> tuple[bool, str]:
    """wrapper patch type: install a shell wrapper script."""
    # Windows: a .cmd shim, not the bash wrapper (which cannot run there).
    if sys.platform == "win32":
        if dry_run:
            return True, "would install Windows wrapper at ~/.local/bin/codex.cmd"
        ok, msg, _dst = _install_windows_wrapper()
        return ok, msg

    wrapper_path = Path(p.get("wrapper_path", "~/.local/bin/codex")).expanduser()
    content = p.get("content", "")
    MARKER = p.get("marker", "# ccp-wrapper")

    if not content:
        return False, "no content defined"

    if wrapper_path.exists() and not wrapper_path.is_symlink():
        try:
            if MARKER in wrapper_path.read_text(encoding="utf-8"):
                return True, "no-op (already applied)"
        except Exception:
            pass

    if dry_run:
        return True, f"would install wrapper at {wrapper_path}"

    wrapper_path.parent.mkdir(parents=True, exist_ok=True)
    wrapper_path.unlink(missing_ok=True)
    wrapper_path.write_text(content, encoding="utf-8")
    wrapper_path.chmod(0o755)
    return True, f"wrapper installed at {wrapper_path}"


# ── commands ──────────────────────────────────────────────────────────────────

_BINARY_PATCH_TYPES = ("macho_replace", "binary_replace", "elf_replace", "pe_replace", "instr_replace")


def _is_binary_patch(p: dict) -> bool:
    return p.get("type") in _BINARY_PATCH_TYPES


def _patch_applies_to_format(p: dict, fmt: str) -> bool:
    """
    Decide whether a binary patch is allowed against a binary of `fmt`.
    - `macho_replace` -> macho only (legacy, pre-multi-platform)
    - `elf_replace`   -> elf only
    - `pe_replace`    -> pe only
    - `binary_replace` -> any format unless the patch declares `formats: [...]`
    """
    t = p.get("type")
    if t == "macho_replace":
        return fmt == "macho"
    if t == "elf_replace":
        return fmt == "elf"
    if t == "pe_replace":
        return fmt == "pe"
    if t == "binary_replace":
        formats = p.get("formats")
        if formats:
            return fmt in formats
        return fmt in ("macho", "elf", "pe")
    if t == "instr_replace":
        # arch-gated: arm64 patches only apply to arm64 binaries; x86_64 to x86_64.
        # Format-agnostic since instr_replace operates on raw bytes via anchor + offset.
        formats = p.get("formats")
        if formats and fmt not in formats:
            return False
        # Cheap arch check: caller may have stamped fmt with a hint, but we don't
        # track arch here. Accept and let apply_instr_patch's byte-match guard skip
        # mismatches (its match_bytes_hex check catches the wrong arch automatically).
        return True
    return False


def _resolve_target(args) -> Path | None:
    """
    Resolve the target binary. Honors -t/--target if provided on the args ns,
    otherwise falls back to autodetection via find_target().
    """
    explicit = getattr(args, "target", None)
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not p.is_file():
            print(f"{R}explicit target not found: {p}{X}", file=sys.stderr)
            return None
        return p
    return find_target()


def cmd_patch(args) -> int:
    patches = load_patches()
    target  = _resolve_target(args)

    binary_patches = [p for p in patches if _is_binary_patch(p)]
    meta_patches   = [p for p in patches if not _is_binary_patch(p)]

    print(f"{B}ccp patch — {len(patches)} patches{X}")
    if target:
        print(f"  target : {target}")
        print(f"  sha    : {sha256_short(target)}")
        print(f"  size   : {target.stat().st_size // 1024 // 1024} MB")
        if not args.dry_run:
            bkp = backup(target)
            print(f"  backup : {bkp}")
    else:
        print(f"  {Y}target not found — binary patches will be skipped{X}")

    ok = fail = skip = 0

    # ── binary patches ─────────────────────────────────────────────────────
    if not target:
        for p in binary_patches:
            print(f"  {Y}skip{X} {p.get('id','?'):40s}  target not found")
            skip += 1
    else:
        data_full = bytearray(target.read_bytes())
        fmt = _binary_format(data_full)
        applicable  = [p for p in binary_patches if _patch_applies_to_format(p, fmt)]
        skipped_fmt = [p for p in binary_patches if not _patch_applies_to_format(p, fmt)]
        for p in skipped_fmt:
            print(f"  {Y}skip{X} {p.get('id','?'):40s}  type={p.get('type')} not applicable to fmt={fmt}")
            skip += 1
        if args.dry_run:
            bounds = _binary_string_bounds(data_full)
            for p in applicable:
                applied_n = 0

                # instr_replace dry-run: check anchor + marker + match bytes.
                # Track each sub's outcome separately so "already applied" is not
                # conflated with "anchor/bytes not found" (the latter means the
                # patch cannot apply to this binary, e.g. wrong arch).
                if p.get("type") == "instr_replace":
                    raw = bytes(data_full)
                    already_n = 0   # marker matched — patch is live
                    nomatch_n = 0   # anchor missing or bytes differ — cannot apply
                    for sub in p.get("patches", []):
                        anchor = sub.get("anchor", "").encode("utf-8", "surrogateescape")
                        ofs    = int(sub.get("offset_from_anchor", 0))
                        mbx    = sub.get("match_bytes_hex", "")
                        amk    = sub.get("applied_marker_hex")
                        if not (anchor and mbx):
                            nomatch_n += 1
                            continue
                        ap = raw.find(anchor)
                        if ap < 0:
                            nomatch_n += 1
                            continue
                        target_off = ap + ofs
                        if target_off < 0 or target_off + len(mbx) // 2 > len(raw):
                            nomatch_n += 1
                            continue
                        actual = raw[target_off: target_off + len(mbx) // 2]
                        try:
                            expected = bytes.fromhex(mbx)
                            marker_bytes = bytes.fromhex(amk) if amk else None
                        except ValueError:
                            nomatch_n += 1
                            continue
                        if marker_bytes and actual == marker_bytes:
                            already_n += 1
                            continue  # already applied
                        if actual == expected:
                            applied_n += 1
                        else:
                            nomatch_n += 1
                    if applied_n:
                        msg = f"would apply {applied_n} instr-replace(s)"
                    elif already_n and not nomatch_n:
                        msg = "no-op (already applied)"
                    elif already_n:
                        msg = f"{already_n} already applied, {nomatch_n} not matched (wrong arch/version?)"
                    else:
                        msg = "skip (anchor/bytes not found — not applicable to this binary)"
                    print(f"  {G}ok{X}    {p.get('id','?'):40s}  {msg}")
                    ok += 1
                    continue

                for sub in p.get("patches", []):
                    marker = sub.get("applied_marker")
                    if marker:
                        marker_b = marker.encode("utf-8", "surrogateescape")
                        if any(data_full.find(marker_b, lo, hi) >= 0 for lo, hi in bounds):
                            continue
                    sr = sub.get("search_regex") or sub.get("search") or ""
                    if not sr:
                        continue
                    try:
                        if sub.get("search_regex"):
                            pat = re.compile(sr.encode("utf-8", "surrogateescape"), re.DOTALL)
                            for lo, hi in bounds:
                                applied_n += sum(1 for _ in pat.finditer(bytes(data_full[lo:hi])))
                        else:
                            s_b = sr.encode("utf-8", "surrogateescape")
                            for lo, hi in bounds:
                                applied_n += bytes(data_full[lo:hi]).count(s_b)
                    except re.error:
                        pass
                msg = "no-op (already applied)" if applied_n == 0 else f"would apply {applied_n} in-place"
                print(f"  {G}ok{X}    {p.get('id','?'):40s}  {msg}")
                ok += 1
            print(f"  {Y}dry-run: binary not modified{X}")
        elif not applicable:
            pass  # nothing to do for this format
        else:
            result = patch_binary_inplace(target, applicable)
            if not result["ok"]:
                print(f"  {R}fail{X}  [{fmt}-inplace]  {result.get('err','unknown')}")
                fail += len(applicable)
            else:
                for pr in result.get("per_patch", []):
                    n   = pr["applied"]
                    msg = "no-op (already applied)" if n == 0 else f"{n} in-place replacement(s)"
                    print(f"  {G}ok{X}    {pr['id']:40s}  {msg}")
                    ok += 1
                if not result.get("noop") and _can_run_native(fmt, bytes(data_full[:0x40])):
                    print(f"  {G}verified in-place{X}  (ran binary --version, output confirmed)")
                elif not result.get("noop"):
                    print(f"  {Y}wrote in-place{X}  (skipped --version verify: foreign fmt/arch)")

    # ── meta patches ───────────────────────────────────────────────────────
    for p in meta_patches:
        t = p.get("type")
        if t == "config_toml":
            success, msg = _apply_toml_defaults(p, dry_run=args.dry_run)
        elif t == "wrapper":
            success, msg = _apply_wrapper(p, target, dry_run=args.dry_run)
        else:
            print(f"  {Y}skip{X} {p.get('id','?'):40s}  type={t} (unknown)")
            skip += 1
            continue
        mark = f"{G}ok{X}" if success else f"{R}fail{X}"
        print(f"  {mark}   {p.get('id','?'):40s}  {msg}")
        ok   += success
        fail += not success

    print(f"\n{B}{ok} ok {DOT} {fail} failed {DOT} {skip} skipped{X}")

    if target and not args.dry_run and not fail:
        try:
            _updater.save_state(last_codex_sha=sha256_short(target))
        except Exception:
            pass

    return 1 if fail else 0


def cmd_verify(args) -> int:
    target = _resolve_target(args)
    if not target:
        print(f"{R}codex binary not found{X}")
        return 2

    data   = bytearray(target.read_bytes())
    fmt    = _binary_format(data)
    bounds = _binary_string_bounds(data)

    missing = 0
    for p in load_patches():
        if not _is_binary_patch(p):
            continue
        if not _patch_applies_to_format(p, fmt):
            continue
        for sub in p.get("patches", []):
            if not sub.get("required", True):
                continue
            marker = sub.get("applied_marker")
            if marker:
                marker_b = marker.encode("utf-8", "surrogateescape")
                found    = any(data.find(marker_b, lo, hi) >= 0 for lo, hi in bounds)
                if not found:
                    print(f"{R}{CROSS}{X} {p.get('id','?')}")
                    missing += 1
                    break

    if missing:
        print(f"\n{R}{missing} patches missing{X}")
        return 1
    print(f"{G}{CHECK} all patches verified{X}")
    return 0


def cmd_rollback(args) -> int:
    target = find_target()
    if not target:
        print(f"{R}codex binary not found{X}")
        return 2
    baks = sorted(BACKUP_DIR.glob("codex.*.bak"))
    if not baks:
        print(f"{R}no backups in {BACKUP_DIR}{X}")
        return 1
    latest = baks[-1]
    mode   = target.stat().st_mode & 0o7777
    target.unlink()
    shutil.copy2(latest, target)
    target.chmod(mode)
    if sys.platform == "darwin":
        ok_s, s_msg = codesign(target)
        if not ok_s:
            print(f"  {Y}{WARN_ICON} codesign after rollback failed: {s_msg}{X}")
    print(f"{G}{CHECK} restored{X} {target} <- {latest.name}")
    return 0


def cmd_status(args) -> int:
    target  = _resolve_target(args)
    patches = load_patches()
    print(f"{B}ccp status{X}")
    print(f"  patches : {len(patches)}")
    if target:
        try:
            with target.open("rb") as _fh:
                _head = _fh.read(0x1000)
            fmt = _binary_format(_head)
        except Exception:
            fmt = "unknown"
        print(f"  target  : {target}")
        print(f"  format  : {fmt}")
        print(f"  sha256  : {sha256_short(target)}")
        print(f"  size    : {target.stat().st_size // 1024 // 1024} MB")
    else:
        print(f"  target  : {R}NOT FOUND{X}")
        print(f"  hint    : install codex via 'npm install -g @openai/codex'")
    baks = sorted(BACKUP_DIR.glob("codex.*.bak"))
    print(f"  backups : {len(baks)}  ({BACKUP_DIR})")
    state = _updater.load_state()
    last_sha = state.get("last_codex_sha")
    if last_sha and target:
        cur = sha256_short(target)
        drift = cur != last_sha
        print(f"  drift   : {'YES — binary changed since last patch' if drift else 'no'}")
    return 0


def cmd_list(args) -> int:
    patches = load_patches()
    if not patches:
        print(f"  {Y}no patches in {PATCH_DIR}{X}")
        return 0
    for p in patches:
        tid = p.get("type", "?")
        req = "" if p.get("required", True) else f" [{Y}optional{X}]"
        print(f"  {p.get('id','?'):45s}  [{tid}]{req}  {p.get('description','')}")
    return 0


def cmd_scan(args) -> int:
    """Signature-based offset discovery. Prints anchor offsets + regex hit status."""
    target = _resolve_target(args)
    if not target:
        print(f"{R}codex binary not found{X}")
        return 2

    try:
        text = _scanner.load_text_from_target(target)
    except Exception as e:
        print(f"{R}extract failed: {e}{X}")
        return 2

    try:
        with target.open("rb") as _fh:
            fmt = _binary_format(_fh.read(0x1000))
    except Exception:
        fmt = "unknown"

    patches = _scanner.load_patches_from_dir(PATCH_DIR)
    # Filter to patches that apply to this binary's format.
    patches = [p for p in patches if _patch_applies_to_format(p, fmt)]
    sc      = _scanner.SigScanner(text)
    rows    = sc.scan_patches(patches)

    print(f"{B}ccp scan — {len(rows)} binary patches (fmt={fmt}){X}")
    print(f"  target : {target}")
    print(f"  text   : {len(text)} bytes extracted")
    print(f"  sha    : {sha256_short(target)}")
    print()
    print(_scanner.format_scan_report(rows, verbose=args.verbose))

    return 1 if any(r["status"] == "drift" for r in rows) else 0


def cmd_doctor(args) -> int:
    """Full health report: sha, patches applied, sig drift, backup count, upstream, codex version."""
    from . import __version__ as _ver

    target  = _resolve_target(args)
    patches = load_patches()
    binary_patches = [p for p in patches if _is_binary_patch(p)]

    print(f"{B}ccp doctor{X}")
    print(f"  ccp ver    : {_ver}")

    # ── target ────────────────────────────────────────────────────────────────
    fmt = "unknown"
    if not target:
        print(f"  target     : {R}NOT FOUND — install via 'npm install -g @openai/codex'{X}")
    else:
        try:
            with target.open("rb") as _fh:
                fmt = _binary_format(_fh.read(0x1000))
        except Exception:
            fmt = "unknown"
        print(f"  target     : {target}")
        print(f"  format     : {fmt}")
        print(f"  sha256     : {sha256_short(target)}")
        sz_mb = target.stat().st_size / 1024 / 1024
        print(f"  size       : {sz_mb:.1f} MB")

    # ── patches count ─────────────────────────────────────────────────────────
    print(f"  patches    : {len(patches)} total  ({len(binary_patches)} binary, {len(patches) - len(binary_patches)} meta)")

    # ── per-patch applied status ──────────────────────────────────────────────
    if target:
        data   = bytearray(target.read_bytes())
        bounds = _binary_string_bounds(data)
        for p in binary_patches:
            if not _patch_applies_to_format(p, fmt):
                print(f"  {DOT} skip       : {p.get('id','?')}  (not applicable to fmt={fmt})")
                continue
            applied = False
            not_here = False
            if p.get("type") == "instr_replace":
                # instr patches record application as the replacement bytes at
                # anchor+offset (applied_marker_hex). If neither the marker nor
                # the original match bytes are present, the patch does not target
                # this binary (e.g. an arm64 patch against a PE) — report skip,
                # not "not applied", so doctor agrees with the dry-run classifier.
                hit = miss = 0
                for sub in p.get("patches", []):
                    anchor = sub.get("anchor", "").encode("utf-8", "surrogateescape")
                    amk = sub.get("applied_marker_hex")
                    mbx = sub.get("match_bytes_hex")
                    ap = data.find(anchor) if anchor else -1
                    if ap < 0 or not (amk or mbx):
                        continue
                    off = ap + int(sub.get("offset_from_anchor", 0))
                    n = len(amk or mbx) // 2
                    if off < 0 or off + n > len(data):
                        continue
                    cur = bytes(data[off:off + n])
                    if amk and cur == bytes.fromhex(amk):
                        hit += 1
                    elif mbx and cur == bytes.fromhex(mbx):
                        miss += 1
                if hit and not miss:
                    applied = True
                elif hit == 0 and miss == 0:
                    not_here = True
            else:
                for sub in p.get("patches", []):
                    marker = sub.get("applied_marker")
                    if marker:
                        marker_b = marker.encode("utf-8", "surrogateescape")
                        if any(data.find(marker_b, lo, hi) >= 0 for lo, hi in bounds):
                            applied = True
                            break
            if not_here:
                print(f"  {DOT} skip       : {p.get('id','?')}  (anchors not in this binary)")
                continue
            icon = f"{G}{CHECK}{X}" if applied else f"{Y}{WARN_ICON}{X}"
            print(f"  {icon} patch      : {p.get('id','?')}  ({'applied' if applied else 'not applied'})")
        for p in [x for x in patches if not _is_binary_patch(x)]:
            print(f"  {DOT} meta       : {p.get('id','?')}  (type={p.get('type','?')})")

    # ── backups ───────────────────────────────────────────────────────────────
    baks = sorted(BACKUP_DIR.glob("codex.*.bak"))
    if baks:
        print(f"  {G}backups    : {len(baks)}{X}")
        for bak in baks[-3:]:
            print(f"               {bak}")
        if len(baks) > 3:
            print(f"               … {len(baks) - 3} older")
    else:
        print(f"  backups    : 0  (run 'ccp patch' to create first backup)")

    # ── sig drift ─────────────────────────────────────────────────────────────
    if target:
        try:
            text = _scanner.load_text_from_target(target)
            # Only score drift for patches that target this binary's format —
            # a macOS-only seatbelt patch is not "drift" on a Windows PE.
            _drift_patches = [
                p for p in _scanner.load_patches_from_dir(PATCH_DIR)
                if _patch_applies_to_format(p, fmt)
            ]
            rows = _scanner.SigScanner(text).scan_patches(_drift_patches)
            drift   = [r["id"] for r in rows if r["status"] == "drift"]
            total_a = len([r for r in rows if r.get("anchors_found", 0) > 0])
            total_d = len([r for r in rows if r.get("anchors_declared", 0) > 0])
            if drift:
                print(f"  {R}sig drift  : {len(drift)} {DOT} {', '.join(drift[:3])}{'...' if len(drift) > 3 else ''}{X}")
            else:
                print(f"  {G}sig drift  : 0 (all anchors locatable){X}")
            print(f"  anchor cov : {total_a}/{total_d} patches have anchors resolved")
        except Exception as e:
            print(f"  {R}sig scan   : failed — {e}{X}")

    # ── Codex CLI version ─────────────────────────────────────────────────────
    try:
        # `codex` is codex.cmd on Windows; bare "codex" via subprocess (no shell)
        # does not resolve there. shutil.which() finds the PATHEXT match.
        _codex = shutil.which("codex") or "codex"
        r = subprocess.run([_codex, "--version"], capture_output=True, text=True, timeout=8)
        codex_ver = (r.stdout or r.stderr or "").strip().splitlines()[0] if r.returncode == 0 else None
        if codex_ver:
            print(f"  {G}codex ver  : {codex_ver}{X}")
        else:
            print(f"  {Y}codex ver  : not found (codex not on PATH){X}")
    except Exception:
        print(f"  {Y}codex ver  : not found (codex not on PATH){X}")

    # ── wrapper / config / AGENTS.md installed ────────────────────────────────
    codex_dir  = Path.home() / ".codex"
    # The wrapper is codex.cmd on Windows, codex (no extension) on POSIX.
    _wrapper_candidates = [
        Path.home() / ".local" / "bin" / "codex.cmd",
        Path.home() / ".local" / "bin" / "codex",
    ]
    w_ok = any(
        w.exists() and "ccp-wrapper" in w.read_text(encoding="utf-8", errors="replace")
        for w in _wrapper_candidates
    )
    c_ok = (codex_dir / "config.toml").exists()
    a_ok = (codex_dir / "AGENTS.md").exists()
    print(f"  wrapper    : {G+'installed'+X if w_ok else Y+'not installed — run ccp install-wrapper'+X}")
    print(f"  config     : {G+'installed'+X if c_ok else Y+'not installed — run ccp install-config'+X}")
    print(f"  AGENTS.md  : {G+'installed'+X if a_ok else Y+'not installed — run ccp install-rules'+X}")

    # ── upstream ──────────────────────────────────────────────────────────────
    try:
        info = _updater.upstream_status(PATCH_DIR)
        if info["drift"]:
            print(f"  {Y}upstream   : behind — run 'ccp self-update'{X}")
        elif info["remote_commit"]:
            print(f"  {G}upstream   : current ({info['remote_commit'][:7]}){X}")
        else:
            print(f"  upstream   : unreachable")
    except Exception:
        print(f"  upstream   : error")

    return 0 if target else 2


def cmd_watch(args) -> int:
    """Daemon: poll binary mtime+sha; on change autoheal."""
    import time
    target = find_target()
    if not target:
        print(f"{R}codex binary not found{X}")
        return 2
    print(f"{B}ccp watch — polling every {args.interval}s{X}")
    print(f"  target: {target}")
    last_sha   = sha256_short(target)
    last_mtime = target.stat().st_mtime
    print(f"  sha   : {last_sha}")
    try:
        while True:
            time.sleep(args.interval)
            try:
                target = find_target()
                if not target:
                    print(f"{Y}  target vanished — waiting{X}")
                    continue
                m = target.stat().st_mtime
                if m == last_mtime:
                    continue
                cur_sha = sha256_short(target)
                if cur_sha == last_sha:
                    last_mtime = m
                    continue
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"\n{Y}[{ts}] codex changed: {last_sha} -> {cur_sha}{X}")
                backup(target)
                class _A:
                    force = False; quiet = False
                rc = cmd_autoheal(_A())
                print(f"  autoheal rc={rc}")
                last_sha   = sha256_short(target)
                last_mtime = target.stat().st_mtime
            except Exception as e:
                print(f"{R}  watch loop error: {e}{X}")
    except KeyboardInterrupt:
        print(f"\n{B}watch stopped{X}")
        return 0


def cmd_autoheal(args) -> int:
    return _updater.autoheal(
        find_target=find_target,
        sha256_short=sha256_short,
        load_patches=load_patches,
        cmd_verify_fn=cmd_verify,
        cmd_patch_fn=cmd_patch,
        cmd_rollback_fn=cmd_rollback,
        patch_dir=PATCH_DIR,
        force=getattr(args, "force", False),
        quiet=getattr(args, "quiet", False),
    )


def cmd_self_update(args) -> int:
    """Pull latest patches/*.json from GitHub and re-apply."""
    print(f"{B}ccp self-update{X}  <- {_updater.REPO}@{_updater.BRANCH}")
    remote = _updater.remote_head_sha("patches")
    if not remote:
        print(f"{R}could not reach GitHub API{X}")
        return 2
    state = _updater.load_state()
    local = state.get("patches_commit")
    print(f"  local  : {local or '(unknown)'}")
    print(f"  remote : {remote}")
    if local == remote and not getattr(args, "force", False):
        print(f"{G}{CHECK} already up to date{X}")
        return 0
    if getattr(args, "dry_run", False):
        print(f"{Y}dry-run: would sync{X}")
        return 0
    changed, sha_or_err = _updater.sync_patches(PATCH_DIR, remote)
    if changed < 0:
        print(f"{R}{CROSS} sync failed — {sha_or_err}{X}")
        return 2
    print(f"{G}{CHECK} synced{X}  {changed} file(s) updated @ {sha_or_err[:7]}")
    if changed and not getattr(args, "no_reapply", False):
        print(f"\n{B}re-applying patches{X}")
        class _P:
            dry_run = False
        return cmd_patch(_P())
    return 0


def cmd_check_updates(args) -> int:
    info = _updater.upstream_status(PATCH_DIR)
    print(f"{B}ccp check-updates{X}")
    print(f"  local commit  : {info['local_commit'] or '(unknown)'}")
    print(f"  remote commit : {info['remote_commit'] or '(unreachable)'}")
    print(f"  local files   : {info['local_files']}")
    if info["drift"]:
        print(f"{Y}{WARN_ICON} update available — run 'ccp self-update'{X}")
        return 1
    if not info["local_commit"] and info["remote_commit"]:
        print(f"{Y}{WARN_ICON} no sync state — run 'ccp self-update' to pin current{X}")
        return 1
    if info["remote_commit"]:
        print(f"{G}{CHECK} up to date{X}")
    return 0


# ── install-rules ─────────────────────────────────────────────────────────────

_CCP_MD_START = "<!-- ccp:authorization:start -->"
_CCP_MD_END   = "<!-- ccp:authorization:end -->"


def _deep_merge(dst: dict, src: dict) -> dict:
    for k, v in src.items():
        if k in dst and isinstance(dst[k], dict) and isinstance(v, dict):
            _deep_merge(dst[k], v)
        elif k in dst and isinstance(dst[k], list) and isinstance(v, list):
            merged = list(dst[k])
            for item in v:
                if item not in merged:
                    merged.append(item)
            dst[k] = merged
        else:
            dst[k] = v
    return dst


_CCP_AGENTS_START = "<!-- ccp:authorization:start -->"
_CCP_AGENTS_END   = "<!-- ccp:authorization:end -->"


def cmd_install_rules(args) -> int:
    """Deploy contrib/rules/ into ~/.codex/: AUTHORIZATION.md, AGENTS.md, config.toml."""
    src_dir = ROOT / "contrib" / "rules"
    if not src_dir.exists():
        print(f"{R}contrib/rules/ missing{X}")
        return 2

    force = getattr(args, "force", False)
    codex_dir = Path.home() / ".codex"
    codex_dir.mkdir(parents=True, exist_ok=True)

    installed = []
    skipped   = []

    # ── AUTHORIZATION.md ──────────────────────────────────────────────────────
    auth_src_path = src_dir / "AUTHORIZATION.md"
    if auth_src_path.exists():
        auth_dst = codex_dir / "AUTHORIZATION.md"
        auth_dst.write_text(auth_src_path.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"  {G}{CHECK}{X} AUTHORIZATION.md {ARROW} {auth_dst}")
        installed.append("AUTHORIZATION.md")

    # ── AGENTS.md (instruction-prefix, read by Codex CLI at session start) ────
    agents_src_path = src_dir / "AGENTS.md"
    if agents_src_path.exists():
        agents_dst = codex_dir / "AGENTS.md"
        agents_src = agents_src_path.read_text(encoding="utf-8")
        block = f"{_CCP_AGENTS_START}\n{agents_src.rstrip()}\n{_CCP_AGENTS_END}\n"
        if agents_dst.exists():
            existing = agents_dst.read_text(encoding="utf-8")
            if _CCP_AGENTS_START in existing and not force:
                # already injected — refresh the block
                existing = re.sub(
                    f"{re.escape(_CCP_AGENTS_START)}.*?{re.escape(_CCP_AGENTS_END)}\n?",
                    "", existing, flags=re.DOTALL,
                )
                merged = block + "\n---\n\n" + existing.lstrip()
            elif force or _CCP_AGENTS_START not in existing:
                merged = block + "\n---\n\n" + existing.lstrip()
            else:
                merged = block
        else:
            merged = block
        agents_dst.write_text(merged, encoding="utf-8")
        print(f"  {G}{CHECK}{X} AGENTS.md {ARROW} {agents_dst}")
        installed.append("AGENTS.md")

    # ── config.toml — create with bypass defaults if absent (or --force) ──────
    config_path = codex_dir / "config.toml"
    config_src  = src_dir / "codex-config.toml"
    if config_path.exists() and not force:
        print(f"  {Y}{WARN_ICON}{X}  config.toml already exists — skipping (use --force to overwrite)")
        skipped.append("config.toml")
    elif config_src.exists():
        # delegate to install-config logic
        class _ICA:
            pass
        _saved = config_path
        rc = cmd_install_config(_ICA())
        if rc == 0:
            installed.append("config.toml")
    else:
        skipped.append("config.toml (codex-config.toml template missing)")

    # ── summary ───────────────────────────────────────────────────────────────
    print()
    if installed:
        print(f"{G}{CHECK} installed:{X} {', '.join(installed)}")
    if skipped:
        print(f"{Y}{WARN_ICON}  skipped:{X}  {', '.join(skipped)}")
    print(f"  revert: remove {codex_dir}/AUTHORIZATION.md and {codex_dir}/AGENTS.md manually")
    return 0


def cmd_install_wrapper(args) -> int:
    """Install the codex wrapper to ~/.local/bin/ (codex.cmd on Windows)."""
    # Windows: install a .cmd shim that calls the real codex.exe with the
    # bypass flag. The bash wrapper cannot execute on Windows.
    if sys.platform == "win32":
        ok, msg, dst = _install_windows_wrapper()
        icon = f"{G}{CHECK}{X}" if ok else f"{R}{CROSS}{X}"
        print(f"  {icon} {msg}")
        if not ok:
            return 2
        print(f"\n{G}{CHECK} wrapper installed{X}")
        print(r"  Ensure %USERPROFILE%\.local\bin precedes %APPDATA%\npm in PATH")
        return 0

    src_dir = ROOT / "contrib" / "wrappers"
    wrapper_src = src_dir / "codex"
    if not wrapper_src.exists():
        print(f"{R}contrib/wrappers/codex missing{X}")
        return 2

    dst = Path.home() / ".local" / "bin" / "codex"
    dst.parent.mkdir(parents=True, exist_ok=True)

    content = wrapper_src.read_text(encoding="utf-8")
    MARKER = "# ccp-wrapper"
    if dst.exists() and not dst.is_symlink():
        try:
            if MARKER in dst.read_text(encoding="utf-8"):
                print(f"  {G}no-op{X}  wrapper already installed at {dst}")
                return 0
        except Exception:
            pass
    dst.unlink(missing_ok=True)
    dst.write_text(content, encoding="utf-8")
    dst.chmod(0o755)
    print(f"  {G}{CHECK}{X} wrapper {ARROW} {dst}")
    print(f"\n{G}{CHECK} wrapper installed{X}")
    print(f"  Ensure ~/.local/bin is first in PATH")
    return 0


def cmd_install_config(args) -> int:
    """Merge contrib/rules/codex-config.toml defaults into ~/.codex/config.toml."""
    src = ROOT / "contrib" / "rules" / "codex-config.toml"
    if not src.exists():
        print(f"{R}contrib/rules/codex-config.toml missing{X}")
        return 2

    config_path = Path.home() / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    existing_text = ""
    if config_path.is_file():
        existing_text = config_path.read_text(encoding="utf-8")

    template = src.read_text(encoding="utf-8")
    added: list[str] = []
    MARKER = "# ccp: bypass defaults"

    if MARKER in existing_text:
        print(f"  {G}no-op{X}  ccp defaults already in config.toml")
        return 0

    # Parse key=value lines from template, skip section headers and comments
    for line in template.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("["):
            continue
        if "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        pattern = re.compile(r"^\s*" + re.escape(key) + r"\s*=", re.MULTILINE)
        if pattern.search(existing_text):
            continue  # operator already set this
        added.append(line)

    if not added:
        print(f"  {G}no-op{X}  all keys already present")
        return 0

    block = f"{MARKER}\n" + "\n".join(added) + "\n"
    new_text = _insert_top_level_toml(existing_text, block)
    config_path.write_text(new_text, encoding="utf-8")
    print(f"  {G}{CHECK}{X} {len(added)} key(s) added to {config_path}")
    print(f"\n{G}{CHECK} config installed{X}")
    return 0


def cmd_install_frida(args) -> int:
    """Deploy the Frida runtime bypass agent (layer 4)."""
    from . import runtime as rt

    print(f"{B}ccp install-frida{X}")
    if getattr(args, "uninstall", False):
        result = rt.uninstall_frida(verbose=False)
        if result["agent_removed"]:
            print(f"  {G}{CHECK}{X} agent removed")
        if result["wrapper_removed"]:
            print(f"  {G}{CHECK}{X} wrapper removed")
        if not (result["agent_removed"] or result["wrapper_removed"]):
            print(f"  {Y}{WARN_ICON}{X} nothing installed at default paths")
        return 0

    result = rt.install_frida(force=getattr(args, "force", False), verbose=False)
    if result["frida"]:
        prefix = G if result["frida"].startswith("frida ") else Y
        print(f"  {prefix}·{X} {result['frida']}")
    if result["agent_installed"]:
        print(f"  {G}{CHECK}{X} agent  → {result['agent_dst']}")
    elif result["agent_skipped"]:
        print(f"  {Y}skip{X}    agent (exists; --force to overwrite): {result['agent_dst']}")
    if result["wrapper_installed"]:
        print(f"  {G}{CHECK}{X} wrapper → {result['wrapper_dst']}")
    elif result["wrapper_skipped"]:
        print(f"  {Y}skip{X}    wrapper (exists; --force to overwrite): {result['wrapper_dst']}")
    for err in result["errors"]:
        print(f"  {R}!!{X} {err}")
    if result["errors"]:
        return 1
    print(f"\n{G}{CHECK} frida runtime installed{X}")
    print(f"  run: codex-frida exec '<your prompt>'")
    return 0


def cmd_scan_gates(args) -> int:
    """r2-driven anchor → gate scan. Lists candidate functions per anchor."""
    from . import deep_scan as ds

    if not ds.have_r2():
        print(f"{R}error{X} r2 not on PATH (brew install radare2)", file=sys.stderr)
        return 127

    target = getattr(args, "target", None)
    if not target:
        target = find_target()
        if not target:
            print(f"{R}error{X} no codex binary found; pass -t <path>", file=sys.stderr)
            return 1
    target = Path(target)
    if not target.is_file():
        print(f"{R}error{X} target not a file: {target}", file=sys.stderr)
        return 1

    arch = getattr(args, "arch", "arm64")
    anchors = getattr(args, "anchor", None) or [
        "approval is not supported",
        "is disallowed by requirements",
        "blocked by method policy",
        "(deny default)",
        "ApprovalDecision::Denied",
        "command execution approval is not supported in exec mode",
    ]

    print(f"{B}ccp scan-gates{X}")
    print(f"  target : {target}")
    print(f"  arch   : {arch}")
    print(f"  anchors: {len(anchors)}")
    print()

    found_any = False
    for anchor in anchors:
        try:
            cands = ds.find_gate_candidates(target, anchor, arch=arch)
        except Exception as exc:
            print(f"  {R}!!{X} {anchor!r}: {exc}", file=sys.stderr)
            continue
        if not cands:
            print(f"  {Y}·{X} {anchor!r}  — no candidates")
            continue
        found_any = True
        print(ds.render_candidates(cands))

    if not found_any:
        print(f"\n{Y}{WARN_ICON}{X} no gate candidates found across all anchors")
        return 1
    return 0


# ── entry ─────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="ccp",
        description="Codex CLI Patcher — Rust Mach-O patches + wrapper + config for OpenAI Codex CLI",
    )
    sub = ap.add_subparsers(dest="cmd", metavar="command")

    def _add_target(p):
        p.add_argument(
            "-t", "--target",
            help="Explicit binary path (skip auto-detect). Useful for inspecting "
                 "vendor binaries for other platforms.",
        )

    p_patch = sub.add_parser("patch", help="Apply all patches to the Codex binary + config")
    p_patch.add_argument("--dry-run", "-n", action="store_true")
    _add_target(p_patch)

    p_verify = sub.add_parser("verify",   help="Check that binary patches are applied")
    _add_target(p_verify)
    sub.add_parser("rollback", help="Restore binary from most recent backup")
    p_status = sub.add_parser("status",   help="Show install state and binary location")
    _add_target(p_status)
    sub.add_parser("list",     help="List all patches in catalog")
    p_doctor = sub.add_parser("doctor",   help="Full health report: target, patches, sig drift, upstream")
    _add_target(p_doctor)

    p_sc = sub.add_parser("scan", help="Signature-based anchor discovery in binary string sections")
    p_sc.add_argument("--verbose", "-v", action="store_true")
    _add_target(p_sc)

    p_su = sub.add_parser("self-update",
        help="Pull latest patches/*.json from GitHub and re-apply")
    p_su.add_argument("--dry-run", "-n", action="store_true")
    p_su.add_argument("--force", "-f", action="store_true")
    p_su.add_argument("--no-reapply", action="store_true")

    p_ah = sub.add_parser("autoheal",
        help="Detect binary drift; self-update + re-patch if broken")
    p_ah.add_argument("--force", "-f", action="store_true")
    p_ah.add_argument("--quiet", "-q", action="store_true")

    sub.add_parser("check-updates", help="Show if remote patches differ from local")

    p_w = sub.add_parser("watch", help="Daemon: poll binary, autoheal on update")
    p_w.add_argument("--interval", "-i", type=int, default=10,
        help="Poll interval in seconds (default 10)")

    p_ir = sub.add_parser("install-rules",
        help="Deploy operator-authorization rules to ~/.codex/ (AUTHORIZATION.md, AGENTS.md, config.toml)")
    p_ir.add_argument("--force", "-f", action="store_true",
        help="Overwrite existing config.toml and refresh AGENTS.md block")
    sub.add_parser("install-wrapper",
        help="Install bypass wrapper to ~/.local/bin/codex")
    sub.add_parser("install-config",
        help="Merge bypass defaults into ~/.codex/config.toml")
    p_if = sub.add_parser("install-frida",
        help="Install Frida runtime bypass agent (layer 4)")
    p_if.add_argument("--force", "-f", action="store_true",
        help="Overwrite existing agent and wrapper")
    p_if.add_argument("--uninstall", action="store_true",
        help="Remove the installed agent and wrapper")
    p_sg = sub.add_parser("scan-gates",
        help="r2-driven anchor → gate-instruction discovery (development tool)")
    p_sg.add_argument("-t", "--target", default=None,
        help="Path to a codex binary (defaults to system codex)")
    p_sg.add_argument("--anchor", action="append", default=None,
        help="String anchor to trace; repeat for multiple. Defaults to a curated set.")
    p_sg.add_argument("--arch", default="arm64", choices=("arm64", "x86_64"),
        help="Target arch for gate-mnemonic filtering (default arm64)")

    args = ap.parse_args()
    if args.cmd is None:
        ap.print_help()
        return 0

    dispatch = {
        "patch":           cmd_patch,
        "verify":          cmd_verify,
        "rollback":        cmd_rollback,
        "status":          cmd_status,
        "list":            cmd_list,
        "doctor":          cmd_doctor,
        "scan":            cmd_scan,
        "self-update":     cmd_self_update,
        "autoheal":        cmd_autoheal,
        "check-updates":   cmd_check_updates,
        "watch":           cmd_watch,
        "install-rules":   cmd_install_rules,
        "install-wrapper": cmd_install_wrapper,
        "install-config":  cmd_install_config,
        "install-frida":   cmd_install_frida,
        "scan-gates":      cmd_scan_gates,
    }
    fn = dispatch.get(args.cmd)
    if fn is None:
        print(f"{R}unknown command: {args.cmd}{X}", file=sys.stderr)
        return 1
    return fn(args)


if __name__ == "__main__":
    sys.exit(main())

import argparse
import ctypes
import json
import msvcrt
import struct
import sys
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path

FROZEN_EXE = getattr(sys, 'frozen', False)

_STD_OUTPUT_HANDLE = -11
_kernel32 = ctypes.windll.kernel32
_console_handle = _kernel32.GetStdHandle(_STD_OUTPUT_HANDLE)

_BLACK   = 0x0000
_BLUE    = 0x0001
_GREEN   = 0x0002
_CYAN    = 0x0003
_RED     = 0x0004
_MAGENTA = 0x0005
_YELLOW  = 0x0006
_WHITE   = 0x0007
_INTENSE = 0x0008

_BRIGHT_WHITE  = _WHITE | _INTENSE
_BRIGHT_RED    = _RED | _INTENSE
_BRIGHT_GREEN  = _GREEN | _INTENSE
_BRIGHT_YELLOW = _YELLOW | _INTENSE
_BRIGHT_CYAN   = _CYAN | _INTENSE
_DIM_WHITE     = _WHITE

_DEFAULT_COLOR = _WHITE

class _CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_short * 2),
        ("dwCursorPosition", ctypes.c_short * 2),
        ("wAttributes", ctypes.c_ushort),
        ("srWindow", ctypes.c_short * 4),
        ("dwMaximumWindowSize", ctypes.c_short * 2),
    ]

_csbi = _CONSOLE_SCREEN_BUFFER_INFO()
_kernel32.GetConsoleScreenBufferInfo(_console_handle, ctypes.byref(_csbi))
_ORIGINAL_ATTRS = _csbi.wAttributes


def _set_color(color: int) -> None:
    _kernel32.SetConsoleTextAttribute(_console_handle, color)


def _reset_color() -> None:
    _kernel32.SetConsoleTextAttribute(_console_handle, _ORIGINAL_ATTRS)


def _get_terminal_width() -> int:
    try:
        info = _CONSOLE_SCREEN_BUFFER_INFO()
        _kernel32.GetConsoleScreenBufferInfo(_console_handle, ctypes.byref(info))
        width = info.srWindow[2] - info.srWindow[0] + 1
        return max(width, 80)
    except Exception:
        return 120


def cprint(text: str, color: int = _DEFAULT_COLOR, end: str = "\n") -> None:
    _set_color(color)
    sys.stdout.write(text)
    sys.stdout.write(end)
    sys.stdout.flush()
    _reset_color()


def cprint_multi(segments: list[tuple[str, int]], end: str = "\n") -> None:
    for text, color in segments:
        _set_color(color)
        sys.stdout.write(text)
        sys.stdout.flush()
    _reset_color()
    sys.stdout.write(end)
    sys.stdout.flush()


def print_horizontal_line(width: int, char: str = "-", color: int = _DIM_WHITE) -> None:
    cprint(char * width, color)


def print_box(lines: list[str | tuple[str, int]], title: str = "",
              border_color: int = _BRIGHT_WHITE, width: int = 0) -> None:
    if width <= 0:
        width = _get_terminal_width() - 2
    inner = width - 2

    if title:
        pad = inner - len(title) - 2
        left_pad = pad // 2
        right_pad = pad - left_pad
        cprint_multi([
            ("\u250c", border_color),
            ("\u2500" * left_pad + " ", border_color),
            (title, _BRIGHT_WHITE),
            (" " + "\u2500" * right_pad, border_color),
            ("\u2510", border_color),
        ])
    else:
        cprint("\u250c" + "\u2500" * inner + "\u2510", border_color)

    for line in lines:
        if isinstance(line, tuple):
            text, color = line
        else:
            text = line
            color = _DEFAULT_COLOR

        visible_len = len(text)
        padding = inner - visible_len
        if padding < 0:
            text = text[:inner]
            padding = 0

        cprint_multi([
            ("\u2502", border_color),
            (text + " " * padding, color),
            ("\u2502", border_color),
        ])

    cprint("\u2514" + "\u2500" * inner + "\u2518", border_color)


def print_table(headers: list[tuple[str, int]], rows: list[list[tuple[str, int]]],
                col_widths: list[int], title: str = "",
                header_color: int = _BRIGHT_WHITE,
                border_color: int = _DIM_WHITE,
                show_lines: bool = True) -> None:
    total_width = sum(col_widths) + len(col_widths) + 1

    if title:
        pad = (total_width - len(title)) // 2
        cprint(" " * max(pad, 0) + title, _BRIGHT_WHITE)
        print()

    top = "\u250c"
    for i, w in enumerate(col_widths):
        top += "\u2500" * (w + 2)
        top += "\u252c" if i < len(col_widths) - 1 else "\u2510"
    cprint(top, border_color)

    segments = [("\u2502", border_color)]
    for i, (hdr_text, _) in enumerate(headers):
        cell = f" {hdr_text:<{col_widths[i]}} "
        segments.append((cell, header_color))
        segments.append(("\u2502", border_color))
    cprint_multi(segments)

    sep = "\u251c"
    for i, w in enumerate(col_widths):
        sep += "\u2500" * (w + 2)
        sep += "\u253c" if i < len(col_widths) - 1 else "\u2524"
    cprint(sep, border_color)

    for row_idx, row in enumerate(rows):
        segments = [("\u2502", border_color)]
        for i, (cell_text, cell_color) in enumerate(row):
            w = col_widths[i]
            truncated = cell_text[:w]
            cell = f" {truncated:<{w}} "
            segments.append((cell, cell_color))
            segments.append(("\u2502", border_color))
        cprint_multi(segments)

        if show_lines and row_idx < len(rows) - 1:
            row_sep = "\u251c"
            for i, w in enumerate(col_widths):
                row_sep += "\u2500" * (w + 2)
                row_sep += "\u253c" if i < len(col_widths) - 1 else "\u2524"
            cprint(row_sep, border_color)

    bottom = "\u2514"
    for i, w in enumerate(col_widths):
        bottom += "\u2500" * (w + 2)
        bottom += "\u2534" if i < len(col_widths) - 1 else "\u2518"
    cprint(bottom, border_color)


def print_progress(description: str, current: int, total: int, bar_width: int = 40) -> None:
    if total == 0:
        pct = 100.0
    else:
        pct = (current / total) * 100.0
    filled = int(bar_width * current / max(total, 1))
    bar = "\u2588" * filled + "\u2591" * (bar_width - filled)
    line = f"\r  {description} [{bar}] {pct:5.1f}% ({current}/{total})"
    _set_color(_BRIGHT_CYAN)
    sys.stdout.write(line)
    sys.stdout.flush()
    _reset_color()
    if current >= total:
        sys.stdout.write("\r" + " " * (len(line) + 5) + "\r")
        sys.stdout.flush()


PREFETCH_DIR = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "Prefetch"
SCCA_SIGNATURE = b"SCCA"
MAM_SIGNATURES = [b"MAM\x04", b"MAM\x05", b"MAM\x06"]
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

HIGH_RISK_TARGETS = {
    "RUNTIMEBROKER.EXE",
    "CTFMON.EXE",
    "SVCHOST.EXE",
    "NOTEPAD.EXE",
    "SPOTIFY.EXE",
    "DLLHOST.EXE",
    "CONHOST.EXE",
    "SEARCHPROTOCOLHOST.EXE",
    "WERFAULT.EXE",
    "TASKHOSTW.EXE",
}

EXPECTED_PATHS = {
    "RUNTIMEBROKER.EXE": ["\\WINDOWS\\SYSTEM32\\RUNTIMEBROKER.EXE"],
    "CTFMON.EXE": ["\\WINDOWS\\SYSTEM32\\CTFMON.EXE"],
    "SVCHOST.EXE": ["\\WINDOWS\\SYSTEM32\\SVCHOST.EXE"],
    "NOTEPAD.EXE": [
        "\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE",
        "\\WINDOWS\\NOTEPAD.EXE",
    ],
    "DLLHOST.EXE": ["\\WINDOWS\\SYSTEM32\\DLLHOST.EXE"],
    "CONHOST.EXE": ["\\WINDOWS\\SYSTEM32\\CONHOST.EXE"],
    "TASKHOSTW.EXE": ["\\WINDOWS\\SYSTEM32\\TASKHOSTW.EXE"],
    "SPOTIFY.EXE": [
        "\\PROGRAM FILES\\SPOTIFY\\SPOTIFY.EXE",
        "\\USERS\\%LOCALAPPDATA%\\SPOTIFY\\SPOTIFY.EXE",
    ],
    "SEARCHPROTOCOLHOST.EXE": ["\\WINDOWS\\SYSTEM32\\SEARCHPROTOCOLHOST.EXE"],
    "WERFAULT.EXE": ["\\WINDOWS\\SYSTEM32\\WERFAULT.EXE"],
}


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"


SEVERITY_COLORS = {
    Severity.CRITICAL: _BRIGHT_RED,
    Severity.HIGH: _RED | _INTENSE,
    Severity.MEDIUM: _BRIGHT_YELLOW,
    Severity.LOW: _BRIGHT_CYAN,
    Severity.CLEAN: _BRIGHT_GREEN,
}


@dataclass
class PrefetchEntry:
    filename: str
    executable_name: str
    prefetch_hash: int
    version: int
    file_size: int
    process_path: str
    file_references: list[str]
    run_count: int
    last_run: datetime | None
    created: datetime | None
    modified: datetime | None
    source_path: str


@dataclass
class Finding:
    entry: PrefetchEntry
    severity: Severity
    reasons: list[str] = field(default_factory=list)


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, OSError):
        return False


def filetime_to_datetime(ft: int) -> datetime | None:
    if ft == 0 or ft < 0:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None


XPRESS_HUFFMAN = 0x0104
WORKSPACE_SIZE = 65536
MAX_PREFETCH_SIZE = 50 * 1024 * 1024  # 50 MB limit to prevent memory exhaustion
MAX_DECOMPRESSED_SIZE = 256 * 1024 * 1024  # 256 MB max decompressed size


def decompress_mam(data: bytes) -> bytes | None:
    # Check if data starts with any known MAM signature
    if not any(data[:4] == sig for sig in MAM_SIGNATURES):
        return None
    try:
        decompressed_size = struct.unpack_from("<I", data, 4)[0]
        if decompressed_size == 0 or decompressed_size > MAX_DECOMPRESSED_SIZE:
            return None
        compressed_data = data[8:]
        output_buffer = ctypes.create_string_buffer(decompressed_size)
        workspace = ctypes.create_string_buffer(WORKSPACE_SIZE)
        final_size = ctypes.c_ulong(0)
        ntdll = ctypes.windll.ntdll

        status = ntdll.RtlDecompressBufferEx(
            ctypes.c_ushort(XPRESS_HUFFMAN),
            output_buffer,
            ctypes.c_ulong(decompressed_size),
            ctypes.c_char_p(compressed_data),
            ctypes.c_ulong(len(compressed_data)),
            ctypes.byref(final_size),
            workspace,
        )
        if status == 0:
            return output_buffer.raw[: final_size.value]

        final_size = ctypes.c_ulong(0)
        status = ntdll.RtlDecompressBuffer(
            ctypes.c_ushort(XPRESS_HUFFMAN),
            output_buffer,
            ctypes.c_ulong(decompressed_size),
            ctypes.c_char_p(compressed_data),
            ctypes.c_ulong(len(compressed_data)),
            ctypes.byref(final_size),
        )
        if status == 0:
            return output_buffer.raw[: final_size.value]

        return None
    except (OSError, Exception):
        return None


def extract_filename_strings(data: bytes, offset: int, length: int) -> list[str]:
    results = []
    if offset + length > len(data) or length == 0:
        return results
    raw = data[offset : offset + length]
    try:
        decoded = raw.decode("utf-16-le", errors="ignore")
    except Exception:
        return results
    for part in decoded.split("\x00"):
        cleaned = part.strip()
        if cleaned:
            results.append(cleaned)
    return results


def resolve_process_path(
    data: bytes,
    executable_name: str,
    metrics_offset: int,
    metrics_count: int,
    strings_offset: int,
    version: int,
) -> tuple[str, list[str]]:
    all_refs = []
    process_path = ""

    if version == 17:
        entry_size = 20
    else:
        entry_size = 32

    for i in range(metrics_count):
        entry_offset = metrics_offset + (i * entry_size)
        if entry_offset + entry_size > len(data):
            break

        if entry_offset + 12 > len(data):
            break
        name_offset, name_chars = struct.unpack_from("<II", data, entry_offset + 4)

        abs_offset = strings_offset + name_offset
        byte_length = name_chars * 2

        if abs_offset + byte_length > len(data) or byte_length == 0:
            continue

        try:
            ref_path = data[abs_offset : abs_offset + byte_length].decode(
                "utf-16-le", errors="ignore"
            ).rstrip("\x00")
        except Exception:
            continue

        if ref_path:
            all_refs.append(ref_path)
            if (
                not process_path
                and executable_name.upper() in ref_path.upper()
                and ref_path.upper().endswith(executable_name.upper())
            ):
                process_path = ref_path

    if not process_path:
        strings_section_len = 0
        if metrics_count > 0:
            last_entry = metrics_offset + (metrics_count * entry_size)
            if strings_offset > last_entry:
                strings_section_len = min(len(data) - strings_offset, 65536)
        if strings_section_len == 0:
            strings_section_len = min(len(data) - strings_offset, 65536)

        all_strings = extract_filename_strings(data, strings_offset, strings_section_len)
        for s in all_strings:
            if s not in all_refs:
                all_refs.append(s)
            if (
                not process_path
                and executable_name.upper() in s.upper()
                and s.upper().endswith(executable_name.upper())
            ):
                process_path = s

    return process_path, all_refs


def parse_prefetch_file(filepath: Path) -> PrefetchEntry | None:
    try:
        raw_data = filepath.read_bytes()
    except (PermissionError, OSError):
        return None

    if len(raw_data) > MAX_PREFETCH_SIZE:
        return None

    if len(raw_data) < 16:
        return None

    data = raw_data
    if raw_data[:4] in MAM_SIGNATURES:
        decompressed = decompress_mam(raw_data)
        if decompressed is None:
            return None
        data = decompressed

    if len(data) < 108:
        return None

    version = struct.unpack_from("<I", data, 0)[0]
    signature = data[4:8]

    if signature != SCCA_SIGNATURE:
        return None

    if version not in (17, 23, 26, 30):
        return None

    # Validate minimum required size for version
    min_size = {17: 100, 23: 152, 26: 176, 30: 208}
    if len(data) < min_size.get(version, 200):
        return None

    try:
        exe_name_raw = data[16:76]
        executable_name = exe_name_raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
    except Exception:
        return None

    if not executable_name:
        return None

    prefetch_hash = struct.unpack_from("<I", data, 76)[0]

    # Validate offsets are within bounds
    metrics_offset = struct.unpack_from("<I", data, 84)[0]
    metrics_count = struct.unpack_from("<I", data, 88)[0]
    strings_offset = struct.unpack_from("<I", data, 100)[0]
    
    # Bounds check: ensure offsets don't exceed data length
    max_offset = max(metrics_offset, strings_offset)
    if max_offset > len(data):
        return None
    
    # Sanity check on metrics count
    if metrics_count > 1000:  # Reasonable upper limit
        return None

    process_path, file_references = resolve_process_path(
        data, executable_name, metrics_offset, metrics_count, strings_offset, version
    )

    run_count = 0
    last_run_ft = 0

    try:
        if version == 17:
            if len(data) >= 0x78 + 4:
                run_count = struct.unpack_from("<I", data, 0x78)[0]
            if len(data) >= 0x78 + 8:
                last_run_ft = struct.unpack_from("<Q", data, 0x80)[0]
        elif version == 23:
            if len(data) >= 0x80 + 8:
                last_run_ft = struct.unpack_from("<Q", data, 0x80)[0]
            if len(data) >= 0x98 + 4:
                run_count = struct.unpack_from("<I", data, 0x98)[0]
        elif version == 26:
            if len(data) >= 0x80 + 8:
                last_run_ft = struct.unpack_from("<Q", data, 0x80)[0]
            if len(data) >= 0xB0 + 4:
                run_count = struct.unpack_from("<I", data, 0xB0)[0]
        elif version == 30:
            if len(data) >= 0x80 + 8:
                last_run_ft = struct.unpack_from("<Q", data, 0x80)[0]
            if len(data) >= 0xD0 + 4:
                run_count = struct.unpack_from("<I", data, 0xD0)[0]
    except struct.error:
        pass

    last_run = filetime_to_datetime(last_run_ft)

    created = None
    modified = None
    try:
        stat = filepath.stat()
        created = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc)
        modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
    except OSError:
        pass

    return PrefetchEntry(
        filename=filepath.name,
        executable_name=executable_name,
        prefetch_hash=prefetch_hash,
        version=version,
        file_size=len(data),
        process_path=process_path,
        file_references=file_references,
        run_count=run_count,
        last_run=last_run,
        created=created,
        modified=modified,
        source_path=str(filepath),
    )


def evaluate_entry(entry: PrefetchEntry) -> Finding:
    reasons = []
    is_high_risk = entry.executable_name.upper() in HIGH_RISK_TARGETS
    has_path = bool(entry.process_path.strip())
    has_refs = len(entry.file_references) > 0

    if is_high_risk and not has_path:
        severity = Severity.CRITICAL
        reasons.append(
            f"{entry.executable_name} is a known injection target with no process path"
        )
        if not has_refs:
            reasons.append("No file references found in prefetch data")

    elif is_high_risk and has_path:
        exe_upper = entry.executable_name.upper()
        path_upper = entry.process_path.upper()
        expected = EXPECTED_PATHS.get(exe_upper, [])
        path_valid = any(
            path_upper.endswith(ep.upper()) for ep in expected
        ) if expected else True
        if not path_valid:
            severity = Severity.HIGH
            reasons.append(
                f"Process path does not match expected location: {entry.process_path}"
            )
        else:
            severity = Severity.CLEAN
    elif not is_high_risk and not has_path and not has_refs:
        severity = Severity.MEDIUM
        reasons.append("No process path or file references detected")
    elif not is_high_risk and not has_path and has_refs:
        severity = Severity.LOW
        reasons.append("Missing process path but file references exist")
    else:
        severity = Severity.CLEAN

    return Finding(entry=entry, severity=severity, reasons=reasons)


def scan_prefetch_directory(prefetch_path: Path) -> tuple[list[PrefetchEntry], list[Finding]]:
    pf_files = sorted(prefetch_path.glob("*.pf"))
    entries = []
    findings = []

    if not pf_files:
        return entries, findings

    total = len(pf_files)
    for idx, pf_file in enumerate(pf_files, 1):
        entry = parse_prefetch_file(pf_file)
        if entry:
            entries.append(entry)
            finding = evaluate_entry(entry)
            if finding.severity != Severity.CLEAN:
                findings.append(finding)
        print_progress("Parsing prefetch files", idx, total)

    return entries, findings


def render_findings(findings: list[Finding]) -> None:
    if not findings:
        print_box(
            [("  No indicators of PE injection detected.", _BRIGHT_GREEN)],
            title="Results",
            border_color=_BRIGHT_GREEN,
        )
        return

    findings.sort(key=lambda f: list(Severity).index(f.severity))

    col_widths = [10, 26, 44, 5, 50]
    headers = [
        ("Severity", 0),
        ("Executable", 0),
        ("Process Path", 0),
        ("Runs", 0),
        ("Reason", 0),
    ]

    rows = []
    for f in findings:
        color = SEVERITY_COLORS[f.severity]
        path_display = f.entry.process_path if f.entry.process_path else "<EMPTY>"
        reason_text = "; ".join(f.reasons)

        rows.append([
            (f.severity.value, color),
            (f.entry.executable_name, color),
            (path_display, _BRIGHT_RED if not f.entry.process_path else _DEFAULT_COLOR),
            (str(f.entry.run_count), _DEFAULT_COLOR),
            (reason_text, _DEFAULT_COLOR),
        ])

    print_table(
        headers=headers,
        rows=rows,
        col_widths=col_widths,
        title="Detection Results",
        show_lines=True,
    )


def render_summary(entries: list[PrefetchEntry], findings: list[Finding]) -> None:
    counts: dict[Severity, int] = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    counts[Severity.CLEAN] = len(entries) - len(findings)

    lines: list[str | tuple[str, int]] = [
        (f"  Total prefetch entries parsed:  {len(entries)}", _BRIGHT_WHITE),
        ("", _DEFAULT_COLOR),
    ]

    for sev in Severity:
        color = SEVERITY_COLORS[sev]
        lines.append((f"  {sev.value:>10}  {counts[sev]}", color))

    critical_or_high = counts[Severity.CRITICAL] + counts[Severity.HIGH]
    lines.append(("", _DEFAULT_COLOR))

    if critical_or_high > 0:
        lines.append(
            (f"  !  {critical_or_high} high-confidence detection(s) found.", _BRIGHT_RED)
        )
    elif counts[Severity.MEDIUM] > 0:
        lines.append(
            ("  !  Possible indicators found. Manual review recommended.", _BRIGHT_YELLOW)
        )
    else:
        lines.append(("  +  System appears clean.", _BRIGHT_GREEN))

    print_box(lines, title="Scan Summary", border_color=_BRIGHT_WHITE)


def render_all_entries(entries: list[PrefetchEntry], flagged_files: set[str]) -> None:
    col_widths = [28, 56, 5, 9]
    headers = [
        ("Executable", 0),
        ("Process Path", 0),
        ("Runs", 0),
        ("Status", 0),
    ]

    rows = []
    for entry in sorted(entries, key=lambda e: e.executable_name):
        is_flagged = entry.filename in flagged_files
        color = _BRIGHT_RED if is_flagged else _DEFAULT_COLOR
        status_text = "FLAGGED" if is_flagged else "OK"
        status_color = _BRIGHT_RED if is_flagged else _BRIGHT_GREEN
        path_display = entry.process_path if entry.process_path else "<none>"

        rows.append([
            (entry.executable_name, color),
            (path_display, _DIM_WHITE if not entry.process_path else _DEFAULT_COLOR),
            (str(entry.run_count), _DEFAULT_COLOR),
            (status_text, status_color),
        ])

    print_table(
        headers=headers,
        rows=rows,
        col_widths=col_widths,
        title="All Prefetch Entries",
        show_lines=False,
    )


def export_results(
    entries: list[PrefetchEntry], findings: list[Finding], output_path: str
) -> None:
    report = {
        "scan_time": datetime.now(tz=timezone.utc).isoformat(),
        "total_entries": len(entries),
        "total_findings": len(findings),
        "findings": [
            {
                "severity": f.severity.value,
                "executable": f.entry.executable_name,
                "process_path": f.entry.process_path,
                "run_count": f.entry.run_count,
                "last_run": f.entry.last_run.isoformat() if f.entry.last_run else None,
                "prefetch_file": f.entry.filename,
                "reasons": f.reasons,
                "file_references_count": len(f.entry.file_references),
            }
            for f in findings
        ],
    }
    try:
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2, ensure_ascii=False)
        print()
        cprint(f"  Report saved to: {output_path}", _BRIGHT_GREEN)
    except OSError as e:
        print()
        cprint(f"  Failed to save report: {e}", _BRIGHT_RED)


def display_banner() -> None:
    lines: list[str | tuple[str, int]] = [
        ("", _DEFAULT_COLOR),
        ("    PE Injection Detector", _BRIGHT_WHITE),
        ("    Prefetch-based process hollowing detection", _DIM_WHITE),
        ("", _DEFAULT_COLOR),
    ]
    print_box(lines, border_color=_BRIGHT_RED)
    print()


def _pause() -> None:
    # For frozen EXE, use os.system("pause")
    if FROZEN_EXE:
        os.system("pause >nul")
        return
    
    # For Python scripts, always try to pause
    # Try msvcrt first (Windows)
    try:
        import msvcrt
        cprint("  Press any key to continue...", _DIM_WHITE)
        msvcrt.getch()
        return
    except (ImportError, AttributeError):
        pass
    
    # Try input() as fallback for cross-platform
    try:
        input("  Press Enter to continue...")
    except (EOFError, KeyboardInterrupt):
        pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect PE injection via Windows Prefetch analysis"
    )
    parser.add_argument(
        "--prefetch-dir",
        type=str,
        default=str(PREFETCH_DIR),
        help="Path to the Prefetch directory",
    )
    parser.add_argument(  # type: ignore[func-returns-value]
        "--all",
        action="store_true",
        help="Display all prefetch entries",
    )
    parser.add_argument(  # type: ignore[func-returns-value]
        "--export",
        type=str,
        default="",
        help="Export results to a JSON file",
    )
    parser.add_argument(  # type: ignore[func-returns-value]
        "--no-banner",
        action="store_true",
        help="Suppress the startup banner",
    )
    parser.add_argument(
        "--no-pause",
        action="store_true",
        help="Disable the pause at the end of execution",
    )
    args = parser.parse_args()

    if not args.no_banner:
        display_banner()

    if sys.platform != "win32":
        cprint("This tool requires Windows.", _BRIGHT_RED)
        sys.exit(1)

    if not is_admin():
        cprint(
            "  !  Not running as administrator. Some prefetch files may be inaccessible.\n",
            _BRIGHT_YELLOW,
        )

    prefetch_path = Path(args.prefetch_dir)
    if not prefetch_path.exists():
        cprint(f"  Prefetch directory not found: {prefetch_path}", _BRIGHT_RED)
        sys.exit(1)

    entries, findings = scan_prefetch_directory(prefetch_path)

    if not entries:
        cprint("  No prefetch files could be parsed.", _BRIGHT_YELLOW)
        sys.exit(0)

    print()
    render_findings(findings)
    print()
    render_summary(entries, findings)

    if args.all:
        print()
        flagged = {f.entry.filename for f in findings}
        render_all_entries(entries, flagged)

    if args.export:
        export_results(entries, findings, args.export)

    print()
    if not args.no_pause:
        _pause()


if __name__ == "__main__":
    main()
